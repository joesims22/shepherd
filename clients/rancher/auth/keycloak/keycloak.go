package keycloak

import (
	"fmt"
    "io"
    "net/http"
    "net/http/cookiejar"
    "net/url"
    "regexp"
    "strings"
	
	management "github.com/rancher/shepherd/clients/rancher/generated/management/v3"
	"github.com/rancher/shepherd/pkg/config"
	"github.com/rancher/shepherd/pkg/session"
)

// KeycloakOperations defines the interface for interacting with the Keycloak Auth Provider
type KeycloakOperations interface {
	Enable() error
	Disable() error
	Update(existing *management.AuthConfig, updates interface{}) (*management.AuthConfig, error)
}

const (
	resourceID           = "keycloak"
	resourceType         = "keyCloakConfig"
	ConfigurationFileKey = "keycloak"
)

type KeycloakClient struct {
	client  *management.Client
	session *session.Session
	Config  *Config
}

func NewKeycloak(client *management.Client, session *session.Session) (*KeycloakClient, error) {
	keycloakConfig := new(Config)
	config.LoadConfig(ConfigurationFileKey, keycloakConfig)

	return &KeycloakClient{
		client:  client,
		session: session,
		Config:  keycloakConfig,
	}, nil
}

func (k *KeycloakClient) Enable() error {
	// 1. Get the current state (we need the Resource URL/ID from this)
	existingConfig, err := k.client.AuthConfig.ByID(resourceID)
	if err != nil {
		return err
	}

	// 2. Prepare the Input using the SPECIFIC KeyCloakConfig struct
	// This struct has the fields you were missing (SpCert, IdpMetadataContent, etc.)
	updateInput := k.newEnableInputFromConfig()

	// 3. Perform the Update using the generic DoUpdate
	// We pass 'updateInput' (the specific struct) instead of 'existingConfig' (the generic struct)
	// DoUpdate(resource, input, output)
	var result management.AuthConfig
	err = k.client.Ops.DoUpdate(resourceType, &existingConfig.Resource, updateInput, &result)
	if err != nil {
		return err
	}

	// 4. Register Cleanup
	k.session.RegisterCleanupFunc(func() error {
		return k.Disable()
	})

	return nil
}

func (k *KeycloakClient) Disable() error {
	existingConfig, err := k.client.AuthConfig.ByID(resourceID)
	if err != nil {
		return err
	}

	// To disable, we can use a simpler map or struct since we only touch the 'enabled' field
	updateInput := map[string]interface{}{
		"enabled": false,
	}

	var result management.AuthConfig
	err = k.client.Ops.DoUpdate(resourceType, &existingConfig.Resource, updateInput, &result)
	return err
}

// Update is a wrapper for the generic update
func (k *KeycloakClient) Update(existing *management.AuthConfig, updates interface{}) (*management.AuthConfig, error) {
	var result management.AuthConfig
	err := k.client.Ops.DoUpdate(resourceType, &existing.Resource, updates, &result)
	return &result, err
}

// Helper: Returns *management.KeyCloakConfig instead of *management.AuthConfig
func (k *KeycloakClient) newEnableInputFromConfig() *management.KeyCloakConfig {
	input := &management.KeyCloakConfig{}
	
	input.Enabled = true
	input.AccessMode = k.Config.AccessMode
	input.Type = "keycloakConfig"


	input.RancherAPIHost = k.Config.RancherApiHost
	input.DisplayNameField = k.Config.DisplayNameField
	input.GroupsField = k.Config.GroupsField
	input.UIDField = k.Config.UIDField
	input.UserNameField = k.Config.UserNameField
	input.IDPMetadataContent = k.Config.IDPMetadataContent
	input.SpCert = k.Config.SpCert
	input.SpKey = k.Config.SpKey

	// input.Username = k.Config.Users.Admin.Username
	// input.Password = k.Config.Users.Admin.Password

	return input
}

// Login simulates a full browser SAML login flow
func (k *KeycloakClient) Login(username, password string) (string, error) {
	// 1. Setup a Client with a Cookie Jar (Memory)
	// This ensures we keep the session cookies between redirects
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
		// We manually handle redirects to parse intermediate pages
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil
		},
	}

	rancherHost := k.Config.RancherApiHost

	// ------------------------------------------------------------------
	// STEP 1: Initiate Login at Rancher
	// ------------------------------------------------------------------
	// This URL starts the flow: /v1-saml/keycloak/saml/login
	startURL := fmt.Sprintf("%s/v1-saml/keycloak/saml/login", rancherHost)
	resp, err := client.Get(startURL)
	if err != nil {
		return "", fmt.Errorf("failed to hit rancher login start: %w", err)
	}
	defer resp.Body.Close()

	// Rancher should redirect us to Keycloak immediately.
	// But sometimes verify if we got a 200 OK (Keycloak Page) or 302 (Redirect)
	// If we are at Keycloak, the URL should look like: .../auth/realms/...
	if !strings.Contains(resp.Request.URL.String(), "/auth/realms/") {
		// If we are not at Keycloak yet, follow the redirect manually if the client didn't
		// (Depends on how many hops there were)
		return "", fmt.Errorf("expected to be at keycloak login page, but valid url was: %s", resp.Request.URL)
	}

	// ------------------------------------------------------------------
	// STEP 2: Parse Keycloak Login Page
	// ------------------------------------------------------------------
	// We need to find the <form action="..."> URL to POST our credentials to.
	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyString := string(bodyBytes)

	// Simple Regex to find the form action. 
	// Looks for: action="https://..."
	actionRegex := regexp.MustCompile(`action="([^"]+)"`)
	matches := actionRegex.FindStringSubmatch(bodyString)
	if len(matches) < 2 {
		return "", fmt.Errorf("could not find login form action in keycloak page")
	}
	// Keycloak sometimes gives a relative path like /auth/..., or absolute.
	// We handle the absolute URL found in the regex.
	// Note: The regex match usually includes &amp; which Go needs to unescape
	loginActionURL := strings.ReplaceAll(matches[1], "&amp;", "&")

	// ------------------------------------------------------------------
	// STEP 3: Submit Credentials to Keycloak
	// ------------------------------------------------------------------
	formValues := url.Values{}
	formValues.Set("username", username)
	formValues.Set("password", password)
	formValues.Set("credentialId", "") // Sometimes required by Keycloak forms

	// Keycloak creates a new Redirect (302) back to Rancher after this POST
	resp, err = client.PostForm(loginActionURL, formValues)
	if err != nil {
		return "", fmt.Errorf("failed to post credentials to keycloak: %w", err)
	}
	defer resp.Body.Close()

	// ------------------------------------------------------------------
	// STEP 4: Handle the SAML Response (The "Post Back")
	// ------------------------------------------------------------------
	// Keycloak does not redirect with a GET. It returns an HTML page with a hidden form
	// containing the SAMLResponse, and a JavaScript that auto-submits it.
	// We must parse this form and submit it manually.
	
	bodyBytes, _ = io.ReadAll(resp.Body)
	bodyString = string(bodyBytes)

	// Find the SAMLResponse hidden input
	samlRegex := regexp.MustCompile(`name="SAMLResponse" value="([^"]+)"`)
	samlMatches := samlRegex.FindStringSubmatch(bodyString)
	if len(samlMatches) < 2 {
		// Check if we just failed login (invalid password)
		if strings.Contains(bodyString, "Invalid username or password") {
			return "", fmt.Errorf("login failed: invalid username or password")
		}
		return "", fmt.Errorf("could not find SAMLResponse in keycloak response")
	}
	samlResponse := samlMatches[1]

	// Find the ACS URL (The Rancher URL to post back to)
	acsRegex := regexp.MustCompile(`action="([^"]+)"`)
	acsMatches := acsRegex.FindStringSubmatch(bodyString)
	if len(acsMatches) < 2 {
		return "", fmt.Errorf("could not find ACS URL in keycloak response")
	}
	acsURL := acsMatches[1]

	// ------------------------------------------------------------------
	// STEP 5: Submit SAMLResponse to Rancher
	// ------------------------------------------------------------------
	fmt.Print("SUBMIT SAMLResponse TO RANCHER")
	fmt.Print(samlResponse)
	rancherValues := url.Values{}
	rancherValues.Set("SAMLResponse", samlResponse)
	// Sometimes 'RelayState' is also required if present in the form
	relayRegex := regexp.MustCompile(`name="RelayState" value="([^"]+)"`)
	relayMatches := relayRegex.FindStringSubmatch(bodyString)
	if len(relayMatches) >= 2 {
		rancherValues.Set("RelayState", relayMatches[1])
	}

	resp, err = client.PostForm(acsURL, rancherValues)
	if err != nil {
		return "", fmt.Errorf("failed to send SAMLResponse to rancher: %w", err)
	}
	defer resp.Body.Close()
	fmt.Print("DEBUG LOGGING STARTS HERE!!!!!!!!!")
	// --- DEBUG START ---
	if !strings.Contains(resp.Request.URL.String(), "/auth/realms/") {
		// Read the body to see the error message from Rancher
		bodyBytes, _ := io.ReadAll(resp.Body)
		fmt.Printf("\n!!! LOGIN FAILED !!!\n")
		fmt.Printf("Status Code: %d\n", resp.StatusCode)
		fmt.Printf("Body: %s\n", string(bodyBytes))
		// --- DEBUG END ---
		
		return "", fmt.Errorf("expected to be at keycloak login page, but valid url was: %s", resp.Request.URL)
	}

	// ------------------------------------------------------------------
	// STEP 6: Extract the Rancher Token
	// ------------------------------------------------------------------
	// If successful, Rancher sets a cookie named "R_SESS" (token).
	// We can inspect the jar or the response cookies.
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "R_SESS" {
			// This is your Bearer token!
			return cookie.Value, nil
		}
	}

	// Fallback: Sometimes the token is in the final URL fragment or body depending on settings
	// But R_SESS is the standard for web access.
	return "", fmt.Errorf("login completed but no R_SESS cookie found. Login might have failed silently")
}