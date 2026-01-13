package keycloak

import (
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

	return input
}