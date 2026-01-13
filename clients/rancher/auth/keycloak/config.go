package keycloak

// Config corresponds to the YAML structure for Keycloak SAML
type Config struct {
	AccessMode         string `json:"accessMode" yaml:"accessMode"`
	RancherApiHost     string `json:"rancherApiHost" yaml:"rancherApiHost"`
	DisplayNameField   string `json:"displayNameField" yaml:"displayNameField"`
	GroupsField        string `json:"groupsField" yaml:"groupsField"`
	UIDField           string `json:"uidField" yaml:"uidField"`
	UserNameField      string `json:"userNameField" yaml:"userNameField"`
	IDPMetadataContent string `json:"idpMetadataContent" yaml:"idpMetadataContent"`
	SpCert             string `json:"spCert" yaml:"spCert"`
	SpKey              string `json:"spKey" yaml:"spKey"`
	Users          *Users          `json:"users" yaml:"users"`
}

// Users represents Keycloak users, used in test scenarios for validating users search.
type Users struct {
	Admin      *User  `json:"admin"      yaml:"admin"`
	SearchBase string `json:"searchBase" yaml:"searchBase"`
}

// User represents a Keycloak user with authentication credentials, used in test scenarios for validating user authentication.
type User struct {
	Password string `json:"password,omitempty" yaml:"password,omitempty"`
	Username string `json:"username,omitempty" yaml:"username,omitempty"`
}
