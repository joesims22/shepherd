package harvester

import (
	"fmt"

	frameworkDynamic "github.com/rancher/shepherd/clients/dynamic"
	"github.com/rancher/shepherd/clients/rancher/catalog"
	v1 "github.com/rancher/shepherd/clients/rancher/v1"

	"github.com/rancher/shepherd/pkg/clientbase"
	"github.com/rancher/shepherd/pkg/config"
	"github.com/rancher/shepherd/pkg/environmentflag"
	"github.com/rancher/shepherd/pkg/session"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

// Client is the main harvester Client object that gives an end user access to the Provisioning and Catalog
// clients in order to create resources on harvester
type Client struct {
	// Client used to access Steve v1 API resources
	Steve *v1.Client
	// Client used to access catalog.cattle.io v1 API resources (apps, charts, etc.)
	Catalog *catalog.Client
	// Config used to test against a harvester instance
	HarvesterConfig *Config
	// Session is the session object used by the client to track all the resources being created by the client.
	Session *session.Session

	restConfig *rest.Config
}

// NewClient is the constructor to the initializing a harvester Client. It takes a bearer token and session.Session. If bearer token is not provided,
// the bearer token provided in the configuration file is used.
func NewClient(bearerToken string, session *session.Session) (*Client, error) {
	harvesterConfig := new(Config)
	config.LoadConfig(ConfigurationFileKey, harvesterConfig)

	environmentFlags := environmentflag.NewEnvironmentFlags()
	environmentflag.LoadEnvironmentFlags(environmentflag.ConfigurationFileKey, environmentFlags)

	if bearerToken == "" {
		bearerToken = harvesterConfig.AdminToken
	}

	c := &Client{
		HarvesterConfig: harvesterConfig,
	}

	session.CleanupEnabled = *harvesterConfig.Cleanup

	var err error
	restConfig := newRestConfig(bearerToken, harvesterConfig)
	c.restConfig = restConfig
	c.Session = session

	c.Steve, err = v1.NewClient(clientOptsV1(restConfig, c.HarvesterConfig))
	if err != nil {
		return nil, err
	}

	c.Steve.Ops.Session = session

	catalogClient, err := catalog.NewForConfig(restConfig, session)
	if err != nil {
		return nil, err
	}

	c.Catalog = catalogClient

	return c, nil
}

// newRestConfig is a constructor that sets ups rest.Config the configuration used by the Provisioning client.
func newRestConfig(bearerToken string, harvesterConfig *Config) *rest.Config {
	return &rest.Config{
		Host:        harvesterConfig.Host,
		BearerToken: bearerToken,
		TLSClientConfig: rest.TLSClientConfig{
			Insecure: *harvesterConfig.Insecure,
		},
	}
}

// clientOptsV1 is a constructor that sets ups clientbase.ClientOpts the configuration used by the v1 harvester clients.
func clientOptsV1(restConfig *rest.Config, harvesterConfig *Config) *clientbase.ClientOpts {
	return &clientbase.ClientOpts{
		URL:      fmt.Sprintf("https://%s/v1", harvesterConfig.Host),
		TokenKey: restConfig.BearerToken,
		Insecure: restConfig.Insecure,
	}
}

// GetHarvesterDynamicClient is a helper function that instantiates a dynamic client to communicate with the harvester host.
func (c *Client) GetHarvesterDynamicClient() (dynamic.Interface, error) {
	dynamic, err := frameworkDynamic.NewForConfig(c.Session, c.restConfig)
	if err != nil {
		return nil, err
	}
	return dynamic, nil
}
