/*
Package wrangler contains functions for creating a management context with wrangler controllers.
*/
package wrangler

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/rancher/lasso/pkg/controller"
	"github.com/rancher/lasso/pkg/dynamic"
	"github.com/rancher/norman/types"
	clusterv3api "github.com/rancher/rancher/pkg/apis/cluster.cattle.io/v3"
	managementv3api "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/shepherd/pkg/generated/controllers/apps"
	appsv1 "github.com/rancher/shepherd/pkg/generated/controllers/apps/v1"
	"github.com/rancher/shepherd/pkg/generated/controllers/batch"
	batchv1 "github.com/rancher/shepherd/pkg/generated/controllers/batch/v1"
	"github.com/rancher/shepherd/pkg/generated/controllers/cluster.cattle.io"
	clusterv3 "github.com/rancher/shepherd/pkg/generated/controllers/cluster.cattle.io/v3"
	"github.com/rancher/shepherd/pkg/generated/controllers/core"
	corev1 "github.com/rancher/shepherd/pkg/generated/controllers/core/v1"
	"github.com/rancher/shepherd/pkg/generated/controllers/management.cattle.io"
	managementv3 "github.com/rancher/shepherd/pkg/generated/controllers/management.cattle.io/v3"
	"github.com/rancher/shepherd/pkg/generated/controllers/rbac"
	rbacv1 "github.com/rancher/shepherd/pkg/generated/controllers/rbac/v1"
	"github.com/rancher/shepherd/pkg/session"
	"github.com/rancher/shepherd/pkg/wrangler/pkg/generic"
	"github.com/rancher/wrangler/v3/pkg/apply"
	"github.com/rancher/wrangler/v3/pkg/leader"
	"github.com/rancher/wrangler/v3/pkg/schemes"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type controllerContextType string

const (
	Management controllerContextType = "mgmt"
)

var (
	localSchemeBuilder = runtime.SchemeBuilder{
		managementv3api.AddToScheme,
		clusterv3api.AddToScheme,
	}
	AddToScheme = localSchemeBuilder.AddToScheme
	Scheme      = runtime.NewScheme()
)

func init() {
	metav1.AddToGroupVersion(Scheme, schema.GroupVersion{Version: "v1"})
	utilruntime.Must(AddToScheme(Scheme))
	utilruntime.Must(schemes.AddToScheme(Scheme))
}

type Context struct {
	RESTConfig *rest.Config

	Apply               apply.Apply
	Dynamic             *dynamic.Controller
	Mgmt                managementv3.Interface
	Apps                appsv1.Interface
	ControllerFactory   controller.SharedControllerFactory
	MultiClusterManager MultiClusterManager
	Core                corev1.Interface
	Cluster             clusterv3.Interface
	RBAC                rbacv1.Interface
	Batch               batchv1.Interface

	CachedDiscovery         discovery.CachedDiscoveryInterface
	RESTMapper              meta.RESTMapper
	SharedControllerFactory controller.SharedControllerFactory
	leadership              *leader.Manager
	controllerLock          *sync.Mutex

	RESTClientGetter genericclioptions.RESTClientGetter

	mgmt    *management.Factory
	apps    *apps.Factory
	core    *core.Factory
	rbac    *rbac.Factory
	cluster *cluster.Factory
	batch   *batch.Factory

	session *session.Session
	started bool
}

type MultiClusterManager interface {
	NormanSchemas() *types.Schemas
	ClusterDialer(clusterID string) func(ctx context.Context, network, address string) (net.Conn, error)
	Start(ctx context.Context) error
	Wait(ctx context.Context)
	Middleware(next http.Handler) http.Handler
	K8sClient(clusterName string) (kubernetes.Interface, error)
}

// OnLeader registers a callback function to be executed when the current context becomes the leader.
// It calls the OnLeader method of the leadership field in the Context struct and passes the provided function as an argument.
func (w *Context) OnLeader(f func(ctx context.Context) error) {
	w.leadership.OnLeader(f)
}

// StartWithTransaction is a method of the Context struct that starts a transaction and executes a provided callback function within the transaction. It returns an error if the callback fails
func (w *Context) StartWithTransaction(ctx context.Context, f func(context.Context) error) (err error) {
	transaction := controller.NewHandlerTransaction(ctx)
	if err := f(transaction); err != nil {
		transaction.Rollback()
		return err
	}

	if err := w.ControllerFactory.SharedCacheFactory().Start(ctx); err != nil {
		transaction.Rollback()
		return err
	}

	w.ControllerFactory.SharedCacheFactory().WaitForCacheSync(ctx)
	transaction.Commit()
	return w.Start(ctx)
}

// Start registers the current context as started and performs necessary initialization steps.
// It acquires a lock using the controllerLock mutex to ensure thread safety.
// If the context is not already started, it calls the Register method of the Dynamic field in the Context struct,
// passing the provided context and SharedControllerFactory as arguments.
// It sets the started field to true.
// It then calls the Start method of the ControllerFactory field, passing the provided context and 50 as arguments.
// It returns an error if there is any.
// It finally calls the Start method of the leadership field in the Context struct, passing the provided context.
func (w *Context) Start(ctx context.Context) error {
	w.controllerLock.Lock()
	defer w.controllerLock.Unlock()

	if !w.started {
		if err := w.Dynamic.Register(ctx, w.SharedControllerFactory); err != nil {
			return err
		}
		w.started = true
	}

	if err := w.ControllerFactory.Start(ctx, 50); err != nil {
		return err
	}
	w.leadership.Start(ctx)
	return nil
}

func enableProtobuf(cfg *rest.Config) *rest.Config {
	cpy := rest.CopyConfig(cfg)
	cpy.AcceptContentTypes = "application/vnd.kubernetes.protobuf, application/json"
	cpy.ContentType = "application/json"
	return cpy
}

// NewContext creates a new Context with the given parameters. It initializes the required controller factories and other components needed for the context.
func NewContext(ctx context.Context, restConfig *rest.Config, ts *session.Session) (*Context, error) {
	sharedOpts := GetOptsFromEnv(Management)
	controllerFactory, err := controller.NewSharedControllerFactoryFromConfigWithOptions(enableProtobuf(restConfig), Scheme, sharedOpts)
	if err != nil {
		return nil, err
	}

	// This opts is used for Factories that need the test session
	opts := &generic.FactoryOptions{
		TS:                      ts,
		SharedControllerFactory: controllerFactory,
	}

	apply, err := apply.NewForConfig(restConfig)
	if err != nil {
		return nil, err
	}

	mgmt, err := management.NewFactoryFromConfigWithOptions(restConfig, opts)
	if err != nil {
		return nil, err
	}

	apps, err := apps.NewFactoryFromConfigWithOptions(restConfig, opts)
	if err != nil {
		return nil, err
	}

	core, err := core.NewFactoryFromConfigWithOptions(restConfig, opts)
	if err != nil {
		return nil, err
	}

	rbac, err := rbac.NewFactoryFromConfigWithOptions(restConfig, opts)
	if err != nil {
		return nil, err
	}

	cluster, err := cluster.NewFactoryFromConfigWithOptions(restConfig, opts)
	if err != nil {
		return nil, err
	}

	batch, err := batch.NewFactoryFromConfigWithOptions(restConfig, opts)
	if err != nil {
		return nil, err
	}

	wContext := &Context{
		RESTConfig:              restConfig,
		Apply:                   apply,
		SharedControllerFactory: controllerFactory,
		Mgmt:                    mgmt.Management().V3(),
		Apps:                    apps.Apps().V1(),
		Core:                    core.Core().V1(),
		RBAC:                    rbac.Rbac().V1(),
		Batch:                   batch.Batch().V1(),
		Cluster:                 cluster.Cluster().V3(),
		ControllerFactory:       controllerFactory,
		controllerLock:          &sync.Mutex{},

		mgmt:    mgmt,
		apps:    apps,
		core:    core,
		rbac:    rbac,
		batch:   batch,
		cluster: cluster,
		session: ts,
	}

	return wContext, nil
}

type SimpleRESTClientGetter struct {
	RESTConfig      *rest.Config
	CachedDiscovery discovery.CachedDiscoveryInterface
	RESTMapper      meta.RESTMapper
}

// ToRESTConfig returns the RESTConfig stored in the SimpleRESTClientGetter.
// It is a getter method that allows access to the REST configuration.
// The RESTConfig field is a pointer to rest.Config defined in the SimpleRESTClientGetter struct.
// It returns the RESTConfig and a nil error.
func (s *SimpleRESTClientGetter) ToRESTConfig() (*rest.Config, error) {
	return s.RESTConfig, nil
}

// ToDiscoveryClient returns the cached discovery client
// It returns the CachedDiscovery field of the SimpleRESTClientGetter struct as a CachedDiscoveryInterface and nil error.
func (s *SimpleRESTClientGetter) ToDiscoveryClient() (discovery.CachedDiscoveryInterface, error) {
	return s.CachedDiscovery, nil
}

// ToRESTMapper returns the REST mapper associated with the SimpleRESTClientGetter.
// It retrieves the REST mapper from the RESTMapper field of the SimpleRESTClientGetter struct and returns it as the first return value.
// The second return value is always nil since no error is encountered during the retrieval process.
func (s *SimpleRESTClientGetter) ToRESTMapper() (meta.RESTMapper, error) {
	return s.RESTMapper, nil
}

// GetOptsFromEnv configures a SharedControllersFactoryOptions using env var and return a pointer to it.
func GetOptsFromEnv(contextType controllerContextType) *controller.SharedControllerFactoryOptions {
	return &controller.SharedControllerFactoryOptions{
		SyncOnlyChangedObjects: syncOnlyChangedObjects(contextType),
	}
}

// syncOnlyChangedObjects returns whether the env var CATTLE_SYNC_ONLY_CHANGED_OBJECTS indicates that controllers for the
// given context type should skip running enqueue if the event triggering the update func is not actual update.
func syncOnlyChangedObjects(option controllerContextType) bool {
	skipUpdate := os.Getenv("CATTLE_SYNC_ONLY_CHANGED_OBJECTS")
	if skipUpdate == "" {
		return false
	}
	parts := strings.Split(skipUpdate, ",")

	for _, part := range parts {
		if controllerContextType(part) == option {
			return true
		}
	}
	return false
}

// DownStreamClusterWranglerContext creates a wrangler context to interact with a specific cluster.
func (w *Context) DownStreamClusterWranglerContext(clusterID string) (*Context, error) {
	restConfig := *w.RESTConfig
	restConfig.Host = fmt.Sprintf("https://%s/k8s/clusters/%s", w.RESTConfig.Host, clusterID)

	clusterContext, err := NewContext(context.TODO(), &restConfig, w.session)
	if err != nil {
		return nil, err
	}

	return clusterContext, nil
}
