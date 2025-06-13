/*
Copyright 2025 Rancher Labs, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by main. DO NOT EDIT.

package v1

import (
	context "context"

	catalogcattleiov1 "github.com/rancher/rancher/pkg/apis/catalog.cattle.io/v1"
	scheme "github.com/rancher/shepherd/pkg/generated/clientset/versioned/scheme"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	gentype "k8s.io/client-go/gentype"
)

// UIPluginsGetter has a method to return a UIPluginInterface.
// A group's client should implement this interface.
type UIPluginsGetter interface {
	UIPlugins(namespace string) UIPluginInterface
}

// UIPluginInterface has methods to work with UIPlugin resources.
type UIPluginInterface interface {
	Create(ctx context.Context, uIPlugin *catalogcattleiov1.UIPlugin, opts metav1.CreateOptions) (*catalogcattleiov1.UIPlugin, error)
	Update(ctx context.Context, uIPlugin *catalogcattleiov1.UIPlugin, opts metav1.UpdateOptions) (*catalogcattleiov1.UIPlugin, error)
	// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
	UpdateStatus(ctx context.Context, uIPlugin *catalogcattleiov1.UIPlugin, opts metav1.UpdateOptions) (*catalogcattleiov1.UIPlugin, error)
	Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*catalogcattleiov1.UIPlugin, error)
	List(ctx context.Context, opts metav1.ListOptions) (*catalogcattleiov1.UIPluginList, error)
	Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *catalogcattleiov1.UIPlugin, err error)
	UIPluginExpansion
}

// uIPlugins implements UIPluginInterface
type uIPlugins struct {
	*gentype.ClientWithList[*catalogcattleiov1.UIPlugin, *catalogcattleiov1.UIPluginList]
}

// newUIPlugins returns a UIPlugins
func newUIPlugins(c *CatalogV1Client, namespace string) *uIPlugins {
	return &uIPlugins{
		gentype.NewClientWithList[*catalogcattleiov1.UIPlugin, *catalogcattleiov1.UIPluginList](
			"uiplugins",
			c.RESTClient(),
			scheme.ParameterCodec,
			namespace,
			func() *catalogcattleiov1.UIPlugin { return &catalogcattleiov1.UIPlugin{} },
			func() *catalogcattleiov1.UIPluginList { return &catalogcattleiov1.UIPluginList{} },
		),
	}
}
