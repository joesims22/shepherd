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

package fake

import (
	v1 "github.com/rancher/rancher/pkg/apis/catalog.cattle.io/v1"
	catalogcattleiov1 "github.com/rancher/shepherd/pkg/generated/clientset/versioned/typed/catalog.cattle.io/v1"
	gentype "k8s.io/client-go/gentype"
)

// fakeUIPlugins implements UIPluginInterface
type fakeUIPlugins struct {
	*gentype.FakeClientWithList[*v1.UIPlugin, *v1.UIPluginList]
	Fake *FakeCatalogV1
}

func newFakeUIPlugins(fake *FakeCatalogV1, namespace string) catalogcattleiov1.UIPluginInterface {
	return &fakeUIPlugins{
		gentype.NewFakeClientWithList[*v1.UIPlugin, *v1.UIPluginList](
			fake.Fake,
			namespace,
			v1.SchemeGroupVersion.WithResource("uiplugins"),
			v1.SchemeGroupVersion.WithKind("UIPlugin"),
			func() *v1.UIPlugin { return &v1.UIPlugin{} },
			func() *v1.UIPluginList { return &v1.UIPluginList{} },
			func(dst, src *v1.UIPluginList) { dst.ListMeta = src.ListMeta },
			func(list *v1.UIPluginList) []*v1.UIPlugin { return gentype.ToPointerSlice(list.Items) },
			func(list *v1.UIPluginList, items []*v1.UIPlugin) { list.Items = gentype.FromPointerSlice(items) },
		),
		fake,
	}
}
