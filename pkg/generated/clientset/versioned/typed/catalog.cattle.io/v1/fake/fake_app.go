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

// fakeApps implements AppInterface
type fakeApps struct {
	*gentype.FakeClientWithList[*v1.App, *v1.AppList]
	Fake *FakeCatalogV1
}

func newFakeApps(fake *FakeCatalogV1, namespace string) catalogcattleiov1.AppInterface {
	return &fakeApps{
		gentype.NewFakeClientWithList[*v1.App, *v1.AppList](
			fake.Fake,
			namespace,
			v1.SchemeGroupVersion.WithResource("apps"),
			v1.SchemeGroupVersion.WithKind("App"),
			func() *v1.App { return &v1.App{} },
			func() *v1.AppList { return &v1.AppList{} },
			func(dst, src *v1.AppList) { dst.ListMeta = src.ListMeta },
			func(list *v1.AppList) []*v1.App { return gentype.ToPointerSlice(list.Items) },
			func(list *v1.AppList, items []*v1.App) { list.Items = gentype.FromPointerSlice(items) },
		),
		fake,
	}
}
