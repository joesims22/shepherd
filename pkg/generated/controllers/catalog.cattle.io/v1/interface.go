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
	"github.com/rancher/lasso/pkg/controller"
	v1 "github.com/rancher/rancher/pkg/apis/catalog.cattle.io/v1"
	"github.com/rancher/shepherd/pkg/session"
	"github.com/rancher/shepherd/pkg/wrangler/pkg/generic"
	"github.com/rancher/wrangler/v3/pkg/schemes"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func init() {
	schemes.Register(v1.AddToScheme)
}

type Interface interface {
	App() AppController
	ClusterRepo() ClusterRepoController
	Operation() OperationController
}

func New(controllerFactory controller.SharedControllerFactory, ts *session.Session) Interface {
	return &version{
		controllerFactory: controllerFactory,
		ts:                ts,
	}
}

type version struct {
	controllerFactory controller.SharedControllerFactory
	ts                *session.Session
}

func (v *version) App() AppController {
	return generic.NewController[*v1.App, *v1.AppList](schema.GroupVersionKind{Group: "catalog.cattle.io", Version: "v1", Kind: "App"}, "apps", true, v.controllerFactory, v.ts)
}

func (v *version) ClusterRepo() ClusterRepoController {
	return generic.NewNonNamespacedController[*v1.ClusterRepo, *v1.ClusterRepoList](schema.GroupVersionKind{Group: "catalog.cattle.io", Version: "v1", Kind: "ClusterRepo"}, "clusterrepos", v.controllerFactory, v.ts)
}

func (v *version) Operation() OperationController {
	return generic.NewController[*v1.Operation, *v1.OperationList](schema.GroupVersionKind{Group: "catalog.cattle.io", Version: "v1", Kind: "Operation"}, "operations", true, v.controllerFactory, v.ts)
}
