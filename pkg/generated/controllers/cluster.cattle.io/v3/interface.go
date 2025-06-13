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

package v3

import (
	"github.com/rancher/lasso/pkg/controller"
	v3 "github.com/rancher/rancher/pkg/apis/cluster.cattle.io/v3"
	"github.com/rancher/shepherd/pkg/session"
	"github.com/rancher/shepherd/pkg/wrangler/pkg/generic"
	"github.com/rancher/wrangler/v3/pkg/schemes"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func init() {
	schemes.Register(v3.AddToScheme)
}

type Interface interface {
	ClusterAuthToken() ClusterAuthTokenController
	ClusterUserAttribute() ClusterUserAttributeController
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

func (v *version) ClusterAuthToken() ClusterAuthTokenController {
	return generic.NewController[*v3.ClusterAuthToken, *v3.ClusterAuthTokenList](schema.GroupVersionKind{Group: "cluster.cattle.io", Version: "v3", Kind: "ClusterAuthToken"}, "clusterauthtokens", true, v.controllerFactory, v.ts)
}

func (v *version) ClusterUserAttribute() ClusterUserAttributeController {
	return generic.NewController[*v3.ClusterUserAttribute, *v3.ClusterUserAttributeList](schema.GroupVersionKind{Group: "cluster.cattle.io", Version: "v3", Kind: "ClusterUserAttribute"}, "clusteruserattributes", true, v.controllerFactory, v.ts)
}
