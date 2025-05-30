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
	"github.com/rancher/shepherd/pkg/session"
	"github.com/rancher/shepherd/pkg/wrangler/pkg/generic"
	"github.com/rancher/wrangler/v3/pkg/schemes"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func init() {
	schemes.Register(v1.AddToScheme)
}

type Interface interface {
	ConfigMap() ConfigMapController
	Endpoints() EndpointsController
	Event() EventController
	LimitRange() LimitRangeController
	Namespace() NamespaceController
	Node() NodeController
	PersistentVolume() PersistentVolumeController
	PersistentVolumeClaim() PersistentVolumeClaimController
	Pod() PodController
	ResourceQuota() ResourceQuotaController
	Secret() SecretController
	Service() ServiceController
	ServiceAccount() ServiceAccountController
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

func (v *version) ConfigMap() ConfigMapController {
	return generic.NewController[*v1.ConfigMap, *v1.ConfigMapList](schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ConfigMap"}, "configmaps", true, v.controllerFactory, v.ts)
}

func (v *version) Endpoints() EndpointsController {
	return generic.NewController[*v1.Endpoints, *v1.EndpointsList](schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Endpoints"}, "endpoints", true, v.controllerFactory, v.ts)
}

func (v *version) Event() EventController {
	return generic.NewController[*v1.Event, *v1.EventList](schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Event"}, "events", true, v.controllerFactory, v.ts)
}

func (v *version) LimitRange() LimitRangeController {
	return generic.NewController[*v1.LimitRange, *v1.LimitRangeList](schema.GroupVersionKind{Group: "", Version: "v1", Kind: "LimitRange"}, "limitranges", true, v.controllerFactory, v.ts)
}

func (v *version) Namespace() NamespaceController {
	return generic.NewNonNamespacedController[*v1.Namespace, *v1.NamespaceList](schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Namespace"}, "namespaces", v.controllerFactory, v.ts)
}

func (v *version) Node() NodeController {
	return generic.NewNonNamespacedController[*v1.Node, *v1.NodeList](schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Node"}, "nodes", v.controllerFactory, v.ts)
}

func (v *version) PersistentVolume() PersistentVolumeController {
	return generic.NewNonNamespacedController[*v1.PersistentVolume, *v1.PersistentVolumeList](schema.GroupVersionKind{Group: "", Version: "v1", Kind: "PersistentVolume"}, "persistentvolumes", v.controllerFactory, v.ts)
}

func (v *version) PersistentVolumeClaim() PersistentVolumeClaimController {
	return generic.NewController[*v1.PersistentVolumeClaim, *v1.PersistentVolumeClaimList](schema.GroupVersionKind{Group: "", Version: "v1", Kind: "PersistentVolumeClaim"}, "persistentvolumeclaims", true, v.controllerFactory, v.ts)
}

func (v *version) Pod() PodController {
	return generic.NewController[*v1.Pod, *v1.PodList](schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"}, "pods", true, v.controllerFactory, v.ts)
}

func (v *version) ResourceQuota() ResourceQuotaController {
	return generic.NewController[*v1.ResourceQuota, *v1.ResourceQuotaList](schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ResourceQuota"}, "resourcequotas", true, v.controllerFactory, v.ts)
}

func (v *version) Secret() SecretController {
	return generic.NewController[*v1.Secret, *v1.SecretList](schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Secret"}, "secrets", true, v.controllerFactory, v.ts)
}

func (v *version) Service() ServiceController {
	return generic.NewController[*v1.Service, *v1.ServiceList](schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Service"}, "services", true, v.controllerFactory, v.ts)
}

func (v *version) ServiceAccount() ServiceAccountController {
	return generic.NewController[*v1.ServiceAccount, *v1.ServiceAccountList](schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ServiceAccount"}, "serviceaccounts", true, v.controllerFactory, v.ts)
}
