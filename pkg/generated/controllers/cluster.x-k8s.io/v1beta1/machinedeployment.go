/*
Copyright 2024 Rancher Labs, Inc.

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

package v1beta1

import (
	"context"
	"sync"
	"time"

	"github.com/rancher/shepherd/pkg/wrangler/pkg/generic"
	"github.com/rancher/wrangler/v3/pkg/apply"
	"github.com/rancher/wrangler/v3/pkg/condition"
	"github.com/rancher/wrangler/v3/pkg/kv"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	v1beta1 "sigs.k8s.io/cluster-api/api/v1beta1"
)

// MachineDeploymentController interface for managing MachineDeployment resources.
type MachineDeploymentController interface {
	generic.ControllerInterface[*v1beta1.MachineDeployment, *v1beta1.MachineDeploymentList]
}

// MachineDeploymentClient interface for managing MachineDeployment resources in Kubernetes.
type MachineDeploymentClient interface {
	generic.ClientInterface[*v1beta1.MachineDeployment, *v1beta1.MachineDeploymentList]
}

// MachineDeploymentCache interface for retrieving MachineDeployment resources in memory.
type MachineDeploymentCache interface {
	generic.CacheInterface[*v1beta1.MachineDeployment]
}

// MachineDeploymentStatusHandler is executed for every added or modified MachineDeployment. Should return the new status to be updated
type MachineDeploymentStatusHandler func(obj *v1beta1.MachineDeployment, status v1beta1.MachineDeploymentStatus) (v1beta1.MachineDeploymentStatus, error)

// MachineDeploymentGeneratingHandler is the top-level handler that is executed for every MachineDeployment event. It extends MachineDeploymentStatusHandler by a returning a slice of child objects to be passed to apply.Apply
type MachineDeploymentGeneratingHandler func(obj *v1beta1.MachineDeployment, status v1beta1.MachineDeploymentStatus) ([]runtime.Object, v1beta1.MachineDeploymentStatus, error)

// RegisterMachineDeploymentStatusHandler configures a MachineDeploymentController to execute a MachineDeploymentStatusHandler for every events observed.
// If a non-empty condition is provided, it will be updated in the status conditions for every handler execution
func RegisterMachineDeploymentStatusHandler(ctx context.Context, controller MachineDeploymentController, condition condition.Cond, name string, handler MachineDeploymentStatusHandler) {
	statusHandler := &machineDeploymentStatusHandler{
		client:    controller,
		condition: condition,
		handler:   handler,
	}
	controller.AddGenericHandler(ctx, name, generic.FromObjectHandlerToHandler(statusHandler.sync))
}

// RegisterMachineDeploymentGeneratingHandler configures a MachineDeploymentController to execute a MachineDeploymentGeneratingHandler for every events observed, passing the returned objects to the provided apply.Apply.
// If a non-empty condition is provided, it will be updated in the status conditions for every handler execution
func RegisterMachineDeploymentGeneratingHandler(ctx context.Context, controller MachineDeploymentController, apply apply.Apply,
	condition condition.Cond, name string, handler MachineDeploymentGeneratingHandler, opts *generic.GeneratingHandlerOptions) {
	statusHandler := &machineDeploymentGeneratingHandler{
		MachineDeploymentGeneratingHandler: handler,
		apply:                              apply,
		name:                               name,
		gvk:                                controller.GroupVersionKind(),
	}
	if opts != nil {
		statusHandler.opts = *opts
	}
	controller.OnChange(ctx, name, statusHandler.Remove)
	RegisterMachineDeploymentStatusHandler(ctx, controller, condition, name, statusHandler.Handle)
}

type machineDeploymentStatusHandler struct {
	client    MachineDeploymentClient
	condition condition.Cond
	handler   MachineDeploymentStatusHandler
}

// sync is executed on every resource addition or modification. Executes the configured handlers and sends the updated status to the Kubernetes API
func (a *machineDeploymentStatusHandler) sync(key string, obj *v1beta1.MachineDeployment) (*v1beta1.MachineDeployment, error) {
	if obj == nil {
		return obj, nil
	}

	origStatus := obj.Status.DeepCopy()
	obj = obj.DeepCopy()
	newStatus, err := a.handler(obj, obj.Status)
	if err != nil {
		// Revert to old status on error
		newStatus = *origStatus.DeepCopy()
	}

	if a.condition != "" {
		if errors.IsConflict(err) {
			a.condition.SetError(&newStatus, "", nil)
		} else {
			a.condition.SetError(&newStatus, "", err)
		}
	}
	if !equality.Semantic.DeepEqual(origStatus, &newStatus) {
		if a.condition != "" {
			// Since status has changed, update the lastUpdatedTime
			a.condition.LastUpdated(&newStatus, time.Now().UTC().Format(time.RFC3339))
		}

		var newErr error
		obj.Status = newStatus
		newObj, newErr := a.client.UpdateStatus(obj)
		if err == nil {
			err = newErr
		}
		if newErr == nil {
			obj = newObj
		}
	}
	return obj, err
}

type machineDeploymentGeneratingHandler struct {
	MachineDeploymentGeneratingHandler
	apply apply.Apply
	opts  generic.GeneratingHandlerOptions
	gvk   schema.GroupVersionKind
	name  string
	seen  sync.Map
}

// Remove handles the observed deletion of a resource, cascade deleting every associated resource previously applied
func (a *machineDeploymentGeneratingHandler) Remove(key string, obj *v1beta1.MachineDeployment) (*v1beta1.MachineDeployment, error) {
	if obj != nil {
		return obj, nil
	}

	obj = &v1beta1.MachineDeployment{}
	obj.Namespace, obj.Name = kv.RSplit(key, "/")
	obj.SetGroupVersionKind(a.gvk)

	if a.opts.UniqueApplyForResourceVersion {
		a.seen.Delete(key)
	}

	return nil, generic.ConfigureApplyForObject(a.apply, obj, &a.opts).
		WithOwner(obj).
		WithSetID(a.name).
		ApplyObjects()
}

// Handle executes the configured MachineDeploymentGeneratingHandler and pass the resulting objects to apply.Apply, finally returning the new status of the resource
func (a *machineDeploymentGeneratingHandler) Handle(obj *v1beta1.MachineDeployment, status v1beta1.MachineDeploymentStatus) (v1beta1.MachineDeploymentStatus, error) {
	if !obj.DeletionTimestamp.IsZero() {
		return status, nil
	}

	objs, newStatus, err := a.MachineDeploymentGeneratingHandler(obj, status)
	if err != nil {
		return newStatus, err
	}
	if !a.isNewResourceVersion(obj) {
		return newStatus, nil
	}

	err = generic.ConfigureApplyForObject(a.apply, obj, &a.opts).
		WithOwner(obj).
		WithSetID(a.name).
		ApplyObjects(objs...)
	if err != nil {
		return newStatus, err
	}
	a.storeResourceVersion(obj)
	return newStatus, nil
}

// isNewResourceVersion detects if a specific resource version was already successfully processed.
// Only used if UniqueApplyForResourceVersion is set in generic.GeneratingHandlerOptions
func (a *machineDeploymentGeneratingHandler) isNewResourceVersion(obj *v1beta1.MachineDeployment) bool {
	if !a.opts.UniqueApplyForResourceVersion {
		return true
	}

	// Apply once per resource version
	key := obj.Namespace + "/" + obj.Name
	previous, ok := a.seen.Load(key)
	return !ok || previous != obj.ResourceVersion
}

// storeResourceVersion keeps track of the latest resource version of an object for which Apply was executed
// Only used if UniqueApplyForResourceVersion is set in generic.GeneratingHandlerOptions
func (a *machineDeploymentGeneratingHandler) storeResourceVersion(obj *v1beta1.MachineDeployment) {
	if !a.opts.UniqueApplyForResourceVersion {
		return
	}

	key := obj.Namespace + "/" + obj.Name
	a.seen.Store(key, obj.ResourceVersion)
}
