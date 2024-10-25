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

package v1

import (
	"context"
	"sync"
	"time"

	v1 "github.com/rancher/rancher/pkg/apis/rke.cattle.io/v1"
	"github.com/rancher/shepherd/pkg/wrangler/pkg/generic"
	"github.com/rancher/wrangler/v3/pkg/apply"
	"github.com/rancher/wrangler/v3/pkg/condition"
	"github.com/rancher/wrangler/v3/pkg/kv"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ETCDSnapshotController interface for managing ETCDSnapshot resources.
type ETCDSnapshotController interface {
	generic.ControllerInterface[*v1.ETCDSnapshot, *v1.ETCDSnapshotList]
}

// ETCDSnapshotClient interface for managing ETCDSnapshot resources in Kubernetes.
type ETCDSnapshotClient interface {
	generic.ClientInterface[*v1.ETCDSnapshot, *v1.ETCDSnapshotList]
}

// ETCDSnapshotCache interface for retrieving ETCDSnapshot resources in memory.
type ETCDSnapshotCache interface {
	generic.CacheInterface[*v1.ETCDSnapshot]
}

// ETCDSnapshotStatusHandler is executed for every added or modified ETCDSnapshot. Should return the new status to be updated
type ETCDSnapshotStatusHandler func(obj *v1.ETCDSnapshot, status v1.ETCDSnapshotStatus) (v1.ETCDSnapshotStatus, error)

// ETCDSnapshotGeneratingHandler is the top-level handler that is executed for every ETCDSnapshot event. It extends ETCDSnapshotStatusHandler by a returning a slice of child objects to be passed to apply.Apply
type ETCDSnapshotGeneratingHandler func(obj *v1.ETCDSnapshot, status v1.ETCDSnapshotStatus) ([]runtime.Object, v1.ETCDSnapshotStatus, error)

// RegisterETCDSnapshotStatusHandler configures a ETCDSnapshotController to execute a ETCDSnapshotStatusHandler for every events observed.
// If a non-empty condition is provided, it will be updated in the status conditions for every handler execution
func RegisterETCDSnapshotStatusHandler(ctx context.Context, controller ETCDSnapshotController, condition condition.Cond, name string, handler ETCDSnapshotStatusHandler) {
	statusHandler := &eTCDSnapshotStatusHandler{
		client:    controller,
		condition: condition,
		handler:   handler,
	}
	controller.AddGenericHandler(ctx, name, generic.FromObjectHandlerToHandler(statusHandler.sync))
}

// RegisterETCDSnapshotGeneratingHandler configures a ETCDSnapshotController to execute a ETCDSnapshotGeneratingHandler for every events observed, passing the returned objects to the provided apply.Apply.
// If a non-empty condition is provided, it will be updated in the status conditions for every handler execution
func RegisterETCDSnapshotGeneratingHandler(ctx context.Context, controller ETCDSnapshotController, apply apply.Apply,
	condition condition.Cond, name string, handler ETCDSnapshotGeneratingHandler, opts *generic.GeneratingHandlerOptions) {
	statusHandler := &eTCDSnapshotGeneratingHandler{
		ETCDSnapshotGeneratingHandler: handler,
		apply:                         apply,
		name:                          name,
		gvk:                           controller.GroupVersionKind(),
	}
	if opts != nil {
		statusHandler.opts = *opts
	}
	controller.OnChange(ctx, name, statusHandler.Remove)
	RegisterETCDSnapshotStatusHandler(ctx, controller, condition, name, statusHandler.Handle)
}

type eTCDSnapshotStatusHandler struct {
	client    ETCDSnapshotClient
	condition condition.Cond
	handler   ETCDSnapshotStatusHandler
}

// sync is executed on every resource addition or modification. Executes the configured handlers and sends the updated status to the Kubernetes API
func (a *eTCDSnapshotStatusHandler) sync(key string, obj *v1.ETCDSnapshot) (*v1.ETCDSnapshot, error) {
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

type eTCDSnapshotGeneratingHandler struct {
	ETCDSnapshotGeneratingHandler
	apply apply.Apply
	opts  generic.GeneratingHandlerOptions
	gvk   schema.GroupVersionKind
	name  string
	seen  sync.Map
}

// Remove handles the observed deletion of a resource, cascade deleting every associated resource previously applied
func (a *eTCDSnapshotGeneratingHandler) Remove(key string, obj *v1.ETCDSnapshot) (*v1.ETCDSnapshot, error) {
	if obj != nil {
		return obj, nil
	}

	obj = &v1.ETCDSnapshot{}
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

// Handle executes the configured ETCDSnapshotGeneratingHandler and pass the resulting objects to apply.Apply, finally returning the new status of the resource
func (a *eTCDSnapshotGeneratingHandler) Handle(obj *v1.ETCDSnapshot, status v1.ETCDSnapshotStatus) (v1.ETCDSnapshotStatus, error) {
	if !obj.DeletionTimestamp.IsZero() {
		return status, nil
	}

	objs, newStatus, err := a.ETCDSnapshotGeneratingHandler(obj, status)
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
func (a *eTCDSnapshotGeneratingHandler) isNewResourceVersion(obj *v1.ETCDSnapshot) bool {
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
func (a *eTCDSnapshotGeneratingHandler) storeResourceVersion(obj *v1.ETCDSnapshot) {
	if !a.opts.UniqueApplyForResourceVersion {
		return
	}

	key := obj.Namespace + "/" + obj.Name
	a.seen.Store(key, obj.ResourceVersion)
}
