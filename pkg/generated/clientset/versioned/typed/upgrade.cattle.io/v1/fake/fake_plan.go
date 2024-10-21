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

package fake

import (
	"context"

	v1 "github.com/rancher/system-upgrade-controller/pkg/apis/upgrade.cattle.io/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakePlans implements PlanInterface
type FakePlans struct {
	Fake *FakeUpgradeV1
	ns   string
}

var plansResource = v1.SchemeGroupVersion.WithResource("plans")

var plansKind = v1.SchemeGroupVersion.WithKind("Plan")

// Get takes name of the plan, and returns the corresponding plan object, and an error if there is any.
func (c *FakePlans) Get(ctx context.Context, name string, options metav1.GetOptions) (result *v1.Plan, err error) {
	emptyResult := &v1.Plan{}
	obj, err := c.Fake.
		Invokes(testing.NewGetActionWithOptions(plansResource, c.ns, name, options), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.Plan), err
}

// List takes label and field selectors, and returns the list of Plans that match those selectors.
func (c *FakePlans) List(ctx context.Context, opts metav1.ListOptions) (result *v1.PlanList, err error) {
	emptyResult := &v1.PlanList{}
	obj, err := c.Fake.
		Invokes(testing.NewListActionWithOptions(plansResource, plansKind, c.ns, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1.PlanList{ListMeta: obj.(*v1.PlanList).ListMeta}
	for _, item := range obj.(*v1.PlanList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested plans.
func (c *FakePlans) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchActionWithOptions(plansResource, c.ns, opts))

}

// Create takes the representation of a plan and creates it.  Returns the server's representation of the plan, and an error, if there is any.
func (c *FakePlans) Create(ctx context.Context, plan *v1.Plan, opts metav1.CreateOptions) (result *v1.Plan, err error) {
	emptyResult := &v1.Plan{}
	obj, err := c.Fake.
		Invokes(testing.NewCreateActionWithOptions(plansResource, c.ns, plan, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.Plan), err
}

// Update takes the representation of a plan and updates it. Returns the server's representation of the plan, and an error, if there is any.
func (c *FakePlans) Update(ctx context.Context, plan *v1.Plan, opts metav1.UpdateOptions) (result *v1.Plan, err error) {
	emptyResult := &v1.Plan{}
	obj, err := c.Fake.
		Invokes(testing.NewUpdateActionWithOptions(plansResource, c.ns, plan, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.Plan), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakePlans) UpdateStatus(ctx context.Context, plan *v1.Plan, opts metav1.UpdateOptions) (result *v1.Plan, err error) {
	emptyResult := &v1.Plan{}
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceActionWithOptions(plansResource, "status", c.ns, plan, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.Plan), err
}

// Delete takes name of the plan and deletes it. Returns an error if one occurs.
func (c *FakePlans) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(plansResource, c.ns, name, opts), &v1.Plan{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakePlans) DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	action := testing.NewDeleteCollectionActionWithOptions(plansResource, c.ns, opts, listOpts)

	_, err := c.Fake.Invokes(action, &v1.PlanList{})
	return err
}

// Patch applies the patch and returns the patched plan.
func (c *FakePlans) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.Plan, err error) {
	emptyResult := &v1.Plan{}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceActionWithOptions(plansResource, c.ns, name, pt, data, opts, subresources...), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.Plan), err
}
