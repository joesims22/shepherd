package client

import (
	"github.com/rancher/norman/types"
)

const (
	ProjectType                               = "project"
	ProjectFieldAnnotations                   = "annotations"
	ProjectFieldBackingNamespace              = "backingNamespace"
	ProjectFieldClusterID                     = "clusterId"
	ProjectFieldConditions                    = "conditions"
	ProjectFieldContainerDefaultResourceLimit = "containerDefaultResourceLimit"
	ProjectFieldCreated                       = "created"
	ProjectFieldCreatorID                     = "creatorId"
	ProjectFieldDescription                   = "description"
	ProjectFieldLabels                        = "labels"
	ProjectFieldName                          = "name"
	ProjectFieldNamespaceDefaultResourceQuota = "namespaceDefaultResourceQuota"
	ProjectFieldNamespaceId                   = "namespaceId"
	ProjectFieldOwnerReferences               = "ownerReferences"
	ProjectFieldRemoved                       = "removed"
	ProjectFieldResourceQuota                 = "resourceQuota"
	ProjectFieldState                         = "state"
	ProjectFieldTransitioning                 = "transitioning"
	ProjectFieldTransitioningMessage          = "transitioningMessage"
	ProjectFieldUUID                          = "uuid"
)

type Project struct {
	types.Resource
	Annotations                   map[string]string       `json:"annotations,omitempty" yaml:"annotations,omitempty"`
	BackingNamespace              string                  `json:"backingNamespace,omitempty" yaml:"backingNamespace,omitempty"`
	ClusterID                     string                  `json:"clusterId,omitempty" yaml:"clusterId,omitempty"`
	Conditions                    []ProjectCondition      `json:"conditions,omitempty" yaml:"conditions,omitempty"`
	ContainerDefaultResourceLimit *ContainerResourceLimit `json:"containerDefaultResourceLimit,omitempty" yaml:"containerDefaultResourceLimit,omitempty"`
	Created                       string                  `json:"created,omitempty" yaml:"created,omitempty"`
	CreatorID                     string                  `json:"creatorId,omitempty" yaml:"creatorId,omitempty"`
	Description                   string                  `json:"description,omitempty" yaml:"description,omitempty"`
	Labels                        map[string]string       `json:"labels,omitempty" yaml:"labels,omitempty"`
	Name                          string                  `json:"name,omitempty" yaml:"name,omitempty"`
	NamespaceDefaultResourceQuota *NamespaceResourceQuota `json:"namespaceDefaultResourceQuota,omitempty" yaml:"namespaceDefaultResourceQuota,omitempty"`
	NamespaceId                   string                  `json:"namespaceId,omitempty" yaml:"namespaceId,omitempty"`
	OwnerReferences               []OwnerReference        `json:"ownerReferences,omitempty" yaml:"ownerReferences,omitempty"`
	Removed                       string                  `json:"removed,omitempty" yaml:"removed,omitempty"`
	ResourceQuota                 *ProjectResourceQuota   `json:"resourceQuota,omitempty" yaml:"resourceQuota,omitempty"`
	State                         string                  `json:"state,omitempty" yaml:"state,omitempty"`
	Transitioning                 string                  `json:"transitioning,omitempty" yaml:"transitioning,omitempty"`
	TransitioningMessage          string                  `json:"transitioningMessage,omitempty" yaml:"transitioningMessage,omitempty"`
	UUID                          string                  `json:"uuid,omitempty" yaml:"uuid,omitempty"`
}

type ProjectCollection struct {
	types.Collection
	Data   []Project `json:"data,omitempty"`
	client *ProjectClient
}

type ProjectClient struct {
	apiClient *Client
}

type ProjectOperations interface {
	List(opts *types.ListOpts) (*ProjectCollection, error)
	ListAll(opts *types.ListOpts) (*ProjectCollection, error)
	Create(opts *Project) (*Project, error)
	Update(existing *Project, updates interface{}) (*Project, error)
	Replace(existing *Project) (*Project, error)
	ByID(id string) (*Project, error)
	Delete(container *Project) error
}

func newProjectClient(apiClient *Client) *ProjectClient {
	return &ProjectClient{
		apiClient: apiClient,
	}
}

func (c *ProjectClient) Create(container *Project) (*Project, error) {
	resp := &Project{}
	err := c.apiClient.Ops.DoCreate(ProjectType, container, resp)
	return resp, err
}

func (c *ProjectClient) Update(existing *Project, updates interface{}) (*Project, error) {
	resp := &Project{}
	err := c.apiClient.Ops.DoUpdate(ProjectType, &existing.Resource, updates, resp)
	return resp, err
}

func (c *ProjectClient) Replace(obj *Project) (*Project, error) {
	resp := &Project{}
	err := c.apiClient.Ops.DoReplace(ProjectType, &obj.Resource, obj, resp)
	return resp, err
}

func (c *ProjectClient) List(opts *types.ListOpts) (*ProjectCollection, error) {
	resp := &ProjectCollection{}
	err := c.apiClient.Ops.DoList(ProjectType, opts, resp)
	resp.client = c
	return resp, err
}

func (c *ProjectClient) ListAll(opts *types.ListOpts) (*ProjectCollection, error) {
	resp := &ProjectCollection{}
	resp, err := c.List(opts)
	if err != nil {
		return resp, err
	}
	data := resp.Data
	for next, err := resp.Next(); next != nil && err == nil; next, err = next.Next() {
		data = append(data, next.Data...)
		resp = next
		resp.Data = data
	}
	if err != nil {
		return resp, err
	}
	return resp, err
}

func (cc *ProjectCollection) Next() (*ProjectCollection, error) {
	if cc != nil && cc.Pagination != nil && cc.Pagination.Next != "" {
		resp := &ProjectCollection{}
		err := cc.client.apiClient.Ops.DoNext(cc.Pagination.Next, resp)
		resp.client = cc.client
		return resp, err
	}
	return nil, nil
}

func (c *ProjectClient) ByID(id string) (*Project, error) {
	resp := &Project{}
	err := c.apiClient.Ops.DoByID(ProjectType, id, resp)
	return resp, err
}

func (c *ProjectClient) Delete(container *Project) error {
	return c.apiClient.Ops.DoResourceDelete(ProjectType, &container.Resource)
}
