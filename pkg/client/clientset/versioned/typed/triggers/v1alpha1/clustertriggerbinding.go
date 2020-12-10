/*
Copyright 2019 The Tekton Authors

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

// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"
	"time"

	v1alpha1 "github.com/dongwenjuan/triggers/pkg/apis/triggers/v1alpha1"
	scheme "github.com/dongwenjuan/triggers/pkg/client/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// ClusterTriggerBindingsGetter has a method to return a ClusterTriggerBindingInterface.
// A group's client should implement this interface.
type ClusterTriggerBindingsGetter interface {
	ClusterTriggerBindings() ClusterTriggerBindingInterface
}

// ClusterTriggerBindingInterface has methods to work with ClusterTriggerBinding resources.
type ClusterTriggerBindingInterface interface {
	Create(ctx context.Context, clusterTriggerBinding *v1alpha1.ClusterTriggerBinding, opts v1.CreateOptions) (*v1alpha1.ClusterTriggerBinding, error)
	Update(ctx context.Context, clusterTriggerBinding *v1alpha1.ClusterTriggerBinding, opts v1.UpdateOptions) (*v1alpha1.ClusterTriggerBinding, error)
	UpdateStatus(ctx context.Context, clusterTriggerBinding *v1alpha1.ClusterTriggerBinding, opts v1.UpdateOptions) (*v1alpha1.ClusterTriggerBinding, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.ClusterTriggerBinding, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.ClusterTriggerBindingList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.ClusterTriggerBinding, err error)
	ClusterTriggerBindingExpansion
}

// clusterTriggerBindings implements ClusterTriggerBindingInterface
type clusterTriggerBindings struct {
	client rest.Interface
}

// newClusterTriggerBindings returns a ClusterTriggerBindings
func newClusterTriggerBindings(c *TriggersV1alpha1Client) *clusterTriggerBindings {
	return &clusterTriggerBindings{
		client: c.RESTClient(),
	}
}

// Get takes name of the clusterTriggerBinding, and returns the corresponding clusterTriggerBinding object, and an error if there is any.
func (c *clusterTriggerBindings) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.ClusterTriggerBinding, err error) {
	result = &v1alpha1.ClusterTriggerBinding{}
	err = c.client.Get().
		Resource("clustertriggerbindings").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of ClusterTriggerBindings that match those selectors.
func (c *clusterTriggerBindings) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.ClusterTriggerBindingList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.ClusterTriggerBindingList{}
	err = c.client.Get().
		Resource("clustertriggerbindings").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested clusterTriggerBindings.
func (c *clusterTriggerBindings) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Resource("clustertriggerbindings").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a clusterTriggerBinding and creates it.  Returns the server's representation of the clusterTriggerBinding, and an error, if there is any.
func (c *clusterTriggerBindings) Create(ctx context.Context, clusterTriggerBinding *v1alpha1.ClusterTriggerBinding, opts v1.CreateOptions) (result *v1alpha1.ClusterTriggerBinding, err error) {
	result = &v1alpha1.ClusterTriggerBinding{}
	err = c.client.Post().
		Resource("clustertriggerbindings").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(clusterTriggerBinding).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a clusterTriggerBinding and updates it. Returns the server's representation of the clusterTriggerBinding, and an error, if there is any.
func (c *clusterTriggerBindings) Update(ctx context.Context, clusterTriggerBinding *v1alpha1.ClusterTriggerBinding, opts v1.UpdateOptions) (result *v1alpha1.ClusterTriggerBinding, err error) {
	result = &v1alpha1.ClusterTriggerBinding{}
	err = c.client.Put().
		Resource("clustertriggerbindings").
		Name(clusterTriggerBinding.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(clusterTriggerBinding).
		Do(ctx).
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *clusterTriggerBindings) UpdateStatus(ctx context.Context, clusterTriggerBinding *v1alpha1.ClusterTriggerBinding, opts v1.UpdateOptions) (result *v1alpha1.ClusterTriggerBinding, err error) {
	result = &v1alpha1.ClusterTriggerBinding{}
	err = c.client.Put().
		Resource("clustertriggerbindings").
		Name(clusterTriggerBinding.Name).
		SubResource("status").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(clusterTriggerBinding).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the clusterTriggerBinding and deletes it. Returns an error if one occurs.
func (c *clusterTriggerBindings) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Resource("clustertriggerbindings").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *clusterTriggerBindings) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Resource("clustertriggerbindings").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched clusterTriggerBinding.
func (c *clusterTriggerBindings) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.ClusterTriggerBinding, err error) {
	result = &v1alpha1.ClusterTriggerBinding{}
	err = c.client.Patch(pt).
		Resource("clustertriggerbindings").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
