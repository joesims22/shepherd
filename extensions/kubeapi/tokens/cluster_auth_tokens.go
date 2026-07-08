package tokens

import (
	"context"
	"fmt"

	clusterv3 "github.com/rancher/rancher/pkg/apis/cluster.cattle.io/v3"
	"github.com/rancher/shepherd/clients/rancher"
	"github.com/rancher/shepherd/extensions/defaults"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kwait "k8s.io/apimachinery/pkg/util/wait"
)

// CreateClusterAuthToken creates a cluster auth token using the wrangler context
func CreateClusterAuthToken(client *rancher.Client, clusterAuthToken *clusterv3.ClusterAuthToken) (*clusterv3.ClusterAuthToken, error) {
	createdClusterAuthToken, err := client.WranglerContext.Cluster.ClusterAuthToken().Create(clusterAuthToken)
	if err != nil {
		return nil, fmt.Errorf("failed to create cluster auth token: %w", err)
	}

	return createdClusterAuthToken, nil
}

// GetClusterAuthTokenByName retrieves a cluster auth token by namespace and name using the wrangler context
func GetClusterAuthTokenByName(client *rancher.Client, namespace, name string) (*clusterv3.ClusterAuthToken, error) {
	clusterAuthToken, err := client.WranglerContext.Cluster.ClusterAuthToken().Get(namespace, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get cluster auth token %s/%s: %w", namespace, name, err)
	}

	return clusterAuthToken, nil
}

// ListClusterAuthTokens retrieves cluster auth tokens in the given namespace using the wrangler context
func ListClusterAuthTokens(client *rancher.Client, namespace string, listOpts metav1.ListOptions) (*clusterv3.ClusterAuthTokenList, error) {
	clusterAuthTokens, err := client.WranglerContext.Cluster.ClusterAuthToken().List(namespace, listOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster auth tokens: %w", err)
	}

	return clusterAuthTokens, nil
}

// UpdateClusterAuthToken updates an existing cluster auth token using wrangler context and returns the updated object
func UpdateClusterAuthToken(client *rancher.Client, clusterAuthToken *clusterv3.ClusterAuthToken) (*clusterv3.ClusterAuthToken, error) {
	if clusterAuthToken == nil {
		return nil, fmt.Errorf("cluster auth token object is nil")
	}

	var updated *clusterv3.ClusterAuthToken
	var lastErr error

	err := kwait.PollUntilContextTimeout(context.TODO(), defaults.FiveSecondTimeout, defaults.OneMinuteTimeout, false, func(ctx context.Context) (bool, error) {
		current, getErr := GetClusterAuthTokenByName(client, clusterAuthToken.Namespace, clusterAuthToken.Name)
		if getErr != nil {
			lastErr = fmt.Errorf("failed to get cluster auth token %s/%s: %w", clusterAuthToken.Namespace, clusterAuthToken.Name, getErr)
			return false, nil
		}
		clusterAuthToken.ResourceVersion = current.ResourceVersion
		updated, lastErr = client.WranglerContext.Cluster.ClusterAuthToken().Update(clusterAuthToken)
		if lastErr != nil {
			if k8serrors.IsConflict(lastErr) {
				return false, nil
			}
			return false, lastErr
		}
		return true, nil
	})

	if err != nil {
		return nil, fmt.Errorf("timed out updating cluster auth token %s/%s: %w", clusterAuthToken.Namespace, clusterAuthToken.Name, lastErr)
	}

	return updated, nil
}

// DeleteClusterAuthToken deletes a cluster auth token by namespace and name using wrangler context and optionally waits for deletion
func DeleteClusterAuthToken(client *rancher.Client, namespace, name string, waitForDelete bool) error {
	err := client.WranglerContext.Cluster.ClusterAuthToken().Delete(namespace, name, &metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete cluster auth token %s/%s: %w", namespace, name, err)
	}

	if waitForDelete {
		err = WaitForClusterAuthTokenDeletion(client, namespace, name)
		if err != nil {
			return fmt.Errorf("timed out waiting for cluster auth token %s/%s to be deleted: %w", namespace, name, err)
		}
	}
	return nil
}

// WaitForClusterAuthTokenDeletion polls until a cluster auth token with the given namespace and name is deleted or the timeout is reached
func WaitForClusterAuthTokenDeletion(client *rancher.Client, namespace, name string) error {
	return kwait.PollUntilContextTimeout(context.TODO(), defaults.FiveSecondTimeout, defaults.OneMinuteTimeout, false, func(ctx context.Context) (bool, error) {
		_, err := GetClusterAuthTokenByName(client, namespace, name)
		if err != nil {
			if k8serrors.IsNotFound(err) {
				return true, nil
			}
			return false, err
		}
		return false, nil
	})
}
