package azurekeyvault

import (
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/hashicorp/go-hclog"
	azkv "github.com/spiffe/spire/pkg/common/plugin/azure_keyvault"
)

// cloudKeyManagementService is an alias for the shared interface.
type cloudKeyManagementService = azkv.CloudKeyManagementService

// newKeyVaultClient creates a new Key Vault client with logging enabled.
func newKeyVaultClient(creds azcore.TokenCredential, keyVaultURI string, log hclog.Logger) (cloudKeyManagementService, error) {
	return azkv.NewKeyVaultClient(creds, keyVaultURI, &azkv.ClientConfig{
		Logger: log,
	})
}
