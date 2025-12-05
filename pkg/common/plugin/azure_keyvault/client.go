package azure_keyvault

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/hashicorp/go-hclog"
)

// CloudKeyManagementService defines the Azure Key Vault operations
// used by both server and agent key manager plugins.
type CloudKeyManagementService interface {
	CreateKey(ctx context.Context, name string, parameters azkeys.CreateKeyParameters, options *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error)
	DeleteKey(ctx context.Context, name string, options *azkeys.DeleteKeyOptions) (azkeys.DeleteKeyResponse, error)
	UpdateKey(ctx context.Context, name string, version string, parameters azkeys.UpdateKeyParameters, options *azkeys.UpdateKeyOptions) (azkeys.UpdateKeyResponse, error)
	GetKey(ctx context.Context, name string, version string, options *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error)
	NewListKeysPager(options *azkeys.ListKeysOptions) *runtime.Pager[azkeys.ListKeysResponse]
	Sign(ctx context.Context, name string, version string, parameters azkeys.SignParameters, options *azkeys.SignOptions) (azkeys.SignResponse, error)
}

// ClientConfig holds optional configuration for the Key Vault client.
type ClientConfig struct {
	// Logger is optional. If set, all Azure API calls will be logged.
	Logger hclog.Logger
}

// keyVaultClient wraps the Azure SDK client with optional logging.
type keyVaultClient struct {
	client *azkeys.Client
	log    hclog.Logger
}

// NewKeyVaultClient creates a new Key Vault client with optional logging.
// If config is nil or config.Logger is nil, no logging will be performed.
func NewKeyVaultClient(creds azcore.TokenCredential, keyVaultURI string, config *ClientConfig) (CloudKeyManagementService, error) {
	client, err := azkeys.NewClient(keyVaultURI, creds, nil)
	if err != nil {
		return nil, err
	}

	var log hclog.Logger
	if config != nil && config.Logger != nil {
		log = config.Logger
	}

	return &keyVaultClient{
		client: client,
		log:    log,
	}, nil
}

func (c *keyVaultClient) CreateKey(ctx context.Context, name string, parameters azkeys.CreateKeyParameters, options *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error) {
	if c.log != nil {
		c.log.Debug("Calling Key Vault CreateKey", "key_name", name, "key_type", parameters.Kty)
	}
	resp, err := c.client.CreateKey(ctx, name, parameters, options)
	if err != nil {
		if c.log != nil {
			c.log.Error("Key Vault CreateKey failed", "key_name", name, "error", err)
		}
	} else if c.log != nil {
		c.log.Debug("Key Vault CreateKey succeeded", "key_name", name, "key_id", resp.Key.KID)
	}
	return resp, err
}

func (c *keyVaultClient) DeleteKey(ctx context.Context, name string, options *azkeys.DeleteKeyOptions) (azkeys.DeleteKeyResponse, error) {
	if c.log != nil {
		c.log.Debug("Calling Key Vault DeleteKey", "key_name", name)
	}
	resp, err := c.client.DeleteKey(ctx, name, options)
	if err != nil {
		if c.log != nil {
			c.log.Error("Key Vault DeleteKey failed", "key_name", name, "error", err)
		}
	} else if c.log != nil {
		c.log.Debug("Key Vault DeleteKey succeeded", "key_name", name)
	}
	return resp, err
}

func (c *keyVaultClient) UpdateKey(ctx context.Context, name string, version string, parameters azkeys.UpdateKeyParameters, options *azkeys.UpdateKeyOptions) (azkeys.UpdateKeyResponse, error) {
	if c.log != nil {
		c.log.Debug("Calling Key Vault UpdateKey", "key_name", name, "version", version)
	}
	resp, err := c.client.UpdateKey(ctx, name, version, parameters, options)
	if err != nil {
		if c.log != nil {
			c.log.Error("Key Vault UpdateKey failed", "key_name", name, "version", version, "error", err)
		}
	} else if c.log != nil {
		c.log.Debug("Key Vault UpdateKey succeeded", "key_name", name, "version", version)
	}
	return resp, err
}

func (c *keyVaultClient) GetKey(ctx context.Context, name string, version string, options *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
	if c.log != nil {
		c.log.Debug("Calling Key Vault GetKey", "key_name", name, "version", version)
	}
	resp, err := c.client.GetKey(ctx, name, version, options)
	if err != nil {
		if c.log != nil {
			c.log.Error("Key Vault GetKey failed", "key_name", name, "version", version, "error", err)
		}
	} else if c.log != nil {
		c.log.Debug("Key Vault GetKey succeeded", "key_name", name, "version", version, "key_id", resp.Key.KID)
	}
	return resp, err
}

func (c *keyVaultClient) NewListKeysPager(options *azkeys.ListKeysOptions) *runtime.Pager[azkeys.ListKeysResponse] {
	if c.log != nil {
		c.log.Debug("Calling Key Vault NewListKeysPager")
	}
	return c.client.NewListKeysPager(options)
}

func (c *keyVaultClient) Sign(ctx context.Context, name string, version string, parameters azkeys.SignParameters, options *azkeys.SignOptions) (azkeys.SignResponse, error) {
	if c.log != nil {
		c.log.Debug("Calling Key Vault Sign", "key_name", name, "version", version, "algorithm", parameters.Algorithm)
	}
	resp, err := c.client.Sign(ctx, name, version, parameters, options)
	if err != nil {
		if c.log != nil {
			c.log.Error("Key Vault Sign failed", "key_name", name, "version", version, "algorithm", parameters.Algorithm, "error", err)
		}
	} else if c.log != nil {
		c.log.Debug("Key Vault Sign succeeded", "key_name", name, "version", version, "algorithm", parameters.Algorithm)
	}
	return resp, err
}
