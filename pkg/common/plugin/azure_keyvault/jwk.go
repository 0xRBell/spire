package azure_keyvault

import (
	"encoding/json"
	"errors"

	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/go-jose/go-jose/v4"
)

// JWKToRawKey converts an Azure JSONWebKey to the corresponding raw Go crypto
// public key type (e.g., *rsa.PublicKey or *ecdsa.PublicKey).
func JWKToRawKey(keyVaultKey *azkeys.JSONWebKey) (any, error) {
	if keyVaultKey == nil {
		return nil, errors.New("key vault key is nil")
	}

	// Marshal the Azure JWK to JSON
	jwkJSON, err := keyVaultKey.MarshalJSON()
	if err != nil {
		return nil, err
	}

	// Parse the JSON into go-jose JWK format
	var key jose.JSONWebKey
	if err := json.Unmarshal(jwkJSON, &key); err != nil {
		return nil, err
	}

	if key.Key == nil {
		return nil, errors.New("failed to convert Key Vault key to raw key: key is nil")
	}

	return key.Key, nil
}
