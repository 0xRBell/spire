package azure_keyvault

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWKToRawKey(t *testing.T) {
	testKeys := new(testkey.Keys)

	tests := []struct {
		name        string
		setupKey    func() *azkeys.JSONWebKey
		expectError bool
		keyType     string
	}{
		{
			name: "Valid RSA key",
			setupKey: func() *azkeys.JSONWebKey {
				rsaKey := testKeys.NewRSA2048(t)
				return ToRSAKey(rsaKey.Public(), "test-key-id", GetKeyOperations())
			},
			expectError: false,
			keyType:     "RSA",
		},
		{
			name: "Valid ECDSA P256 key",
			setupKey: func() *azkeys.JSONWebKey {
				ecKey := testKeys.NewEC256(t)
				return ToECKey(ecKey.Public(), "test-key-id", azkeys.JSONWebKeyCurveNameP256, GetKeyOperations())
			},
			expectError: false,
			keyType:     "ECDSA",
		},
		{
			name: "Valid ECDSA P384 key",
			setupKey: func() *azkeys.JSONWebKey {
				ecKey := testKeys.NewEC384(t)
				return ToECKey(ecKey.Public(), "test-key-id", azkeys.JSONWebKeyCurveNameP384, GetKeyOperations())
			},
			expectError: false,
			keyType:     "ECDSA",
		},
		{
			name: "Nil key",
			setupKey: func() *azkeys.JSONWebKey {
				return nil
			},
			expectError: true,
			keyType:     "",
		},
		{
			name: "Invalid key - missing required fields",
			setupKey: func() *azkeys.JSONWebKey {
				return &azkeys.JSONWebKey{
					Kty: to.Ptr(azkeys.JSONWebKeyTypeRSA),
					KID: to.Ptr(azkeys.ID("test-key-id")),
					// Missing N and E for RSA key
				}
			},
			expectError: true,
			keyType:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyVaultKey := tt.setupKey()
			rawKey, err := JWKToRawKey(keyVaultKey)

			if tt.expectError {
				require.Error(t, err)
				assert.Nil(t, rawKey)
			} else {
				require.NoError(t, err)
				require.NotNil(t, rawKey)

				// Verify the key type
				switch tt.keyType {
				case "RSA":
					_, ok := rawKey.(*rsa.PublicKey)
					assert.True(t, ok, "Expected RSA public key")
				case "ECDSA":
					_, ok := rawKey.(*ecdsa.PublicKey)
					assert.True(t, ok, "Expected ECDSA public key")
				}
			}
		})
	}
}
