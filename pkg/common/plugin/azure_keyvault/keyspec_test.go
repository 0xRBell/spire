package azure_keyvault

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyTypeFromKeySpec(t *testing.T) {
	testKeys := new(testkey.Keys)
	rsa2048Key := testKeys.NewRSA2048(t)
	rsa4096Key := testKeys.NewRSA4096(t)
	ec256Key := testKeys.NewEC256(t)
	ec384Key := testKeys.NewEC384(t)

	tests := []struct {
		name       string
		keyBundle  azkeys.KeyBundle
		expectType KeyType
		expectOK   bool
	}{
		{
			name:       "RSA 2048",
			keyBundle:  MakeKeyBundle(t, rsa2048Key.Public(), azkeys.JSONWebKeyTypeRSA, nil),
			expectType: KeyTypeRSA2048,
			expectOK:   true,
		},
		{
			name:       "RSA 4096",
			keyBundle:  MakeKeyBundle(t, rsa4096Key.Public(), azkeys.JSONWebKeyTypeRSA, nil),
			expectType: KeyTypeRSA4096,
			expectOK:   true,
		},
		{
			name:       "EC P256",
			keyBundle:  MakeKeyBundle(t, ec256Key.Public(), azkeys.JSONWebKeyTypeEC, to.Ptr(azkeys.JSONWebKeyCurveNameP256)),
			expectType: KeyTypeECP256,
			expectOK:   true,
		},
		{
			name:       "EC P384",
			keyBundle:  MakeKeyBundle(t, ec384Key.Public(), azkeys.JSONWebKeyTypeEC, to.Ptr(azkeys.JSONWebKeyCurveNameP384)),
			expectType: KeyTypeECP384,
			expectOK:   true,
		},
		{
			name: "Unsupported key type - P521",
			keyBundle: azkeys.KeyBundle{
				Key: &azkeys.JSONWebKey{
					Kty: to.Ptr(azkeys.JSONWebKeyTypeEC),
					Crv: to.Ptr(azkeys.JSONWebKeyCurveNameP521),
				},
			},
			expectOK: false,
		},
		{
			name: "RSA with wrong size",
			keyBundle: azkeys.KeyBundle{
				Key: &azkeys.JSONWebKey{
					Kty: to.Ptr(azkeys.JSONWebKeyTypeRSA),
					N:   make([]byte, 128), // Wrong size
				},
			},
			expectOK: false,
		},
		{
			name: "Nil key",
			keyBundle: azkeys.KeyBundle{
				Key: nil,
			},
			expectOK: false,
		},
		{
			name: "Nil key type",
			keyBundle: azkeys.KeyBundle{
				Key: &azkeys.JSONWebKey{
					Kty: nil,
				},
			},
			expectOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyType, ok := KeyTypeFromKeySpec(tt.keyBundle)
			assert.Equal(t, tt.expectOK, ok)
			if tt.expectOK {
				assert.Equal(t, tt.expectType, keyType)
			} else {
				assert.Equal(t, KeyTypeUnspecified, keyType)
			}
		})
	}
}

func TestGetCreateKeyParameters(t *testing.T) {
	tests := []struct {
		name        string
		keyType     KeyType
		keyTags     map[string]*string
		expectError bool
		validate    func(t *testing.T, params *azkeys.CreateKeyParameters)
	}{
		{
			name:    "RSA 2048",
			keyType: KeyTypeRSA2048,
			keyTags: map[string]*string{
				"tag1": to.Ptr("value1"),
			},
			expectError: false,
			validate: func(t *testing.T, params *azkeys.CreateKeyParameters) {
				assert.Equal(t, azkeys.JSONWebKeyTypeRSA, *params.Kty)
				assert.Equal(t, int32(2048), *params.KeySize)
				assert.Nil(t, params.Curve)
			},
		},
		{
			name:    "RSA 4096",
			keyType: KeyTypeRSA4096,
			keyTags: map[string]*string{
				"tag1": to.Ptr("value1"),
			},
			expectError: false,
			validate: func(t *testing.T, params *azkeys.CreateKeyParameters) {
				assert.Equal(t, azkeys.JSONWebKeyTypeRSA, *params.Kty)
				assert.Equal(t, int32(4096), *params.KeySize)
				assert.Nil(t, params.Curve)
			},
		},
		{
			name:    "EC P256",
			keyType: KeyTypeECP256,
			keyTags: map[string]*string{
				"tag1": to.Ptr("value1"),
			},
			expectError: false,
			validate: func(t *testing.T, params *azkeys.CreateKeyParameters) {
				assert.Equal(t, azkeys.JSONWebKeyTypeEC, *params.Kty)
				assert.Equal(t, azkeys.JSONWebKeyCurveNameP256, *params.Curve)
				assert.Nil(t, params.KeySize)
			},
		},
		{
			name:    "EC P384",
			keyType: KeyTypeECP384,
			keyTags: map[string]*string{
				"tag1": to.Ptr("value1"),
			},
			expectError: false,
			validate: func(t *testing.T, params *azkeys.CreateKeyParameters) {
				assert.Equal(t, azkeys.JSONWebKeyTypeEC, *params.Kty)
				assert.Equal(t, azkeys.JSONWebKeyCurveNameP384, *params.Curve)
				assert.Nil(t, params.KeySize)
			},
		},
		{
			name:        "Unsupported key type",
			keyType:     KeyTypeUnspecified,
			keyTags:     nil,
			expectError: true,
		},
		{
			name:        "Key operations should include Sign and Verify",
			keyType:     KeyTypeRSA2048,
			keyTags:     nil,
			expectError: false,
			validate: func(t *testing.T, params *azkeys.CreateKeyParameters) {
				assert.Contains(t, params.KeyOps, to.Ptr(azkeys.JSONWebKeyOperationSign))
				assert.Contains(t, params.KeyOps, to.Ptr(azkeys.JSONWebKeyOperationVerify))
			},
		},
		{
			name:    "Tags should be set",
			keyType: KeyTypeRSA2048,
			keyTags: map[string]*string{
				"tag1": to.Ptr("value1"),
				"tag2": to.Ptr("value2"),
			},
			expectError: false,
			validate: func(t *testing.T, params *azkeys.CreateKeyParameters) {
				assert.Equal(t, "value1", *params.Tags["tag1"])
				assert.Equal(t, "value2", *params.Tags["tag2"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := GetCreateKeyParameters(tt.keyType, tt.keyTags)

			if tt.expectError {
				require.Error(t, err)
				assert.Nil(t, params)
				assert.Contains(t, err.Error(), "unsupported key type")
			} else {
				require.NoError(t, err)
				require.NotNil(t, params)
				if tt.validate != nil {
					tt.validate(t, params)
				}
			}
		})
	}
}

func TestSigningAlgorithm(t *testing.T) {
	tests := []struct {
		name        string
		keyType     KeyType
		hashAlgo    HashAlgorithm
		isPSS       bool
		expectAlgo  azkeys.JSONWebKeySignatureAlgorithm
		expectError bool
		errorMsg    string
	}{
		// ECDSA algorithms
		{
			name:        "ECDSA P256 with SHA256",
			keyType:     KeyTypeECP256,
			hashAlgo:    HashAlgorithmSHA256,
			isPSS:       false,
			expectAlgo:  azkeys.JSONWebKeySignatureAlgorithmES256,
			expectError: false,
		},
		{
			name:        "ECDSA P384 with SHA384",
			keyType:     KeyTypeECP384,
			hashAlgo:    HashAlgorithmSHA384,
			isPSS:       false,
			expectAlgo:  azkeys.JSONWebKeySignatureAlgorithmES384,
			expectError: false,
		},
		// RSA PKCS1v1.5 algorithms
		{
			name:        "RSA 2048 with SHA256",
			keyType:     KeyTypeRSA2048,
			hashAlgo:    HashAlgorithmSHA256,
			isPSS:       false,
			expectAlgo:  azkeys.JSONWebKeySignatureAlgorithmRS256,
			expectError: false,
		},
		{
			name:        "RSA 2048 with SHA384",
			keyType:     KeyTypeRSA2048,
			hashAlgo:    HashAlgorithmSHA384,
			isPSS:       false,
			expectAlgo:  azkeys.JSONWebKeySignatureAlgorithmRS384,
			expectError: false,
		},
		{
			name:        "RSA 2048 with SHA512",
			keyType:     KeyTypeRSA2048,
			hashAlgo:    HashAlgorithmSHA512,
			isPSS:       false,
			expectAlgo:  azkeys.JSONWebKeySignatureAlgorithmRS512,
			expectError: false,
		},
		{
			name:        "RSA 4096 with SHA256",
			keyType:     KeyTypeRSA4096,
			hashAlgo:    HashAlgorithmSHA256,
			isPSS:       false,
			expectAlgo:  azkeys.JSONWebKeySignatureAlgorithmRS256,
			expectError: false,
		},
		// RSA PSS algorithms
		{
			name:        "RSA 2048 PSS with SHA256",
			keyType:     KeyTypeRSA2048,
			hashAlgo:    HashAlgorithmSHA256,
			isPSS:       true,
			expectAlgo:  azkeys.JSONWebKeySignatureAlgorithmPS256,
			expectError: false,
		},
		{
			name:        "RSA 2048 PSS with SHA384",
			keyType:     KeyTypeRSA2048,
			hashAlgo:    HashAlgorithmSHA384,
			isPSS:       true,
			expectAlgo:  azkeys.JSONWebKeySignatureAlgorithmPS384,
			expectError: false,
		},
		{
			name:        "RSA 2048 PSS with SHA512",
			keyType:     KeyTypeRSA2048,
			hashAlgo:    HashAlgorithmSHA512,
			isPSS:       true,
			expectAlgo:  azkeys.JSONWebKeySignatureAlgorithmPS512,
			expectError: false,
		},
		// Error cases
		{
			name:        "Unspecified hash algorithm",
			keyType:     KeyTypeRSA2048,
			hashAlgo:    HashAlgorithmUnspecified,
			isPSS:       false,
			expectError: true,
			errorMsg:    "hash algorithm is required",
		},
		{
			name:        "ECDSA P256 with SHA384 (unsupported)",
			keyType:     KeyTypeECP256,
			hashAlgo:    HashAlgorithmSHA384,
			isPSS:       false,
			expectError: true,
			errorMsg:    "unsupported combination",
		},
		{
			name:        "ECDSA P384 with SHA256 (unsupported)",
			keyType:     KeyTypeECP384,
			hashAlgo:    HashAlgorithmSHA256,
			isPSS:       false,
			expectError: true,
			errorMsg:    "unsupported combination",
		},
		{
			name:        "ECDSA P256 with SHA512 (unsupported)",
			keyType:     KeyTypeECP256,
			hashAlgo:    HashAlgorithmSHA512,
			isPSS:       false,
			expectError: true,
			errorMsg:    "unsupported combination",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			algo, err := SigningAlgorithm(tt.keyType, tt.hashAlgo, tt.isPSS)

			if tt.expectError {
				require.Error(t, err)
				assert.Empty(t, algo)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectAlgo, algo)
			}
		})
	}
}

func TestKeyType_String(t *testing.T) {
	tests := []struct {
		keyType  KeyType
		expected string
	}{
		{KeyTypeUnspecified, "UNSPECIFIED"},
		{KeyTypeRSA2048, "RSA_2048"},
		{KeyTypeRSA4096, "RSA_4096"},
		{KeyTypeECP256, "EC_P256"},
		{KeyTypeECP384, "EC_P384"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.keyType.String())
		})
	}
}

func TestKeyType_IsRSA(t *testing.T) {
	assert.True(t, KeyTypeRSA2048.IsRSA())
	assert.True(t, KeyTypeRSA4096.IsRSA())
	assert.False(t, KeyTypeECP256.IsRSA())
	assert.False(t, KeyTypeECP384.IsRSA())
	assert.False(t, KeyTypeUnspecified.IsRSA())
}

func TestKeyType_IsEC(t *testing.T) {
	assert.False(t, KeyTypeRSA2048.IsEC())
	assert.False(t, KeyTypeRSA4096.IsEC())
	assert.True(t, KeyTypeECP256.IsEC())
	assert.True(t, KeyTypeECP384.IsEC())
	assert.False(t, KeyTypeUnspecified.IsEC())
}

func TestHashAlgorithm_String(t *testing.T) {
	tests := []struct {
		hashAlgo HashAlgorithm
		expected string
	}{
		{HashAlgorithmUnspecified, "UNSPECIFIED"},
		{HashAlgorithmSHA256, "SHA256"},
		{HashAlgorithmSHA384, "SHA384"},
		{HashAlgorithmSHA512, "SHA512"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.hashAlgo.String())
		})
	}
}
