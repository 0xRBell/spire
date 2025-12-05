package azure_keyvault

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignatureToASN1(t *testing.T) {
	tests := []struct {
		name          string
		signature     []byte
		keyType       KeyType
		expectError   bool
		expectChanged bool // Whether the signature should be different from input
	}{
		{
			name:          "RSA 2048 - should return unchanged",
			signature:     []byte{1, 2, 3, 4, 5},
			keyType:       KeyTypeRSA2048,
			expectError:   false,
			expectChanged: false,
		},
		{
			name:          "RSA 4096 - should return unchanged",
			signature:     []byte{1, 2, 3, 4, 5, 6, 7, 8},
			keyType:       KeyTypeRSA4096,
			expectError:   false,
			expectChanged: false,
		},
		{
			name:          "ECDSA P256 - 64 bytes should convert",
			signature:     make([]byte, 64),
			keyType:       KeyTypeECP256,
			expectError:   false,
			expectChanged: true,
		},
		{
			name:          "ECDSA P384 - 96 bytes should convert",
			signature:     make([]byte, 96),
			keyType:       KeyTypeECP384,
			expectError:   false,
			expectChanged: true,
		},
		{
			name:        "ECDSA P256 - wrong length (32 bytes)",
			signature:   make([]byte, 32),
			keyType:     KeyTypeECP256,
			expectError: true,
		},
		{
			name:        "ECDSA P256 - wrong length (128 bytes)",
			signature:   make([]byte, 128),
			keyType:     KeyTypeECP256,
			expectError: true,
		},
		{
			name:          "ECDSA P384 - accepts 64 bytes (function accepts 64 or 96)",
			signature:     make([]byte, 64),
			keyType:       KeyTypeECP384,
			expectError:   false,
			expectChanged: true,
		},
		{
			name:        "ECDSA P256 - empty signature",
			signature:   []byte{},
			keyType:     KeyTypeECP256,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fill signature with test data for ECDSA cases
			if len(tt.signature) > 0 && tt.keyType.IsEC() {
				for i := range tt.signature {
					tt.signature[i] = byte(i % 256)
				}
			}

			result, err := SignatureToASN1(tt.signature, tt.keyType)

			if tt.expectError {
				require.Error(t, err)
				assert.Nil(t, result)
				assert.Contains(t, err.Error(), "malformed signature response")
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)

				if tt.expectChanged {
					// For ECDSA, the result should be ASN.1 encoded and different from input
					assert.NotEqual(t, tt.signature, result)
					// Verify it's valid ASN.1 SEQUENCE (starts with 0x30)
					assert.GreaterOrEqual(t, len(result), 2)
					assert.Equal(t, byte(0x30), result[0])
				} else {
					// For RSA, should be unchanged
					assert.Equal(t, tt.signature, result)
				}
			}
		})
	}
}

func TestSignatureToASN1_ECDSA_ValidConversion(t *testing.T) {
	// Test with actual ECDSA signature values to verify correct conversion
	// Create a 64-byte signature (P256): r (32 bytes) + s (32 bytes)
	rVal := big.NewInt(123456789)
	sVal := big.NewInt(987654321)

	rBytes := rVal.Bytes()
	sBytes := sVal.Bytes()

	// Pad to 32 bytes each for P256
	rPadded := make([]byte, 32)
	sPadded := make([]byte, 32)
	copy(rPadded[32-len(rBytes):], rBytes)
	copy(sPadded[32-len(sBytes):], sBytes)

	ieeeP1363Sig := append(rPadded, sPadded...)
	assert.Len(t, ieeeP1363Sig, 64)

	result, err := SignatureToASN1(ieeeP1363Sig, KeyTypeECP256)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify it's ASN.1 encoded
	assert.GreaterOrEqual(t, len(result), 2)
	assert.Equal(t, byte(0x30), result[0]) // SEQUENCE tag
}
