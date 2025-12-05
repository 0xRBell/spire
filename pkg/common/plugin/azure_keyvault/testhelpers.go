package azure_keyvault

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"math/big"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
)

// ToRSAKey converts an RSA public key to an Azure JSONWebKey.
func ToRSAKey(publicKey crypto.PublicKey, keyID string, keyOperations []*string) *azkeys.JSONWebKey {
	rsaKey := publicKey.(*rsa.PublicKey)
	s := big.NewInt(int64(rsaKey.E))
	e := s.Bytes()
	return &azkeys.JSONWebKey{
		N:      rsaKey.N.Bytes(),
		E:      e,
		KID:    to.Ptr(azkeys.ID(keyID)),
		KeyOps: keyOperations,
		Kty:    to.Ptr(azkeys.JSONWebKeyTypeRSA),
	}
}

// ToECKey converts an ECDSA public key to an Azure JSONWebKey.
func ToECKey(publicKey crypto.PublicKey, keyID string, curveName azkeys.JSONWebKeyCurveName, keyOperations []*string) *azkeys.JSONWebKey {
	ecKey := publicKey.(*ecdsa.PublicKey)
	curveBits := ecKey.Curve.Params().BitSize
	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes++
	}

	xBytes := ecKey.X.Bytes()
	xPadded := make([]byte, keyBytes)
	copy(xPadded[keyBytes-len(xBytes):], xBytes)

	yBytes := ecKey.Y.Bytes()
	yPadded := make([]byte, keyBytes)
	copy(yPadded[keyBytes-len(yBytes):], yBytes)

	return &azkeys.JSONWebKey{
		Crv:    to.Ptr(curveName),
		X:      xPadded,
		Y:      yPadded,
		KID:    to.Ptr(azkeys.ID(keyID)),
		KeyOps: keyOperations,
		Kty:    to.Ptr(azkeys.JSONWebKeyTypeEC),
	}
}

// GetKeyOperations returns the standard key operations for sign/verify keys.
func GetKeyOperations() []*string {
	return []*string{
		to.Ptr("Sign"),
		to.Ptr("Verify"),
	}
}

// MakeKeyBundle creates a KeyBundle from a public key for testing.
func MakeKeyBundle(t *testing.T, publicKey crypto.PublicKey, keyType azkeys.JSONWebKeyType, curve *azkeys.JSONWebKeyCurveName) azkeys.KeyBundle {
	t.Helper()
	var key *azkeys.JSONWebKey
	keyOps := GetKeyOperations()

	switch k := publicKey.(type) {
	case *rsa.PublicKey:
		key = ToRSAKey(k, "https://vault.azure.net/keys/test-key/v1", keyOps)
	case *ecdsa.PublicKey:
		if curve == nil {
			t.Fatal("curve is required for ECDSA keys")
		}
		key = ToECKey(k, "https://vault.azure.net/keys/test-key/v1", *curve, keyOps)
	default:
		t.Fatalf("unsupported key type: %T", publicKey)
	}

	return azkeys.KeyBundle{
		Key: key,
		Attributes: &azkeys.KeyAttributes{
			Enabled: to.Ptr(true),
			Created: to.Ptr(time.Now()),
			Updated: to.Ptr(time.Now()),
		},
	}
}
