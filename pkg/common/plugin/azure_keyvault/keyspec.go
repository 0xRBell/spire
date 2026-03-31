package azure_keyvault

import (
	"errors"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
)

// KeyType represents SPIRE key types in a proto-agnostic way.
// Both server and agent plugins can convert their proto KeyType
// to this shared type for use with utility functions.
type KeyType int

const (
	KeyTypeUnspecified KeyType = iota
	KeyTypeRSA2048
	KeyTypeRSA4096
	KeyTypeECP256
	KeyTypeECP384
)

// String returns the string representation of the KeyType.
func (kt KeyType) String() string {
	switch kt {
	case KeyTypeRSA2048:
		return "RSA_2048"
	case KeyTypeRSA4096:
		return "RSA_4096"
	case KeyTypeECP256:
		return "EC_P256"
	case KeyTypeECP384:
		return "EC_P384"
	default:
		return "UNSPECIFIED"
	}
}

// IsRSA returns true if the key type is RSA.
func (kt KeyType) IsRSA() bool {
	return kt == KeyTypeRSA2048 || kt == KeyTypeRSA4096
}

// IsEC returns true if the key type is elliptic curve.
func (kt KeyType) IsEC() bool {
	return kt == KeyTypeECP256 || kt == KeyTypeECP384
}

// HashAlgorithm represents hash algorithms in a proto-agnostic way.
type HashAlgorithm int

const (
	HashAlgorithmUnspecified HashAlgorithm = iota
	HashAlgorithmSHA256
	HashAlgorithmSHA384
	HashAlgorithmSHA512
)

// String returns the string representation of the HashAlgorithm.
func (ha HashAlgorithm) String() string {
	switch ha {
	case HashAlgorithmSHA256:
		return "SHA256"
	case HashAlgorithmSHA384:
		return "SHA384"
	case HashAlgorithmSHA512:
		return "SHA512"
	default:
		return "UNSPECIFIED"
	}
}

// KeyTypeFromKeySpec determines the key type from an Azure KeyBundle.
// Returns the KeyType and true if successful, or KeyTypeUnspecified and false
// if the key type is not supported.
func KeyTypeFromKeySpec(keyBundle azkeys.KeyBundle) (KeyType, bool) {
	if keyBundle.Key == nil || keyBundle.Key.Kty == nil {
		return KeyTypeUnspecified, false
	}

	switch {
	case *keyBundle.Key.Kty == azkeys.JSONWebKeyTypeRSA && len(keyBundle.Key.N) == 256:
		return KeyTypeRSA2048, true
	case *keyBundle.Key.Kty == azkeys.JSONWebKeyTypeRSA && len(keyBundle.Key.N) == 512:
		return KeyTypeRSA4096, true
	case *keyBundle.Key.Kty == azkeys.JSONWebKeyTypeEC && keyBundle.Key.Crv != nil && *keyBundle.Key.Crv == azkeys.JSONWebKeyCurveNameP256:
		return KeyTypeECP256, true
	case *keyBundle.Key.Kty == azkeys.JSONWebKeyTypeEC && keyBundle.Key.Crv != nil && *keyBundle.Key.Crv == azkeys.JSONWebKeyCurveNameP384:
		return KeyTypeECP384, true
	default:
		return KeyTypeUnspecified, false
	}
}

// GetCreateKeyParameters builds Azure CreateKeyParameters from KeyType.
// The keyTags parameter allows setting custom tags on the created key.
func GetCreateKeyParameters(keyType KeyType, keyTags map[string]*string) (*azkeys.CreateKeyParameters, error) {
	result := &azkeys.CreateKeyParameters{}

	switch keyType {
	case KeyTypeRSA2048:
		result.Kty = to.Ptr(azkeys.JSONWebKeyTypeRSA)
		result.KeySize = to.Ptr(int32(2048))
	case KeyTypeRSA4096:
		result.Kty = to.Ptr(azkeys.JSONWebKeyTypeRSA)
		result.KeySize = to.Ptr(int32(4096))
	case KeyTypeECP256:
		result.Kty = to.Ptr(azkeys.JSONWebKeyTypeEC)
		result.Curve = to.Ptr(azkeys.JSONWebKeyCurveNameP256)
	case KeyTypeECP384:
		result.Kty = to.Ptr(azkeys.JSONWebKeyTypeEC)
		result.Curve = to.Ptr(azkeys.JSONWebKeyCurveNameP384)
	default:
		return nil, fmt.Errorf("unsupported key type: %v", keyType)
	}

	// Specify the key operations as Sign and Verify
	result.KeyOps = append(result.KeyOps, to.Ptr(azkeys.JSONWebKeyOperationSign), to.Ptr(azkeys.JSONWebKeyOperationVerify))
	// Set the key tags
	result.Tags = keyTags

	return result, nil
}

// SigningAlgorithm returns the Azure signing algorithm for a key type,
// hash algorithm, and whether PSS padding is used (for RSA keys).
func SigningAlgorithm(keyType KeyType, hashAlgo HashAlgorithm, isPSS bool) (azkeys.JSONWebKeySignatureAlgorithm, error) {
	if hashAlgo == HashAlgorithmUnspecified {
		return "", errors.New("hash algorithm is required")
	}

	switch {
	case keyType == KeyTypeECP256 && hashAlgo == HashAlgorithmSHA256:
		return azkeys.JSONWebKeySignatureAlgorithmES256, nil
	case keyType == KeyTypeECP384 && hashAlgo == HashAlgorithmSHA384:
		return azkeys.JSONWebKeySignatureAlgorithmES384, nil
	case keyType.IsRSA() && !isPSS && hashAlgo == HashAlgorithmSHA256:
		return azkeys.JSONWebKeySignatureAlgorithmRS256, nil
	case keyType.IsRSA() && !isPSS && hashAlgo == HashAlgorithmSHA384:
		return azkeys.JSONWebKeySignatureAlgorithmRS384, nil
	case keyType.IsRSA() && !isPSS && hashAlgo == HashAlgorithmSHA512:
		return azkeys.JSONWebKeySignatureAlgorithmRS512, nil
	case keyType.IsRSA() && isPSS && hashAlgo == HashAlgorithmSHA256:
		return azkeys.JSONWebKeySignatureAlgorithmPS256, nil
	case keyType.IsRSA() && isPSS && hashAlgo == HashAlgorithmSHA384:
		return azkeys.JSONWebKeySignatureAlgorithmPS384, nil
	case keyType.IsRSA() && isPSS && hashAlgo == HashAlgorithmSHA512:
		return azkeys.JSONWebKeySignatureAlgorithmPS512, nil
	default:
		return "", fmt.Errorf("unsupported combination of key type: %v and hashing algorithm: %v", keyType, hashAlgo)
	}
}
