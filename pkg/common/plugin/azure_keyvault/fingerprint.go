package azure_keyvault

import (
	"crypto/sha256"
	"encoding/hex"
)

// MakeFingerprint creates a SHA256 fingerprint of PKIX public key data.
// The fingerprint is returned as a lowercase hex-encoded string.
func MakeFingerprint(pkixData []byte) string {
	s := sha256.Sum256(pkixData)
	return hex.EncodeToString(s[:])
}
