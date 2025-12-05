package azure_keyvault

import (
	"errors"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// SignatureToASN1 converts the signature format from IEEE P1363 to ASN.1/DER
// for ECDSA signed messages. If the key type is RSA, the signature is returned
// unchanged as RSA signatures are already in the correct format.
//
// Azure Key Vault's Sign API produces IEEE P1363 format for ECDSA signatures,
// while SPIRE expects RFC3279 ASN.1 DER format for signature verification
// (ecdsa.VerifyASN1).
func SignatureToASN1(sigResult []byte, keyType KeyType) ([]byte, error) {
	if keyType.IsRSA() {
		// No conversion needed for RSA, it's already in the correct format
		return sigResult, nil
	}

	sigLength := len(sigResult)
	// The signature byte array length must either be 64 (EC P256) or 96 (EC P384)
	if sigLength != 64 && sigLength != 96 {
		return nil, errors.New("malformed signature response")
	}

	// Split the IEEE P1363 signature into r and s values
	rVal := new(big.Int)
	rVal.SetBytes(sigResult[0 : sigLength/2])
	sVal := new(big.Int)
	sVal.SetBytes(sigResult[sigLength/2 : sigLength])

	// Build ASN.1 DER encoded signature
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(rVal)
		b.AddASN1BigInt(sVal)
	})

	return b.Bytes()
}
