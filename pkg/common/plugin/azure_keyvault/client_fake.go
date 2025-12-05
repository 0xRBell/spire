package azure_keyvault

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"path"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/andres-erbsen/clock"
	"github.com/spiffe/spire/test/testkey"
)

// FakeKeyEntry represents a key stored in the fake Key Vault.
type FakeKeyEntry struct {
	KeyBundle  azkeys.KeyBundle
	PrivateKey crypto.Signer
}

// FakeKeyStore provides in-memory key storage for tests.
type FakeKeyStore struct {
	Keys       map[string]*FakeKeyEntry
	EC256Key   crypto.Signer
	EC384Key   crypto.Signer
	RSA2048Key crypto.Signer
	RSA4096Key crypto.Signer
	Clock      clock.Clock
	mu         sync.RWMutex
}

// NewFakeKeyStore creates a new FakeKeyStore with pre-generated test keys.
func NewFakeKeyStore(t *testing.T, clk clock.Clock) *FakeKeyStore {
	testKeys := new(testkey.Keys)
	return &FakeKeyStore{
		Keys:       make(map[string]*FakeKeyEntry),
		Clock:      clk,
		EC256Key:   testKeys.NewEC256(t),
		EC384Key:   testKeys.NewEC384(t),
		RSA2048Key: testKeys.NewRSA2048(t),
		RSA4096Key: testKeys.NewRSA4096(t),
	}
}

// SaveKeyEntry saves a key entry to the store.
func (fs *FakeKeyStore) SaveKeyEntry(entry *FakeKeyEntry) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.Keys[entry.KeyBundle.Key.KID.Name()] = entry
}

// DeleteKeyEntry removes a key entry from the store.
func (fs *FakeKeyStore) DeleteKeyEntry(keyName string) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	delete(fs.Keys, keyName)
}

// FetchKeyEntry retrieves a key entry by name.
func (fs *FakeKeyStore) FetchKeyEntry(keyName string) (*FakeKeyEntry, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	entry, ok := fs.Keys[keyName]
	if !ok {
		return nil, fmt.Errorf("no such key %q", keyName)
	}
	return entry, nil
}

// FetchAllKeyEntries returns all key entries in the store.
func (fs *FakeKeyStore) FetchAllKeyEntries() []*FakeKeyEntry {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	entries := make([]*FakeKeyEntry, 0, len(fs.Keys))
	for _, v := range fs.Keys {
		entries = append(entries, v)
	}
	return entries
}

// FakeKeyVaultClient implements CloudKeyManagementService for testing.
type FakeKeyVaultClient struct {
	Store        *FakeKeyStore
	VaultURI     string
	Tags         map[string]*string // Default tags to apply to created keys
	CreateKeyErr error
	DeleteKeyErr error
	UpdateKeyErr error
	GetKeyErr    error
	ListKeysErr  error
	SignErr      error
	mu           sync.RWMutex
}

// NewFakeKeyVaultClient creates a new fake Key Vault client for testing.
func NewFakeKeyVaultClient(t *testing.T, vaultURI string, tags map[string]*string, clk clock.Clock) *FakeKeyVaultClient {
	return &FakeKeyVaultClient{
		Store:    NewFakeKeyStore(t, clk),
		VaultURI: vaultURI,
		Tags:     tags,
	}
}

// SetCreateKeyErr sets an error to be returned by CreateKey.
func (c *FakeKeyVaultClient) SetCreateKeyErr(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.CreateKeyErr = err
}

// SetDeleteKeyErr sets an error to be returned by DeleteKey.
func (c *FakeKeyVaultClient) SetDeleteKeyErr(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.DeleteKeyErr = err
}

// SetUpdateKeyErr sets an error to be returned by UpdateKey.
func (c *FakeKeyVaultClient) SetUpdateKeyErr(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.UpdateKeyErr = err
}

// SetGetKeyErr sets an error to be returned by GetKey.
func (c *FakeKeyVaultClient) SetGetKeyErr(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.GetKeyErr = err
}

// SetListKeysErr sets an error to be returned by NewListKeysPager.
func (c *FakeKeyVaultClient) SetListKeysErr(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ListKeysErr = err
}

// SetSignErr sets an error to be returned by Sign.
func (c *FakeKeyVaultClient) SetSignErr(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.SignErr = err
}

// SetEntries populates the fake store with pre-existing key entries.
func (c *FakeKeyVaultClient) SetEntries(entries []FakeKeyEntry) {
	for _, e := range entries {
		if e.KeyBundle.Key != nil && e.KeyBundle.Key.KID != nil && e.KeyBundle.Key.KID.Name() != "" {
			newEntry := e
			c.Store.SaveKeyEntry(&newEntry)
		}
	}
}

func (c *FakeKeyVaultClient) CreateKey(_ context.Context, keyName string, parameters azkeys.CreateKeyParameters, _ *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.CreateKeyErr != nil {
		return azkeys.CreateKeyResponse{}, c.CreateKeyErr
	}

	var publicKey *azkeys.JSONWebKey
	var privateKey crypto.Signer
	keyOperations := GetKeyOperations()
	kmsKeyID := path.Join(c.VaultURI, keyName)

	switch {
	case *parameters.Kty == azkeys.JSONWebKeyTypeEC && *parameters.Curve == azkeys.JSONWebKeyCurveNameP256:
		privateKey = c.Store.EC256Key
		publicKey = ToECKey(privateKey.Public(), kmsKeyID, *parameters.Curve, keyOperations)
	case *parameters.Kty == azkeys.JSONWebKeyTypeEC && *parameters.Curve == azkeys.JSONWebKeyCurveNameP384:
		privateKey = c.Store.EC384Key
		publicKey = ToECKey(privateKey.Public(), kmsKeyID, *parameters.Curve, keyOperations)
	case *parameters.Kty == azkeys.JSONWebKeyTypeRSA && *parameters.KeySize == 2048:
		privateKey = c.Store.RSA2048Key
		publicKey = ToRSAKey(privateKey.Public(), kmsKeyID, keyOperations)
	case *parameters.Kty == azkeys.JSONWebKeyTypeRSA && *parameters.KeySize == 4096:
		privateKey = c.Store.RSA4096Key
		publicKey = ToRSAKey(privateKey.Public(), kmsKeyID, keyOperations)
	default:
		return azkeys.CreateKeyResponse{}, fmt.Errorf("unknown key type %q", *parameters.Kty)
	}

	now := time.Now()
	if c.Store.Clock != nil {
		now = c.Store.Clock.Now()
	}

	tags := make(map[string]*string)
	for k, v := range c.Tags {
		tags[k] = v
	}
	// Also include any tags from the parameters
	for k, v := range parameters.Tags {
		tags[k] = v
	}

	keyBundle := &azkeys.KeyBundle{
		Attributes: &azkeys.KeyAttributes{
			Enabled: to.Ptr(true),
			Created: to.Ptr(now),
			Updated: to.Ptr(now),
		},
		Key:  publicKey,
		Tags: tags,
	}

	entry := &FakeKeyEntry{
		KeyBundle:  *keyBundle,
		PrivateKey: privateKey,
	}

	c.Store.SaveKeyEntry(entry)
	return azkeys.CreateKeyResponse{KeyBundle: *keyBundle}, nil
}

func (c *FakeKeyVaultClient) DeleteKey(_ context.Context, name string, _ *azkeys.DeleteKeyOptions) (azkeys.DeleteKeyResponse, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.DeleteKeyErr != nil {
		return azkeys.DeleteKeyResponse{}, c.DeleteKeyErr
	}

	entry, err := c.Store.FetchKeyEntry(name)
	if err != nil {
		return azkeys.DeleteKeyResponse{}, err
	}

	c.Store.DeleteKeyEntry(name)

	return azkeys.DeleteKeyResponse{
		DeletedKeyBundle: azkeys.DeletedKeyBundle{
			Attributes: entry.KeyBundle.Attributes,
			Key:        entry.KeyBundle.Key,
		},
	}, nil
}

func (c *FakeKeyVaultClient) UpdateKey(_ context.Context, name, _ string, _ azkeys.UpdateKeyParameters, _ *azkeys.UpdateKeyOptions) (azkeys.UpdateKeyResponse, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.UpdateKeyErr != nil {
		return azkeys.UpdateKeyResponse{}, c.UpdateKeyErr
	}

	entry, err := c.Store.FetchKeyEntry(name)
	if err != nil {
		return azkeys.UpdateKeyResponse{}, err
	}

	now := time.Now()
	if c.Store.Clock != nil {
		now = c.Store.Clock.Now()
	}

	entry.KeyBundle.Attributes.Updated = to.Ptr(now)
	c.Store.SaveKeyEntry(entry)

	return azkeys.UpdateKeyResponse{
		KeyBundle: azkeys.KeyBundle{
			Attributes: entry.KeyBundle.Attributes,
			Key:        entry.KeyBundle.Key,
			Tags:       entry.KeyBundle.Tags,
		},
	}, nil
}

func (c *FakeKeyVaultClient) GetKey(_ context.Context, keyName, _ string, _ *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.GetKeyErr != nil {
		return azkeys.GetKeyResponse{}, c.GetKeyErr
	}

	entry, err := c.Store.FetchKeyEntry(keyName)
	if err != nil {
		return azkeys.GetKeyResponse{}, err
	}

	return azkeys.GetKeyResponse{
		KeyBundle: azkeys.KeyBundle{
			Attributes: entry.KeyBundle.Attributes,
			Key:        entry.KeyBundle.Key,
			Tags:       entry.KeyBundle.Tags,
		},
	}, nil
}

func (c *FakeKeyVaultClient) NewListKeysPager(_ *azkeys.ListKeysOptions) *runtime.Pager[azkeys.ListKeysResponse] {
	return runtime.NewPager(runtime.PagingHandler[azkeys.ListKeysResponse]{
		More: func(page azkeys.ListKeysResponse) bool {
			return page.NextLink != nil && len(*page.NextLink) > 0
		},
		Fetcher: func(ctx context.Context, page *azkeys.ListKeysResponse) (azkeys.ListKeysResponse, error) {
			c.mu.RLock()
			defer c.mu.RUnlock()

			if c.ListKeysErr != nil {
				return azkeys.ListKeysResponse{}, c.ListKeysErr
			}

			var items []*azkeys.KeyItem
			for _, entry := range c.Store.FetchAllKeyEntries() {
				items = append(items, &azkeys.KeyItem{
					Attributes: entry.KeyBundle.Attributes,
					KID:        entry.KeyBundle.Key.KID,
					Tags:       entry.KeyBundle.Tags,
				})
			}

			return azkeys.ListKeysResponse{
				KeyListResult: azkeys.KeyListResult{
					NextLink: nil,
					Value:    items,
				},
			}, nil
		},
	})
}

func (c *FakeKeyVaultClient) Sign(_ context.Context, keyName, _ string, parameters azkeys.SignParameters, _ *azkeys.SignOptions) (azkeys.SignResponse, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.SignErr != nil {
		return azkeys.SignResponse{}, c.SignErr
	}

	entry, err := c.Store.FetchKeyEntry(keyName)
	if err != nil {
		return azkeys.SignResponse{}, err
	}

	privateKey := entry.PrivateKey

	signRSA := func(opts crypto.SignerOpts) ([]byte, error) {
		rsaKey, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid signing algorithm %q for RSA key", *parameters.Algorithm)
		}
		return rsaKey.Sign(rand.Reader, parameters.Value, opts)
	}

	signECDSA := func() ([]byte, error) {
		ecKey, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid signing algorithm %q for ECDSA key", *parameters.Algorithm)
		}

		// Produce an IEEE-P1363 encoded signature (what Azure returns)
		curveBits := ecKey.Curve.Params().BitSize
		keyBytes := curveBits / 8
		if curveBits%8 > 0 {
			keyBytes++
		}

		r, s, err := ecdsa.Sign(rand.Reader, ecKey, parameters.Value)
		if err != nil {
			return nil, fmt.Errorf("failed to sign data using ecdsa: %w", err)
		}

		rBytes := r.Bytes()
		rBytesPadded := make([]byte, keyBytes)
		copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

		sBytes := s.Bytes()
		sBytesPadded := make([]byte, keyBytes)
		copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

		return append(rBytesPadded, sBytesPadded...), nil
	}

	var signature []byte
	switch *parameters.Algorithm {
	case azkeys.JSONWebKeySignatureAlgorithmPS256:
		signature, err = signRSA(&rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: rsa.PSSSaltLengthEqualsHash})
	case azkeys.JSONWebKeySignatureAlgorithmPS384:
		signature, err = signRSA(&rsa.PSSOptions{Hash: crypto.SHA384, SaltLength: rsa.PSSSaltLengthEqualsHash})
	case azkeys.JSONWebKeySignatureAlgorithmPS512:
		signature, err = signRSA(&rsa.PSSOptions{Hash: crypto.SHA512, SaltLength: rsa.PSSSaltLengthEqualsHash})
	case azkeys.JSONWebKeySignatureAlgorithmRS256:
		signature, err = signRSA(crypto.SHA256)
	case azkeys.JSONWebKeySignatureAlgorithmRS384:
		signature, err = signRSA(crypto.SHA384)
	case azkeys.JSONWebKeySignatureAlgorithmRS512:
		signature, err = signRSA(crypto.SHA512)
	case azkeys.JSONWebKeySignatureAlgorithmES256:
		signature, err = signECDSA()
	case azkeys.JSONWebKeySignatureAlgorithmES384:
		signature, err = signECDSA()
	case azkeys.JSONWebKeySignatureAlgorithmES512:
		signature, err = signECDSA()
	default:
		return azkeys.SignResponse{}, fmt.Errorf("unsupported signing algorithm: %s", *parameters.Algorithm)
	}

	if err != nil {
		return azkeys.SignResponse{}, fmt.Errorf("unable to sign digest: %v", err)
	}

	return azkeys.SignResponse{
		KeyOperationResult: azkeys.KeyOperationResult{
			Result: signature,
		},
	}, nil
}
