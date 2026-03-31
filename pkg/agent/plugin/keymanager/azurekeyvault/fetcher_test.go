package azurekeyvault

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/hashicorp/go-hclog"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/keymanager/v1"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	testAgentID     = "test-agent-123"
	testTrustDomain = "test.example.org"
)

func TestSpireKeyIDFromKeyName(t *testing.T) {
	tests := []struct {
		name        string
		keyName     string
		agentID     string
		expectID    string
		expectOK    bool
	}{
		{
			name:     "Valid key name",
			keyName:  "spire-agent-key-test-agent-123-agent-svid-A",
			agentID:  "test-agent-123",
			expectID: "agent-svid-A",
			expectOK: true,
		},
		{
			name:     "Valid key name with different agent ID",
			keyName:  "spire-agent-key-other-agent-456-agent-svid-B",
			agentID:  "other-agent-456",
			expectID: "agent-svid-B",
			expectOK: true,
		},
		{
			name:     "Missing prefix",
			keyName:  "some-other-key-test-agent-123-agent-svid-A",
			agentID:  "test-agent-123",
			expectOK: false,
		},
		{
			name:     "Wrong agent ID",
			keyName:  "spire-agent-key-wrong-agent-789-agent-svid-A",
			agentID:  "test-agent-123",
			expectOK: false,
		},
		{
			name:     "Empty SPIRE Key ID",
			keyName:  "spire-agent-key-test-agent-123-",
			agentID:  "test-agent-123",
			expectOK: false,
		},
		{
			name:     "Key name without agent ID separator",
			keyName:  "spire-agent-key-test-agent-123",
			agentID:  "test-agent-123",
			expectOK: false,
		},
		{
			name:     "Empty key name",
			keyName:  "",
			agentID:  "test-agent-123",
			expectOK: false,
		},
		{
			name:     "Only prefix",
			keyName:  "spire-agent-key-",
			agentID:  "test-agent-123",
			expectOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spireKeyID, ok := spireKeyIDFromKeyName(tt.keyName, tt.agentID)
			assert.Equal(t, tt.expectOK, ok)
			if tt.expectOK {
				assert.Equal(t, tt.expectID, spireKeyID)
			} else {
				assert.Empty(t, spireKeyID)
			}
		})
	}
}

func TestKeyBelongsToAgent(t *testing.T) {
	kf := &keyFetcher{
		agentID:     testAgentID,
		trustDomain: testTrustDomain,
	}

	tests := []struct {
		name        string
		key         *azkeys.KeyItem
		expectMatch bool
	}{
		{
			name: "Matching trust domain and agent ID",
			key: &azkeys.KeyItem{
				Tags: map[string]*string{
					tagNameAgentTrustDomain: to.Ptr(testTrustDomain),
					tagNameAgentID:          to.Ptr(testAgentID),
				},
			},
			expectMatch: true,
		},
		{
			name: "Missing trust domain tag",
			key: &azkeys.KeyItem{
				Tags: map[string]*string{
					tagNameAgentID: to.Ptr(testAgentID),
				},
			},
			expectMatch: false,
		},
		{
			name: "Missing agent ID tag",
			key: &azkeys.KeyItem{
				Tags: map[string]*string{
					tagNameAgentTrustDomain: to.Ptr(testTrustDomain),
				},
			},
			expectMatch: false,
		},
		{
			name: "Wrong trust domain",
			key: &azkeys.KeyItem{
				Tags: map[string]*string{
					tagNameAgentTrustDomain: to.Ptr("wrong.example.org"),
					tagNameAgentID:          to.Ptr(testAgentID),
				},
			},
			expectMatch: false,
		},
		{
			name: "Wrong agent ID",
			key: &azkeys.KeyItem{
				Tags: map[string]*string{
					tagNameAgentTrustDomain: to.Ptr(testTrustDomain),
					tagNameAgentID:          to.Ptr("wrong-agent"),
				},
			},
			expectMatch: false,
		},
		{
			name: "Empty tags",
			key: &azkeys.KeyItem{
				Tags: map[string]*string{},
			},
			expectMatch: false,
		},
		{
			name: "Nil tags",
			key: &azkeys.KeyItem{
				Tags: nil,
			},
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := kf.keyBelongsToAgent(tt.key)
			assert.Equal(t, tt.expectMatch, result)
		})
	}
}

func TestFetchKeyEntryDetails(t *testing.T) {
	testKeys := new(testkey.Keys)
	rsa2048Key := testKeys.NewRSA2048(t)
	ec256Key := testKeys.NewEC256(t)

	tests := []struct {
		name        string
		keyItem     *azkeys.KeyItem
		spireKeyID  string
		setupMock   func(*mockKeyVaultClient)
		expectError bool
		errorCode   codes.Code
		validate    func(t *testing.T, entry *keyEntry)
	}{
		{
			name: "Success with RSA 2048",
			keyItem: &azkeys.KeyItem{
				KID: to.Ptr(azkeys.ID("https://vault.azure.net/keys/test-key/v1")),
			},
			spireKeyID: "agent-svid-A",
			setupMock: func(m *mockKeyVaultClient) {
				m.getKeyResponse = &azkeys.GetKeyResponse{
					KeyBundle: makeKeyBundle(t, rsa2048Key.Public(), azkeys.JSONWebKeyTypeRSA, nil, to.Ptr(int32(2048))),
				}
				m.getKeyResponse.KeyBundle.Key.KID = to.Ptr(azkeys.ID("https://vault.azure.net/keys/test-key/v1"))
			},
			expectError: false,
			validate: func(t *testing.T, entry *keyEntry) {
				assert.Equal(t, "agent-svid-A", entry.PublicKey.Id)
				assert.Equal(t, keymanagerv1.KeyType_RSA_2048, entry.PublicKey.Type)
				assert.NotEmpty(t, entry.PublicKey.PkixData)
				assert.NotEmpty(t, entry.PublicKey.Fingerprint)
			},
		},
		{
			name: "Success with EC P256",
			keyItem: &azkeys.KeyItem{
				KID: to.Ptr(azkeys.ID("https://vault.azure.net/keys/test-key/v1")),
			},
			spireKeyID: "agent-svid-B",
			setupMock: func(m *mockKeyVaultClient) {
				m.getKeyResponse = &azkeys.GetKeyResponse{
					KeyBundle: makeKeyBundle(t, ec256Key.Public(), azkeys.JSONWebKeyTypeEC, to.Ptr(azkeys.JSONWebKeyCurveNameP256), nil),
				}
				m.getKeyResponse.KeyBundle.Key.KID = to.Ptr(azkeys.ID("https://vault.azure.net/keys/test-key/v1"))
			},
			expectError: false,
			validate: func(t *testing.T, entry *keyEntry) {
				assert.Equal(t, "agent-svid-B", entry.PublicKey.Id)
				assert.Equal(t, keymanagerv1.KeyType_EC_P256, entry.PublicKey.Type)
			},
		},
		{
			name:        "Nil keyItem",
			keyItem:     nil,
			spireKeyID:  "agent-svid-A",
			expectError: true,
			errorCode:   codes.Internal,
		},
		{
			name: "GetKey error",
			keyItem: &azkeys.KeyItem{
				KID: to.Ptr(azkeys.ID("https://vault.azure.net/keys/test-key/v1")),
			},
			spireKeyID: "agent-svid-A",
			setupMock: func(m *mockKeyVaultClient) {
				m.getKeyErr = errors.New("key not found")
			},
			expectError: true,
			errorCode:   codes.Internal,
		},
		{
			name: "Missing attributes",
			keyItem: &azkeys.KeyItem{
				KID: to.Ptr(azkeys.ID("https://vault.azure.net/keys/test-key/v1")),
			},
			spireKeyID: "agent-svid-A",
			setupMock: func(m *mockKeyVaultClient) {
				m.getKeyResponse = &azkeys.GetKeyResponse{
					KeyBundle: azkeys.KeyBundle{
						Key: &azkeys.JSONWebKey{
							KID: to.Ptr(azkeys.ID("https://vault.azure.net/keys/test-key/v1")),
						},
						Attributes: nil,
					},
				}
			},
			expectError: true,
			errorCode:   codes.Internal,
		},
		{
			name: "Disabled key",
			keyItem: &azkeys.KeyItem{
				KID: to.Ptr(azkeys.ID("https://vault.azure.net/keys/test-key/v1")),
			},
			spireKeyID: "agent-svid-A",
			setupMock: func(m *mockKeyVaultClient) {
				m.getKeyResponse = &azkeys.GetKeyResponse{
					KeyBundle: makeKeyBundle(t, rsa2048Key.Public(), azkeys.JSONWebKeyTypeRSA, nil, to.Ptr(int32(2048))),
				}
				m.getKeyResponse.KeyBundle.Attributes.Enabled = to.Ptr(false)
				m.getKeyResponse.KeyBundle.Key.KID = to.Ptr(azkeys.ID("https://vault.azure.net/keys/test-key/v1"))
			},
			expectError: true,
			errorCode:   codes.FailedPrecondition,
		},
		{
			name: "Unsupported key spec",
			keyItem: &azkeys.KeyItem{
				KID: to.Ptr(azkeys.ID("https://vault.azure.net/keys/test-key/v1")),
			},
			spireKeyID: "agent-svid-A",
			setupMock: func(m *mockKeyVaultClient) {
				m.getKeyResponse = &azkeys.GetKeyResponse{
					KeyBundle: azkeys.KeyBundle{
						Key: &azkeys.JSONWebKey{
							KID: to.Ptr(azkeys.ID("https://vault.azure.net/keys/test-key/v1")),
							Kty: to.Ptr(azkeys.JSONWebKeyTypeEC),
							Crv: to.Ptr(azkeys.JSONWebKeyCurveNameP521),
						},
						Attributes: &azkeys.KeyAttributes{
							Enabled: to.Ptr(true),
						},
					},
				}
			},
			expectError: true,
			errorCode:   codes.Internal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := newMockKeyVaultClient()
			if tt.setupMock != nil {
				tt.setupMock(mockClient)
			}

			kf := &keyFetcher{
				keyVaultClient: mockClient,
				log:            hclog.NewNullLogger(),
				agentID:        testAgentID,
				trustDomain:    testTrustDomain,
			}

			entry, err := kf.fetchKeyEntryDetails(context.Background(), tt.keyItem, tt.spireKeyID)

			if tt.expectError {
				require.Error(t, err)
				assert.Nil(t, entry)
				if tt.errorCode != codes.Unknown {
					statusErr, ok := status.FromError(err)
					require.True(t, ok)
					assert.Equal(t, tt.errorCode, statusErr.Code())
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, entry)
				if tt.validate != nil {
					tt.validate(t, entry)
				}
			}
		})
	}
}

func TestFetchKeyEntries(t *testing.T) {
	testKeys := new(testkey.Keys)
	rsa2048Key := testKeys.NewRSA2048(t)
	ec256Key := testKeys.NewEC256(t)

	tests := []struct {
		name        string
		setupMock   func(*mockKeyVaultClient)
		expectCount int
		expectError bool
		errorCode   codes.Code
		validate    func(t *testing.T, entries []*keyEntry)
	}{
		{
			name: "Empty key list",
			setupMock: func(m *mockKeyVaultClient) {
				m.listKeysPages = [][]*azkeys.KeyItem{}
			},
			expectCount: 0,
			expectError: false,
		},
		{
			name: "Single key",
			setupMock: func(m *mockKeyVaultClient) {
				keyItem := &azkeys.KeyItem{
					KID: to.Ptr(azkeys.ID("https://vault.azure.net/keys/spire-agent-key-test-agent-123-agent-svid-A/v1")),
					Tags: map[string]*string{
						tagNameAgentTrustDomain: to.Ptr(testTrustDomain),
						tagNameAgentID:          to.Ptr(testAgentID),
					},
				}
				m.listKeysPages = [][]*azkeys.KeyItem{{keyItem}}
				m.getKeyResponse = &azkeys.GetKeyResponse{
					KeyBundle: makeKeyBundle(t, rsa2048Key.Public(), azkeys.JSONWebKeyTypeRSA, nil, to.Ptr(int32(2048))),
				}
				m.getKeyResponse.KeyBundle.Key.KID = keyItem.KID
			},
			expectCount: 1,
			expectError: false,
			validate: func(t *testing.T, entries []*keyEntry) {
				assert.Len(t, entries, 1)
				assert.Equal(t, "agent-svid-A", entries[0].PublicKey.Id)
			},
		},
		{
			name: "Multiple keys",
			setupMock: func(m *mockKeyVaultClient) {
				keyItem1 := &azkeys.KeyItem{
					KID: to.Ptr(azkeys.ID("https://vault.azure.net/keys/spire-agent-key-test-agent-123-agent-svid-A/v1")),
					Tags: map[string]*string{
						tagNameAgentTrustDomain: to.Ptr(testTrustDomain),
						tagNameAgentID:          to.Ptr(testAgentID),
					},
				}
				keyItem2 := &azkeys.KeyItem{
					KID: to.Ptr(azkeys.ID("https://vault.azure.net/keys/spire-agent-key-test-agent-123-agent-svid-B/v1")),
					Tags: map[string]*string{
						tagNameAgentTrustDomain: to.Ptr(testTrustDomain),
						tagNameAgentID:          to.Ptr(testAgentID),
					},
				}
				m.listKeysPages = [][]*azkeys.KeyItem{{keyItem1, keyItem2}}
				m.getKeyResponses = map[string]*azkeys.GetKeyResponse{
					keyItem1.KID.Name(): {
						KeyBundle: makeKeyBundle(t, rsa2048Key.Public(), azkeys.JSONWebKeyTypeRSA, nil, to.Ptr(int32(2048))),
					},
					keyItem2.KID.Name(): {
						KeyBundle: makeKeyBundle(t, ec256Key.Public(), azkeys.JSONWebKeyTypeEC, to.Ptr(azkeys.JSONWebKeyCurveNameP256), nil),
					},
				}
				m.getKeyResponses[keyItem1.KID.Name()].KeyBundle.Key.KID = keyItem1.KID
				m.getKeyResponses[keyItem2.KID.Name()].KeyBundle.Key.KID = keyItem2.KID
			},
			expectCount: 2,
			expectError: false,
			validate: func(t *testing.T, entries []*keyEntry) {
				assert.Len(t, entries, 2)
				keyIDs := make(map[string]bool)
				for _, entry := range entries {
					keyIDs[entry.PublicKey.Id] = true
				}
				assert.True(t, keyIDs["agent-svid-A"])
				assert.True(t, keyIDs["agent-svid-B"])
			},
		},
		{
			name: "Keys filtered by agent",
			setupMock: func(m *mockKeyVaultClient) {
				keyItem1 := &azkeys.KeyItem{
					KID: to.Ptr(azkeys.ID("https://vault.azure.net/keys/spire-agent-key-test-agent-123-agent-svid-A/v1")),
					Tags: map[string]*string{
						tagNameAgentTrustDomain: to.Ptr(testTrustDomain),
						tagNameAgentID:          to.Ptr(testAgentID),
					},
				}
				keyItem2 := &azkeys.KeyItem{
					KID: to.Ptr(azkeys.ID("https://vault.azure.net/keys/spire-agent-key-other-agent-456-agent-svid-X/v1")),
					Tags: map[string]*string{
						tagNameAgentTrustDomain: to.Ptr(testTrustDomain),
						tagNameAgentID:          to.Ptr("other-agent-456"),
					},
				}
				m.listKeysPages = [][]*azkeys.KeyItem{{keyItem1, keyItem2}}
				m.getKeyResponse = &azkeys.GetKeyResponse{
					KeyBundle: makeKeyBundle(t, rsa2048Key.Public(), azkeys.JSONWebKeyTypeRSA, nil, to.Ptr(int32(2048))),
				}
				m.getKeyResponse.KeyBundle.Key.KID = keyItem1.KID
			},
			expectCount: 1,
			expectError: false,
			validate: func(t *testing.T, entries []*keyEntry) {
				assert.Len(t, entries, 1)
				assert.Equal(t, "agent-svid-A", entries[0].PublicKey.Id)
			},
		},
		{
			name: "Key with invalid name format",
			setupMock: func(m *mockKeyVaultClient) {
				keyItem := &azkeys.KeyItem{
					KID: to.Ptr(azkeys.ID("https://vault.azure.net/keys/invalid-key-name/v1")),
					Tags: map[string]*string{
						tagNameAgentTrustDomain: to.Ptr(testTrustDomain),
						tagNameAgentID:          to.Ptr(testAgentID),
					},
				}
				m.listKeysPages = [][]*azkeys.KeyItem{{keyItem}}
			},
			expectCount: 0,
			expectError: false,
		},
		{
			name: "ListKeys error",
			setupMock: func(m *mockKeyVaultClient) {
				m.listKeysErr = errors.New("list keys failed")
			},
			expectError: true,
			errorCode:   codes.Internal,
		},
		{
			name: "GetKey error",
			setupMock: func(m *mockKeyVaultClient) {
				keyItem := &azkeys.KeyItem{
					KID: to.Ptr(azkeys.ID("https://vault.azure.net/keys/spire-agent-key-test-agent-123-agent-svid-A/v1")),
					Tags: map[string]*string{
						tagNameAgentTrustDomain: to.Ptr(testTrustDomain),
						tagNameAgentID:          to.Ptr(testAgentID),
					},
				}
				m.listKeysPages = [][]*azkeys.KeyItem{{keyItem}}
				m.getKeyErr = errors.New("get key failed")
			},
			expectError: true,
			errorCode:   codes.Internal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := newMockKeyVaultClient()
			if tt.setupMock != nil {
				tt.setupMock(mockClient)
			}

			kf := &keyFetcher{
				keyVaultClient: mockClient,
				log:            hclog.NewNullLogger(),
				agentID:        testAgentID,
				trustDomain:    testTrustDomain,
			}

			entries, err := kf.fetchKeyEntries(context.Background())

			if tt.expectError {
				require.Error(t, err)
				assert.Nil(t, entries)
				if tt.errorCode != codes.Unknown {
					statusErr, ok := status.FromError(err)
					require.True(t, ok)
					assert.Equal(t, tt.errorCode, statusErr.Code())
				}
			} else {
				require.NoError(t, err)
				assert.Len(t, entries, tt.expectCount)
				if tt.validate != nil {
					tt.validate(t, entries)
				}
			}
		})
	}
}

// Mock implementation of cloudKeyManagementService
type mockKeyVaultClient struct {
	listKeysPages     [][]*azkeys.KeyItem
	listKeysErr       error
	getKeyResponse    *azkeys.GetKeyResponse
	getKeyResponses   map[string]*azkeys.GetKeyResponse
	getKeyErr         error
	createKeyResponse *azkeys.CreateKeyResponse
	createKeyErr      error
	signResponse      *azkeys.SignResponse
	signErr           error
	updateKeyResponse *azkeys.UpdateKeyResponse
	updateKeyErr      error
	deleteKeyResponse *azkeys.DeleteKeyResponse
	deleteKeyErr      error
	deleteKeyCallCount int
	deleteKeyCalls     []string
	currentPage        int
}

func newMockKeyVaultClient() *mockKeyVaultClient {
	return &mockKeyVaultClient{
		listKeysPages:   [][]*azkeys.KeyItem{},
		getKeyResponses: make(map[string]*azkeys.GetKeyResponse),
	}
}

func (m *mockKeyVaultClient) NewListKeysPager(options *azkeys.ListKeysOptions) *runtime.Pager[azkeys.ListKeysResponse] {
	return runtime.NewPager(runtime.PagingHandler[azkeys.ListKeysResponse]{
		More: func(page azkeys.ListKeysResponse) bool {
			return m.currentPage < len(m.listKeysPages)
		},
		Fetcher: func(ctx context.Context, page *azkeys.ListKeysResponse) (azkeys.ListKeysResponse, error) {
			if m.listKeysErr != nil {
				return azkeys.ListKeysResponse{}, m.listKeysErr
			}
			if m.currentPage >= len(m.listKeysPages) {
				return azkeys.ListKeysResponse{}, nil
			}
			resp := azkeys.ListKeysResponse{
				KeyListResult: azkeys.KeyListResult{
					Value: m.listKeysPages[m.currentPage],
				},
			}
			m.currentPage++
			return resp, nil
		},
	})
}

func (m *mockKeyVaultClient) GetKey(ctx context.Context, name string, version string, options *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
	if m.getKeyErr != nil {
		return azkeys.GetKeyResponse{}, m.getKeyErr
	}
	if resp, ok := m.getKeyResponses[name]; ok {
		return *resp, nil
	}
	if m.getKeyResponse != nil {
		return *m.getKeyResponse, nil
	}
	return azkeys.GetKeyResponse{}, errors.New("key not found")
}

func (m *mockKeyVaultClient) CreateKey(ctx context.Context, name string, parameters azkeys.CreateKeyParameters, options *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error) {
	if m.createKeyErr != nil {
		return azkeys.CreateKeyResponse{}, m.createKeyErr
	}
	if m.createKeyResponse != nil {
		return *m.createKeyResponse, nil
	}
	return azkeys.CreateKeyResponse{}, errors.New("create key not configured")
}

func (m *mockKeyVaultClient) DeleteKey(ctx context.Context, name string, options *azkeys.DeleteKeyOptions) (azkeys.DeleteKeyResponse, error) {
	m.deleteKeyCallCount++
	m.deleteKeyCalls = append(m.deleteKeyCalls, name)
	if m.deleteKeyErr != nil {
		return azkeys.DeleteKeyResponse{}, m.deleteKeyErr
	}
	if m.deleteKeyResponse != nil {
		return *m.deleteKeyResponse, nil
	}
	return azkeys.DeleteKeyResponse{}, errors.New("delete key not configured")
}

func (m *mockKeyVaultClient) UpdateKey(ctx context.Context, name string, version string, parameters azkeys.UpdateKeyParameters, options *azkeys.UpdateKeyOptions) (azkeys.UpdateKeyResponse, error) {
	if m.updateKeyErr != nil {
		return azkeys.UpdateKeyResponse{}, m.updateKeyErr
	}
	if m.updateKeyResponse != nil {
		return *m.updateKeyResponse, nil
	}
	return azkeys.UpdateKeyResponse{}, errors.New("update key not configured")
}

func (m *mockKeyVaultClient) Sign(ctx context.Context, name string, version string, parameters azkeys.SignParameters, options *azkeys.SignOptions) (azkeys.SignResponse, error) {
	if m.signErr != nil {
		return azkeys.SignResponse{}, m.signErr
	}
	if m.signResponse != nil {
		return *m.signResponse, nil
	}
	return azkeys.SignResponse{}, errors.New("sign not configured")
}

// Helper function to create a KeyBundle from a public key
func makeKeyBundle(t *testing.T, publicKey crypto.PublicKey, keyType azkeys.JSONWebKeyType, curve *azkeys.JSONWebKeyCurveName, keySize *int32) azkeys.KeyBundle {
	var key *azkeys.JSONWebKey
	keyOps := []*string{to.Ptr("Sign"), to.Ptr("Verify")}

	switch k := publicKey.(type) {
	case *rsa.PublicKey:
		var s = big.NewInt(int64(k.E))
		var e = s.Bytes()
		key = &azkeys.JSONWebKey{
			N:      k.N.Bytes(),
			E:      e,
			KID:    to.Ptr(azkeys.ID("https://vault.azure.net/keys/test-key/v1")),
			KeyOps: keyOps,
			Kty:    to.Ptr(keyType),
		}
	case *ecdsa.PublicKey:
		curveBits := k.Curve.Params().BitSize
		keyBytes := curveBits / 8
		if curveBits%8 > 0 {
			keyBytes++
		}

		xBytes := k.X.Bytes()
		xPadded := make([]byte, keyBytes)
		copy(xPadded[keyBytes-len(xBytes):], xBytes)

		yBytes := k.Y.Bytes()
		yPadded := make([]byte, keyBytes)
		copy(yPadded[keyBytes-len(yBytes):], yBytes)

		key = &azkeys.JSONWebKey{
			Crv:    curve,
			X:      xPadded,
			Y:      yPadded,
			KID:    to.Ptr(azkeys.ID("https://vault.azure.net/keys/test-key/v1")),
			KeyOps: keyOps,
			Kty:    to.Ptr(keyType),
		}
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

