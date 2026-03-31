package azurekeyvault

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/andres-erbsen/clock"
	"github.com/hashicorp/go-hclog"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/keymanager/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	testTenantID  = "test-tenant-id"
	testAppID     = "test-app-id"
	testAppSecret = "test-app-secret"
	testEnvVar    = "TEST_NODE_NAME"
)

func TestGetAgentID(t *testing.T) {
	tests := []struct {
		name            string
		keyIdentifier   string
		envVarName      string
		setEnvVar       string
		expectError     bool
		expectErrorCode codes.Code
		expectErrorMsg  string
		validateAgentID func(t *testing.T, agentID string)
	}{
		{
			name:          "Success",
			keyIdentifier: "key-id-value",
			envVarName:    testEnvVar,
			setEnvVar:     "node-123",
			expectError:   false,
			validateAgentID: func(t *testing.T, agentID string) {
				assert.Equal(t, "key-id-value-node-123", agentID)
			},
		},
		{
			name:            "Environment variable not set",
			keyIdentifier:   "key-id-value",
			envVarName:      testEnvVar,
			setEnvVar:       "",
			expectError:     true,
			expectErrorCode: codes.InvalidArgument,
			expectErrorMsg:  "environment variable",
		},
		{
			name:            "Agent ID too long",
			keyIdentifier:   string(make([]byte, 250)),
			envVarName:      testEnvVar,
			setEnvVar:       "node-123",
			expectError:     true,
			expectErrorCode: codes.InvalidArgument,
			expectErrorMsg:  "exceeds maximum length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set/unset environment variable
			if tt.setEnvVar != "" {
				os.Setenv(tt.envVarName, tt.setEnvVar)
				defer os.Unsetenv(tt.envVarName)
			} else {
				os.Unsetenv(tt.envVarName)
				defer os.Unsetenv(tt.envVarName)
			}

			agentID, err := getAgentID(tt.keyIdentifier, tt.envVarName)

			if tt.expectError {
				require.Error(t, err)
				assert.Empty(t, agentID)
				statusErr, ok := status.FromError(err)
				require.True(t, ok)
				assert.Equal(t, tt.expectErrorCode, statusErr.Code())
				if tt.expectErrorMsg != "" {
					assert.Contains(t, statusErr.Message(), tt.expectErrorMsg)
				}
			} else {
				require.NoError(t, err)
				if tt.validateAgentID != nil {
					tt.validateAgentID(t, agentID)
				}
			}
		})
	}
}

func TestGenerateKeyName(t *testing.T) {
	tests := []struct {
		name         string
		agentID      string
		spireKeyID   string
		expectedName string
	}{
		{
			name:         "Success",
			agentID:      testAgentID,
			spireKeyID:   "agent-svid-A",
			expectedName: "spire-agent-key-test-agent-123-agent-svid-A",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Plugin{
				agentID: tt.agentID,
			}

			keyName := p.generateKeyName(tt.spireKeyID)
			assert.Equal(t, tt.expectedName, keyName)
		})
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name        string
		config      string
		expectValid bool
	}{
		{
			name: "Valid configuration",
			config: `
				key_vault_uri = "https://test.vault.azure.net/"
				key_identifier_value = "test-id"
				agent_id_env_var = "NODE_NAME"
			`,
			expectValid: true,
		},
		{
			name: "Missing key_vault_uri",
			config: `
				key_identifier_value = "test-id"
				agent_id_env_var = "NODE_NAME"
			`,
			expectValid: false,
		},
		{
			name: "Missing key_identifier_value",
			config: `
				key_vault_uri = "https://test.vault.azure.net/"
				agent_id_env_var = "NODE_NAME"
			`,
			expectValid: false,
		},
		{
			name: "Missing agent_id_env_var",
			config: `
				key_vault_uri = "https://test.vault.azure.net/"
				key_identifier_value = "test-id"
			`,
			expectValid: false,
		},
		{
			name: "Key identifier too long",
			config: `
				key_vault_uri = "https://test.vault.azure.net/"
				key_identifier_value = "` + string(make([]byte, 257)) + `"
				agent_id_env_var = "NODE_NAME"
			`,
			expectValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := New()
			p.SetLogger(hclog.NewNullLogger())

			req := &configv1.ValidateRequest{
				HclConfiguration: tt.config,
				CoreConfiguration: &configv1.CoreConfiguration{
					TrustDomain: testTrustDomain,
				},
			}

			resp, err := p.Validate(context.Background(), req)
			require.NoError(t, err)
			assert.Equal(t, tt.expectValid, resp.Valid)
		})
	}
}

func TestConfigure(t *testing.T) {
	tests := []struct {
		name            string
		config          string
		setEnvVar       string
		setupMock       func(*mockKeyVaultClient)
		expectError     bool
		expectErrorCode codes.Code
		validate        func(t *testing.T, p *Plugin)
	}{
		{
			name:      "Success with default credentials",
			setEnvVar: "node-123",
			config: `
				key_vault_uri = "https://test.vault.azure.net/"
				key_identifier_value = "test-id"
				agent_id_env_var = "` + testEnvVar + `"
			`,
			setupMock: func(m *mockKeyVaultClient) {
				m.listKeysPages = [][]*azkeys.KeyItem{}
			},
			expectError: false,
			validate: func(t *testing.T, p *Plugin) {
				assert.Equal(t, testTrustDomain, p.trustDomain)
				assert.Equal(t, "test-id-node-123", p.agentID)
				assert.NotNil(t, p.keyVaultClient)
			},
		},
		{
			name:      "Success with client secret credentials",
			setEnvVar: "node-123",
			config: `
				key_vault_uri = "https://test.vault.azure.net/"
				key_identifier_value = "test-id"
				agent_id_env_var = "` + testEnvVar + `"
				tenant_id = "` + testTenantID + `"
				subscription_id = "sub-id"
				app_id = "` + testAppID + `"
				app_secret = "` + testAppSecret + `"
			`,
			setupMock: func(m *mockKeyVaultClient) {
				m.listKeysPages = [][]*azkeys.KeyItem{}
			},
			expectError: false,
			validate: func(t *testing.T, p *Plugin) {
				assert.NotNil(t, p.keyVaultClient)
			},
		},
		{
			name:      "Environment variable not set",
			setEnvVar: "",
			config: `
				key_vault_uri = "https://test.vault.azure.net/"
				key_identifier_value = "test-id"
				agent_id_env_var = "` + testEnvVar + `"
			`,
			expectError:     true,
			expectErrorCode: codes.InvalidArgument,
		},
		{
			name:      "Invalid key_ttl",
			setEnvVar: "node-123",
			config: `
				key_vault_uri = "https://test.vault.azure.net/"
				key_identifier_value = "test-id"
				agent_id_env_var = "` + testEnvVar + `"
				key_ttl = "invalid"
			`,
			expectError:     true,
			expectErrorCode: codes.InvalidArgument,
		},
		{
			name:      "Fetch keys error",
			setEnvVar: "node-123",
			config: `
				key_vault_uri = "https://test.vault.azure.net/"
				key_identifier_value = "test-id"
				agent_id_env_var = "` + testEnvVar + `"
			`,
			setupMock: func(m *mockKeyVaultClient) {
				m.listKeysErr = errors.New("list keys failed")
			},
			expectError:     true,
			expectErrorCode: codes.Internal,
		},
		{
			name:      "Partial client secret credentials - requires all fields",
			setEnvVar: "node-123",
			config: `
				key_vault_uri = "https://test.vault.azure.net/"
				key_identifier_value = "test-id"
				agent_id_env_var = "` + testEnvVar + `"
				tenant_id = "` + testTenantID + `"
			`,
			setupMock: func(m *mockKeyVaultClient) {
				m.listKeysPages = [][]*azkeys.KeyItem{}
			},
			expectError:     true,
			expectErrorCode: codes.InvalidArgument,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set/unset environment variable
			if tt.setEnvVar != "" {
				os.Setenv(testEnvVar, tt.setEnvVar)
				defer os.Unsetenv(testEnvVar)
			} else {
				os.Unsetenv(testEnvVar)
				defer os.Unsetenv(testEnvVar)
			}

			mockClient := newMockKeyVaultClient()
			if tt.setupMock != nil {
				tt.setupMock(mockClient)
			}

			p := newPlugin(func(creds azcore.TokenCredential, keyVaultURI string, log hclog.Logger) (cloudKeyManagementService, error) {
				return mockClient, nil
			})
			p.SetLogger(hclog.NewNullLogger())

			req := &configv1.ConfigureRequest{
				HclConfiguration: tt.config,
				CoreConfiguration: &configv1.CoreConfiguration{
					TrustDomain: testTrustDomain,
				},
			}

			resp, err := p.Configure(context.Background(), req)

			if tt.expectError {
				require.Error(t, err)
				assert.Nil(t, resp)
				if tt.expectErrorCode != codes.Unknown {
					statusErr, ok := status.FromError(err)
					require.True(t, ok)
					assert.Equal(t, tt.expectErrorCode, statusErr.Code())
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, resp)
				if tt.validate != nil {
					tt.validate(t, p)
				}
			}
		})
	}
}

func TestGenerateKey(t *testing.T) {
	testKeys := new(testkey.Keys)
	rsa2048Key := testKeys.NewRSA2048(t)
	ec256Key := testKeys.NewEC256(t)

	tests := []struct {
		name            string
		req             *keymanagerv1.GenerateKeyRequest
		setupPlugin     func(*Plugin, *mockKeyVaultClient)
		expectError     bool
		expectErrorCode codes.Code
		validate        func(t *testing.T, resp *keymanagerv1.GenerateKeyResponse)
	}{
		{
			name: "Success with RSA 2048",
			req: &keymanagerv1.GenerateKeyRequest{
				KeyId:   "agent-svid-A",
				KeyType: keymanagerv1.KeyType_RSA_2048,
			},
			setupPlugin: func(p *Plugin, m *mockKeyVaultClient) {
				p.agentID = testAgentID
				p.trustDomain = testTrustDomain
				p.keyVaultClient = m
				p.keyTags = map[string]*string{
					tagNameAgentID:          to.Ptr(testAgentID),
					tagNameAgentTrustDomain: to.Ptr(testTrustDomain),
				}
				keyBundle := makeKeyBundle(t, rsa2048Key.Public(), azkeys.JSONWebKeyTypeRSA, nil, to.Ptr(int32(2048)))
				keyBundle.Key.KID = to.Ptr(azkeys.ID("https://vault.azure.net/keys/spire-agent-key-test-agent-123-agent-svid-A/v1"))
				m.createKeyResponse = &azkeys.CreateKeyResponse{KeyBundle: keyBundle}
			},
			expectError: false,
			validate: func(t *testing.T, resp *keymanagerv1.GenerateKeyResponse) {
				assert.Equal(t, "agent-svid-A", resp.PublicKey.Id)
				assert.Equal(t, keymanagerv1.KeyType_RSA_2048, resp.PublicKey.Type)
				assert.NotEmpty(t, resp.PublicKey.PkixData)
				assert.NotEmpty(t, resp.PublicKey.Fingerprint)
			},
		},
		{
			name: "Success with EC P256",
			req: &keymanagerv1.GenerateKeyRequest{
				KeyId:   "agent-svid-B",
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
			setupPlugin: func(p *Plugin, m *mockKeyVaultClient) {
				p.agentID = testAgentID
				p.trustDomain = testTrustDomain
				p.keyVaultClient = m
				p.keyTags = map[string]*string{
					tagNameAgentID:          to.Ptr(testAgentID),
					tagNameAgentTrustDomain: to.Ptr(testTrustDomain),
				}
				keyBundle := makeKeyBundle(t, ec256Key.Public(), azkeys.JSONWebKeyTypeEC, to.Ptr(azkeys.JSONWebKeyCurveNameP256), nil)
				keyBundle.Key.KID = to.Ptr(azkeys.ID("https://vault.azure.net/keys/spire-agent-key-test-agent-123-agent-svid-B/v1"))
				m.createKeyResponse = &azkeys.CreateKeyResponse{KeyBundle: keyBundle}
			},
			expectError: false,
			validate: func(t *testing.T, resp *keymanagerv1.GenerateKeyResponse) {
				assert.Equal(t, "agent-svid-B", resp.PublicKey.Id)
				assert.Equal(t, keymanagerv1.KeyType_EC_P256, resp.PublicKey.Type)
				assert.NotEmpty(t, resp.PublicKey.PkixData)
			},
		},
		{
			name: "Empty key ID",
			req: &keymanagerv1.GenerateKeyRequest{
				KeyId:   "",
				KeyType: keymanagerv1.KeyType_RSA_2048,
			},
			setupPlugin: func(p *Plugin, m *mockKeyVaultClient) {
				p.agentID = testAgentID
				p.keyVaultClient = m
			},
			expectError:     true,
			expectErrorCode: codes.InvalidArgument,
		},
		{
			name: "Unspecified key type",
			req: &keymanagerv1.GenerateKeyRequest{
				KeyId:   "agent-svid-A",
				KeyType: keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE,
			},
			setupPlugin: func(p *Plugin, m *mockKeyVaultClient) {
				p.agentID = testAgentID
				p.keyVaultClient = m
			},
			expectError:     true,
			expectErrorCode: codes.InvalidArgument,
		},
		{
			name: "Not configured",
			req: &keymanagerv1.GenerateKeyRequest{
				KeyId:   "agent-svid-A",
				KeyType: keymanagerv1.KeyType_RSA_2048,
			},
			setupPlugin: func(p *Plugin, m *mockKeyVaultClient) {
				p.agentID = "" // Not configured
			},
			expectError:     true,
			expectErrorCode: codes.FailedPrecondition,
		},
		{
			name: "CreateKey error",
			req: &keymanagerv1.GenerateKeyRequest{
				KeyId:   "agent-svid-A",
				KeyType: keymanagerv1.KeyType_RSA_2048,
			},
			setupPlugin: func(p *Plugin, m *mockKeyVaultClient) {
				p.agentID = testAgentID
				p.trustDomain = testTrustDomain
				p.keyVaultClient = m
				p.keyTags = map[string]*string{
					tagNameAgentID:          to.Ptr(testAgentID),
					tagNameAgentTrustDomain: to.Ptr(testTrustDomain),
				}
				m.createKeyErr = errors.New("create key failed")
			},
			expectError:     true,
			expectErrorCode: codes.Internal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := newMockKeyVaultClient()
			p := New()
			p.SetLogger(hclog.NewNullLogger())
			if tt.setupPlugin != nil {
				tt.setupPlugin(p, mockClient)
			}

			resp, err := p.GenerateKey(context.Background(), tt.req)

			if tt.expectError {
				require.Error(t, err)
				assert.Nil(t, resp)
				if tt.expectErrorCode != codes.Unknown {
					statusErr, ok := status.FromError(err)
					require.True(t, ok)
					assert.Equal(t, tt.expectErrorCode, statusErr.Code())
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, resp)
				if tt.validate != nil {
					tt.validate(t, resp)
				}
			}
		})
	}
}

func TestSignData(t *testing.T) {
	sum256 := sha256.Sum256([]byte("test data"))

	tests := []struct {
		name            string
		req             *keymanagerv1.SignDataRequest
		setupPlugin     func(*Plugin, *mockKeyVaultClient)
		expectError     bool
		expectErrorCode codes.Code
		validate        func(t *testing.T, resp *keymanagerv1.SignDataResponse)
	}{
		{
			name: "Success with RSA 2048 SHA256",
			req: &keymanagerv1.SignDataRequest{
				KeyId: "agent-svid-A",
				Data:  sum256[:],
				SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanagerv1.HashAlgorithm_SHA256,
				},
			},
			setupPlugin: func(p *Plugin, m *mockKeyVaultClient) {
				p.entries = map[string]keyEntry{
					"agent-svid-A": {
						KeyName:    "spire-agent-key-test-agent-123-agent-svid-A",
						keyVersion: "v1",
						PublicKey: &keymanagerv1.PublicKey{
							Id:          "agent-svid-A",
							Type:        keymanagerv1.KeyType_RSA_2048,
							Fingerprint: "test-fingerprint",
						},
					},
				}
				p.keyVaultClient = m
				m.signResponse = &azkeys.SignResponse{
					KeyOperationResult: azkeys.KeyOperationResult{Result: []byte("signature")},
				}
			},
			expectError: false,
			validate: func(t *testing.T, resp *keymanagerv1.SignDataResponse) {
				assert.NotEmpty(t, resp.Signature)
				assert.Equal(t, "test-fingerprint", resp.KeyFingerprint)
			},
		},
		{
			name: "Success with EC P256 SHA256",
			req: &keymanagerv1.SignDataRequest{
				KeyId: "agent-svid-B",
				Data:  sum256[:],
				SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanagerv1.HashAlgorithm_SHA256,
				},
			},
			setupPlugin: func(p *Plugin, m *mockKeyVaultClient) {
				p.entries = map[string]keyEntry{
					"agent-svid-B": {
						KeyName:    "spire-agent-key-test-agent-123-agent-svid-B",
						keyVersion: "v1",
						PublicKey: &keymanagerv1.PublicKey{
							Id:   "agent-svid-B",
							Type: keymanagerv1.KeyType_EC_P256,
						},
					},
				}
				p.keyVaultClient = m
				m.signResponse = &azkeys.SignResponse{
					KeyOperationResult: azkeys.KeyOperationResult{Result: make([]byte, 64)},
				}
			},
			expectError: false,
			validate: func(t *testing.T, resp *keymanagerv1.SignDataResponse) {
				assert.NotEmpty(t, resp.Signature)
			},
		},
		{
			name: "Empty key ID",
			req: &keymanagerv1.SignDataRequest{
				KeyId: "",
				Data:  sum256[:],
				SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanagerv1.HashAlgorithm_SHA256,
				},
			},
			setupPlugin: func(p *Plugin, m *mockKeyVaultClient) {
				p.keyVaultClient = m
			},
			expectError:     true,
			expectErrorCode: codes.InvalidArgument,
		},
		{
			name: "Nil signer opts",
			req: &keymanagerv1.SignDataRequest{
				KeyId:      "agent-svid-A",
				Data:       sum256[:],
				SignerOpts: nil,
			},
			setupPlugin: func(p *Plugin, m *mockKeyVaultClient) {
				p.keyVaultClient = m
			},
			expectError:     true,
			expectErrorCode: codes.InvalidArgument,
		},
		{
			name: "Key not found",
			req: &keymanagerv1.SignDataRequest{
				KeyId: "non-existent",
				Data:  sum256[:],
				SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanagerv1.HashAlgorithm_SHA256,
				},
			},
			setupPlugin: func(p *Plugin, m *mockKeyVaultClient) {
				p.entries = map[string]keyEntry{}
				p.keyVaultClient = m
			},
			expectError:     true,
			expectErrorCode: codes.NotFound,
		},
		{
			name: "Sign error",
			req: &keymanagerv1.SignDataRequest{
				KeyId: "agent-svid-A",
				Data:  sum256[:],
				SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanagerv1.HashAlgorithm_SHA256,
				},
			},
			setupPlugin: func(p *Plugin, m *mockKeyVaultClient) {
				p.entries = map[string]keyEntry{
					"agent-svid-A": {
						KeyName:    "spire-agent-key-test-agent-123-agent-svid-A",
						keyVersion: "v1",
						PublicKey:  &keymanagerv1.PublicKey{Id: "agent-svid-A", Type: keymanagerv1.KeyType_RSA_2048},
					},
				}
				p.keyVaultClient = m
				m.signErr = errors.New("sign failed")
			},
			expectError:     true,
			expectErrorCode: codes.Internal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := newMockKeyVaultClient()
			p := New()
			p.SetLogger(hclog.NewNullLogger())
			if tt.setupPlugin != nil {
				tt.setupPlugin(p, mockClient)
			}

			resp, err := p.SignData(context.Background(), tt.req)

			if tt.expectError {
				require.Error(t, err)
				assert.Nil(t, resp)
				if tt.expectErrorCode != codes.Unknown {
					statusErr, ok := status.FromError(err)
					require.True(t, ok)
					assert.Equal(t, tt.expectErrorCode, statusErr.Code())
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, resp)
				if tt.validate != nil {
					tt.validate(t, resp)
				}
			}
		})
	}
}

func TestGetPublicKey(t *testing.T) {
	tests := []struct {
		name            string
		req             *keymanagerv1.GetPublicKeyRequest
		setupPlugin     func(*Plugin)
		expectError     bool
		expectErrorCode codes.Code
		validate        func(t *testing.T, resp *keymanagerv1.GetPublicKeyResponse)
	}{
		{
			name: "Success",
			req: &keymanagerv1.GetPublicKeyRequest{
				KeyId: "agent-svid-A",
			},
			setupPlugin: func(p *Plugin) {
				p.entries = map[string]keyEntry{
					"agent-svid-A": {
						PublicKey: &keymanagerv1.PublicKey{Id: "agent-svid-A", Type: keymanagerv1.KeyType_RSA_2048},
					},
				}
			},
			expectError: false,
			validate: func(t *testing.T, resp *keymanagerv1.GetPublicKeyResponse) {
				assert.Equal(t, "agent-svid-A", resp.PublicKey.Id)
				assert.Equal(t, keymanagerv1.KeyType_RSA_2048, resp.PublicKey.Type)
			},
		},
		{
			name: "Empty key ID",
			req: &keymanagerv1.GetPublicKeyRequest{
				KeyId: "",
			},
			setupPlugin: func(p *Plugin) {
				p.entries = map[string]keyEntry{}
			},
			expectError:     true,
			expectErrorCode: codes.InvalidArgument,
		},
		{
			name: "Key not found",
			req: &keymanagerv1.GetPublicKeyRequest{
				KeyId: "non-existent",
			},
			setupPlugin: func(p *Plugin) {
				p.entries = map[string]keyEntry{}
			},
			expectError:     true,
			expectErrorCode: codes.NotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := New()
			p.SetLogger(hclog.NewNullLogger())
			if tt.setupPlugin != nil {
				tt.setupPlugin(p)
			}

			resp, err := p.GetPublicKey(context.Background(), tt.req)

			if tt.expectError {
				require.Error(t, err)
				assert.Nil(t, resp)
				if tt.expectErrorCode != codes.Unknown {
					statusErr, ok := status.FromError(err)
					require.True(t, ok)
					assert.Equal(t, tt.expectErrorCode, statusErr.Code())
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, resp)
				if tt.validate != nil {
					tt.validate(t, resp)
				}
			}
		})
	}
}

func TestGetPublicKeys(t *testing.T) {
	tests := []struct {
		name        string
		setupPlugin func(*Plugin)
		expectCount int
	}{
		{
			name: "No keys",
			setupPlugin: func(p *Plugin) {
				p.entries = map[string]keyEntry{}
			},
			expectCount: 0,
		},
		{
			name: "Multiple keys",
			setupPlugin: func(p *Plugin) {
				p.entries = map[string]keyEntry{
					"agent-svid-A": {
						PublicKey: &keymanagerv1.PublicKey{Id: "agent-svid-A", Type: keymanagerv1.KeyType_RSA_2048},
					},
					"agent-svid-B": {
						PublicKey: &keymanagerv1.PublicKey{Id: "agent-svid-B", Type: keymanagerv1.KeyType_EC_P256},
					},
				}
			},
			expectCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := New()
			p.SetLogger(hclog.NewNullLogger())
			if tt.setupPlugin != nil {
				tt.setupPlugin(p)
			}

			resp, err := p.GetPublicKeys(context.Background(), &keymanagerv1.GetPublicKeysRequest{})
			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.Len(t, resp.PublicKeys, tt.expectCount)
		})
	}
}

func TestSetCache(t *testing.T) {
	p := New()
	p.SetLogger(hclog.NewNullLogger())

	// Set initial cache
	initialEntries := []*keyEntry{
		{
			KeyID:   "key1",
			KeyName: "name1",
			PublicKey: &keymanagerv1.PublicKey{
				Id: "agent-svid-A",
			},
		},
		{
			KeyID:   "key2",
			KeyName: "name2",
			PublicKey: &keymanagerv1.PublicKey{
				Id: "agent-svid-B",
			},
		},
	}

	p.setCache(initialEntries)
	assert.Len(t, p.entries, 2)
	assert.Equal(t, "agent-svid-A", p.entries["agent-svid-A"].PublicKey.Id)
	assert.Equal(t, "agent-svid-B", p.entries["agent-svid-B"].PublicKey.Id)

	// Replace cache
	newEntries := []*keyEntry{
		{
			KeyID:   "key3",
			KeyName: "name3",
			PublicKey: &keymanagerv1.PublicKey{
				Id: "agent-svid-C",
			},
		},
	}

	p.setCache(newEntries)
	assert.Len(t, p.entries, 1)
	assert.Equal(t, "agent-svid-C", p.entries["agent-svid-C"].PublicKey.Id)
	_, exists := p.entries["agent-svid-A"]
	assert.False(t, exists)
}

func TestRefreshKeys(t *testing.T) {
	testKeys := new(testkey.Keys)
	rsa2048Key := testKeys.NewRSA2048(t)

	tests := []struct {
		name        string
		setupPlugin func(*Plugin, *mockKeyVaultClient, *clock.Mock)
		expectError bool
	}{
		{
			name: "Success - refresh all keys",
			setupPlugin: func(p *Plugin, m *mockKeyVaultClient, c *clock.Mock) {
				p.keyVaultClient = m
				p.entries = map[string]keyEntry{
					"agent-svid-A": {
						KeyName:    "key-A",
						keyVersion: "v1",
						PublicKey:  &keymanagerv1.PublicKey{Id: "agent-svid-A"},
					},
					"agent-svid-B": {
						KeyName:    "key-B",
						keyVersion: "v1",
						PublicKey:  &keymanagerv1.PublicKey{Id: "agent-svid-B"},
					},
				}
				keyBundle := makeKeyBundle(t, rsa2048Key.Public(), azkeys.JSONWebKeyTypeRSA, nil, to.Ptr(int32(2048)))
				m.getKeyResponse = &azkeys.GetKeyResponse{KeyBundle: keyBundle}
				m.updateKeyResponse = &azkeys.UpdateKeyResponse{KeyBundle: keyBundle}
			},
			expectError: false,
		},
		{
			name: "GetKey error - continues with other keys",
			setupPlugin: func(p *Plugin, m *mockKeyVaultClient, c *clock.Mock) {
				p.keyVaultClient = m
				p.entries = map[string]keyEntry{
					"agent-svid-A": {
						KeyName:    "key-A",
						keyVersion: "v1",
						PublicKey:  &keymanagerv1.PublicKey{Id: "agent-svid-A"},
					},
				}
				m.getKeyErr = errors.New("get key failed")
			},
			expectError: false,
		},
		{
			name: "UpdateKey error",
			setupPlugin: func(p *Plugin, m *mockKeyVaultClient, c *clock.Mock) {
				p.keyVaultClient = m
				p.entries = map[string]keyEntry{
					"agent-svid-A": {
						KeyName:    "key-A",
						keyVersion: "v1",
						PublicKey:  &keymanagerv1.PublicKey{Id: "agent-svid-A"},
					},
				}
				m.getKeyResponse = &azkeys.GetKeyResponse{
					KeyBundle: makeKeyBundle(t, rsa2048Key.Public(), azkeys.JSONWebKeyTypeRSA, nil, to.Ptr(int32(2048))),
				}
				m.updateKeyErr = errors.New("update key failed")
			},
			expectError: true,
		},
		{
			name: "No keys to refresh",
			setupPlugin: func(p *Plugin, m *mockKeyVaultClient, c *clock.Mock) {
				p.keyVaultClient = m
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := newMockKeyVaultClient()
			mockClock := clock.NewMock()
			p := New()
			p.SetLogger(hclog.NewNullLogger())
			p.hooks.clk = mockClock
			if tt.setupPlugin != nil {
				tt.setupPlugin(p, mockClient, mockClock)
			}

			err := p.refreshKeys(context.Background())

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCleanupStaleKeys(t *testing.T) {
	tests := []struct {
		name        string
		setupPlugin func(*Plugin, *mockKeyVaultClient, *clock.Mock)
		keyTTL      time.Duration
		validate    func(t *testing.T, p *Plugin, m *mockKeyVaultClient)
	}{
		{
			name:   "Cleanup stale keys",
			keyTTL: 24 * time.Hour,
			setupPlugin: func(p *Plugin, m *mockKeyVaultClient, c *clock.Mock) {
				p.keyVaultClient = m
				p.trustDomain = testTrustDomain
				p.hooks.clk = c

				now := c.Now()
				// Stale key updated more than 1 month ago (minimumKeyTTL)
				staleKey := &azkeys.KeyItem{
					KID: to.Ptr(azkeys.ID("https://vault.azure.net/keys/stale-key/v1")),
					Tags: map[string]*string{
						tagNameAgentTrustDomain: to.Ptr(testTrustDomain),
					},
					Attributes: &azkeys.KeyAttributes{
						Updated: to.Ptr(now.Add(-35 * 24 * time.Hour)),
					},
				}
				freshKey := &azkeys.KeyItem{
					KID: to.Ptr(azkeys.ID("https://vault.azure.net/keys/fresh-key/v1")),
					Tags: map[string]*string{
						tagNameAgentTrustDomain: to.Ptr(testTrustDomain),
					},
					Attributes: &azkeys.KeyAttributes{
						Updated: to.Ptr(now.Add(-1 * time.Hour)),
					},
				}
				otherTDKey := &azkeys.KeyItem{
					KID: to.Ptr(azkeys.ID("https://vault.azure.net/keys/other-td-key/v1")),
					Tags: map[string]*string{
						tagNameAgentTrustDomain: to.Ptr("other.example.org"),
					},
					Attributes: &azkeys.KeyAttributes{
						Updated: to.Ptr(now.Add(-35 * 24 * time.Hour)),
					},
				}

				m.currentPage = 0
				m.listKeysPages = [][]*azkeys.KeyItem{{staleKey, freshKey, otherTDKey}}
			},
			validate: func(t *testing.T, p *Plugin, m *mockKeyVaultClient) {
				// Check if pager was called
				if m.currentPage == 0 {
					t.Error("Pager was not called")
					return
				}
				// Check if stale key was deleted (only stale-key should be deleted)
				assert.Equal(t, 1, m.deleteKeyCallCount, "Expected exactly one delete call for stale key")
				if len(m.deleteKeyCalls) > 0 {
					assert.Equal(t, "stale-key", m.deleteKeyCalls[0], "Expected stale-key to be deleted")
				}
			},
		},
		{
			name:   "Use minimumKeyTTL when keyTTL is too short",
			keyTTL: 1 * time.Hour,
			setupPlugin: func(p *Plugin, m *mockKeyVaultClient, c *clock.Mock) {
				p.keyVaultClient = m
				p.trustDomain = testTrustDomain
				p.hooks.clk = c

				now := c.Now()
				key := &azkeys.KeyItem{
					KID: to.Ptr(azkeys.ID("https://vault.azure.net/keys/test-key/v1")),
					Tags: map[string]*string{
						tagNameAgentTrustDomain: to.Ptr(testTrustDomain),
					},
					Attributes: &azkeys.KeyAttributes{
						Updated: to.Ptr(now.Add(-14 * 24 * time.Hour)),
					},
				}
				m.listKeysPages = [][]*azkeys.KeyItem{{key}}
			},
			validate: func(t *testing.T, p *Plugin, m *mockKeyVaultClient) {
				// Key should not be deleted (not stale enough)
				assert.Equal(t, 0, m.deleteKeyCallCount, "Key should not be deleted")
			},
		},
		{
			name:   "ListKeys error",
			keyTTL: 24 * time.Hour,
			setupPlugin: func(p *Plugin, m *mockKeyVaultClient, c *clock.Mock) {
				p.keyVaultClient = m
				p.trustDomain = testTrustDomain
				p.hooks.clk = c
				m.listKeysErr = errors.New("list keys failed")
			},
			validate: func(t *testing.T, p *Plugin, m *mockKeyVaultClient) {
				// Should not delete any keys on error
				assert.Equal(t, 0, m.deleteKeyCallCount, "Should not delete keys on error")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := newMockKeyVaultClient()
			mockClock := clock.NewMock()
			p := New()
			p.SetLogger(hclog.NewNullLogger())
			p.keyTTL = tt.keyTTL
			if tt.setupPlugin != nil {
				tt.setupPlugin(p, mockClient, mockClock)
			}

			p.cleanupStaleKeys(context.Background())

			if tt.validate != nil {
				tt.validate(t, p, mockClient)
			}
		})
	}
}

