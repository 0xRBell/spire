package azurekeyvault

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/andres-erbsen/clock"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/keymanager/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	azkv "github.com/spiffe/spire/pkg/common/plugin/azure_keyvault"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName              = "azure_key_vault"
	keyNamePrefix           = "spire-agent-key"
	tagNameAgentID          = "spire-agent-id"
	tagNameAgentTrustDomain = "spire-agent-td"
	minimumKeyTTL           = time.Hour * 24 * 30 // 1 month
	defaultKeyTTL           = time.Hour * 24 * 14 // 2 weeks
	keyNameTag              = "key_name"
	reasonTag               = "reason"
	minimumRefreshInterval  = time.Hour // Minimum refresh interval for key refresh task
)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		keymanagerv1.KeyManagerPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

type keyEntry struct {
	KeyID      string
	KeyName    string
	keyVersion string
	PublicKey  *keymanagerv1.PublicKey
}

type pluginHooks struct {
	newKeyVaultClient func(creds azcore.TokenCredential, keyVaultURI string, log hclog.Logger) (cloudKeyManagementService, error)
	fetchCredential   func() (azcore.TokenCredential, error)
	clk               clock.Clock
	// Used for testing only.
	refreshKeysSignal chan error
}

// Config provides configuration context for the plugin.
type Config struct {
	KeyIdentifierValue string `hcl:"key_identifier_value" json:"key_identifier_value"`
	KeyVaultURI        string `hcl:"key_vault_uri" json:"key_vault_uri"`
	AgentIDEnvVar      string `hcl:"agent_id_env_var" json:"agent_id_env_var"`
	KeyTTL             string `hcl:"key_ttl" json:"key_ttl"`
	TenantID           string `hcl:"tenant_id" json:"tenant_id"`
	SubscriptionID     string `hcl:"subscription_id" json:"subscription_id"`
	AppID              string `hcl:"app_id" json:"app_id"`
	AppSecret          string `hcl:"app_secret" json:"app_secret"`
}

func buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *Config {
	newConfig := new(Config)

	if err := hcl.Decode(newConfig, hclText); err != nil {
		status.ReportErrorf("unable to decode configuration: %v", err)
		return nil
	}

	if newConfig.KeyVaultURI == "" {
		status.ReportError("configuration is missing the Key Vault URI")
	}

	if newConfig.AgentIDEnvVar == "" {
		status.ReportError("configuration requires agent_id_env_var")
	}

	if newConfig.KeyIdentifierValue == "" {
		status.ReportError("configuration requires key_identifier_value")
	}

	if len(newConfig.KeyIdentifierValue) > 256 {
		status.ReportError("Key identifier must not be longer than 256 characters")
	}

	// Parse key_ttl, default to 2 weeks if not specified
	if newConfig.KeyTTL == "" {
		newConfig.KeyTTL = defaultKeyTTL.String()
	}

	return newConfig
}

// Plugin is the main representation of this keymanager plugin.
// It manages keys stored in Azure Key Vault and provides key operations
// for the SPIRE agent.
//
// Mutex usage:
//   - entriesMtx: Protects the entries map cache
type Plugin struct {
	keymanagerv1.UnsafeKeyManagerServer
	configv1.UnsafeConfigServer
	log            hclog.Logger
	entries        map[string]keyEntry
	entriesMtx     sync.RWMutex // Protects entries map
	keyVaultClient cloudKeyManagementService
	trustDomain    string
	agentID        string
	hooks          pluginHooks
	keyTags        map[string]*string
	keyTTL         time.Duration
}

// New returns an instantiated plugin.
func New() *Plugin {
	return newPlugin(newKeyVaultClient)
}

// newPlugin returns a new plugin instance.
func newPlugin(
	newKeyVaultClient func(creds azcore.TokenCredential, keyVaultURI string, log hclog.Logger) (cloudKeyManagementService, error),
) *Plugin {
	return &Plugin{
		entries: make(map[string]keyEntry),
		hooks: pluginHooks{
			newKeyVaultClient: newKeyVaultClient,
			clk:               clock.New(),
			fetchCredential: func() (azcore.TokenCredential, error) {
				return azidentity.NewDefaultAzureCredential(nil)
			},
		},
	}
}

// SetLogger sets a logger
func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	newConfig, _, err := pluginconf.Build(req, buildConfig)
	if err != nil {
		return nil, err
	}

	agentID, err := getAgentID(newConfig.KeyIdentifierValue, newConfig.AgentIDEnvVar)
	if err != nil {
		return nil, err
	}
	p.log.Debug("Loaded agent id", "agent_id", agentID)

	// Parse key_ttl duration
	keyTTL, err := time.ParseDuration(newConfig.KeyTTL)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid key_ttl duration %q: %v", newConfig.KeyTTL, err)
	}

	// Setup Azure Key Vault client with appropriate credentials
	client, err := p.setupCredentials(newConfig)
	if err != nil {
		return nil, err
	}

	// Initialize cache by fetching existing keys from Key Vault
	keyEntries, err := p.initializeCache(ctx, client, agentID, req.CoreConfiguration.TrustDomain, newConfig.KeyVaultURI)
	if err != nil {
		return nil, err
	}

	// Update plugin state with new configuration
	p.setCache(keyEntries)
	p.keyVaultClient = client
	p.trustDomain = req.CoreConfiguration.TrustDomain
	p.agentID = agentID
	p.keyTTL = keyTTL
	p.keyTags = make(map[string]*string)
	p.keyTags[tagNameAgentTrustDomain] = to.Ptr(req.CoreConfiguration.TrustDomain)
	p.keyTags[tagNameAgentID] = to.Ptr(agentID)

	// Start background tasks for key refresh and cleanup
	p.startBackgroundTasks()

	return &configv1.ConfigureResponse{}, nil
}

// setupCredentials creates an Azure Key Vault client using either client secret credentials
// or default Azure credentials (MSI/Managed Identity).
func (p *Plugin) setupCredentials(config *Config) (cloudKeyManagementService, error) {
	// Check if client secret credentials are provided
	hasClientSecretCreds := config.TenantID != "" || config.AppID != "" || config.AppSecret != "" || config.SubscriptionID != ""

	if hasClientSecretCreds {
		// Validate all required fields for client secret authentication
		if config.TenantID == "" {
			return nil, status.Errorf(codes.InvalidArgument, "invalid configuration: tenant_id is required when using client secret authentication")
		}
		if config.SubscriptionID == "" {
			return nil, status.Errorf(codes.InvalidArgument, "invalid configuration: subscription_id is required when using client secret authentication")
		}
		if config.AppID == "" {
			return nil, status.Errorf(codes.InvalidArgument, "invalid configuration: app_id is required when using client secret authentication")
		}
		if config.AppSecret == "" {
			return nil, status.Errorf(codes.InvalidArgument, "invalid configuration: app_secret is required when using client secret authentication")
		}

		creds, err := azidentity.NewClientSecretCredential(config.TenantID, config.AppID, config.AppSecret, nil)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "unable to create client secret credential: %v", err)
		}

		client, err := p.hooks.newKeyVaultClient(creds, config.KeyVaultURI, p.log)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to create Key Vault client with client secret credentials: %v", err)
		}
		return client, nil
	}

	// Use default Azure credentials (MSI/Managed Identity)
	cred, err := p.hooks.fetchCredential()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to fetch default Azure credential: %v", err)
	}

	client, err := p.hooks.newKeyVaultClient(cred, config.KeyVaultURI, p.log)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create Key Vault client with default Azure credential: %v", err)
	}
	return client, nil
}

// initializeCache fetches existing keys from Azure Key Vault and returns them as key entries.
func (p *Plugin) initializeCache(ctx context.Context, client cloudKeyManagementService, agentID, trustDomain, keyVaultURI string) ([]*keyEntry, error) {
	fetcher := &keyFetcher{
		keyVaultClient: client,
		log:            p.log,
		agentID:        agentID,
		trustDomain:    trustDomain,
	}

	p.log.Debug("Fetching keys from Azure Key Vault", "key_vault_uri", keyVaultURI)
	keyEntries, err := fetcher.fetchKeyEntries(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch keys from Key Vault: %w", err)
	}

	return keyEntries, nil
}

// startBackgroundTasks starts background tasks for key refresh and cleanup.
func (p *Plugin) startBackgroundTasks() {
	taskCtx := context.Background()
	go p.refreshKeysTask(taskCtx)
	go p.cleanupStaleKeys(taskCtx)
}

func (p *Plugin) Validate(ctx context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, nil
}

// GenerateKey creates a key in Key Vault. If a key already exists in the local
// storage, it is updated.
func (p *Plugin) GenerateKey(ctx context.Context, req *keymanagerv1.GenerateKeyRequest) (*keymanagerv1.GenerateKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}
	if req.KeyType == keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE {
		return nil, status.Error(codes.InvalidArgument, "key type is required")
	}
	if p.agentID == "" {
		return nil, status.Error(codes.FailedPrecondition, "agent ID not configured")
	}

	spireKeyID := req.KeyId
	newKeyEntry, err := p.createKeyWithClient(ctx, spireKeyID, req.KeyType)
	if err != nil {
		return nil, err
	}

	p.setKeyEntry(spireKeyID, *newKeyEntry)

	return &keymanagerv1.GenerateKeyResponse{
		PublicKey: newKeyEntry.PublicKey,
	}, nil
}

// createKeyWithClient creates a key in Azure Key Vault.
func (p *Plugin) createKeyWithClient(ctx context.Context, spireKeyID string, keyType keymanagerv1.KeyType) (*keyEntry, error) {
	sharedKeyType := protoKeyTypeToShared(keyType)
	createKeyParameters, err := azkv.GetCreateKeyParameters(sharedKeyType, p.keyTags)
	if err != nil {
		return nil, err
	}

	keyName := p.generateKeyName(spireKeyID)

	createResp, err := p.keyVaultClient.CreateKey(ctx, keyName, *createKeyParameters, nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create key %q: %v", keyName, err)
	}
	log := p.log.With("key_id", *createResp.Key.KID)
	log.Debug("Key created", "algorithm", *createResp.Key.Kty)

	rawKey, err := azkv.JWKToRawKey(createResp.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to convert key vault key to raw key: %w", err)
	}
	publicKey, err := x509.MarshalPKIXPublicKey(rawKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to marshal public key: %v", err)
	}

	return &keyEntry{
		KeyID:      string(*createResp.Key.KID),
		KeyName:    createResp.Key.KID.Name(),
		keyVersion: createResp.Key.KID.Version(),
		PublicKey: &keymanagerv1.PublicKey{
			Id:          spireKeyID,
			Type:        keyType,
			PkixData:    publicKey,
			Fingerprint: azkv.MakeFingerprint(publicKey),
		},
	}, nil
}

// SignData creates a digital signature for the data to be signed
func (p *Plugin) SignData(ctx context.Context, req *keymanagerv1.SignDataRequest) (*keymanagerv1.SignDataResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}
	if req.SignerOpts == nil {
		return nil, status.Error(codes.InvalidArgument, "signer opts is required")
	}

	// Get key entry from cache (read-only access)
	key, hasKey := p.getKeyEntry(req.KeyId)
	if !hasKey {
		return nil, status.Errorf(codes.NotFound, "key %q not found", req.KeyId)
	}

	keyType := key.PublicKey.Type
	keyName := key.KeyName
	keyVersion := key.keyVersion
	keyFingerprint := key.PublicKey.Fingerprint

	sharedKeyType := protoKeyTypeToShared(keyType)
	hashAlgo, isPSS, err := extractHashInfo(req.SignerOpts)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	signingAlgo, err := azkv.SigningAlgorithm(sharedKeyType, hashAlgo, isPSS)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	signResponse, err := p.keyVaultClient.Sign(ctx, keyName, keyVersion, azkeys.SignParameters{
		Algorithm: to.Ptr(signingAlgo),
		Value:     req.Data,
	}, nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to sign with key %q: %v", keyName, err)
	}

	result := signResponse.Result
	signatureBytes, err := azkv.SignatureToASN1(result, sharedKeyType)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to convert Key Vault signature to ASN.1/DER format: %v", err)
	}

	return &keymanagerv1.SignDataResponse{
		Signature:      signatureBytes,
		KeyFingerprint: keyFingerprint,
	}, nil
}

// GetPublicKey returns the public key for a given key
func (p *Plugin) GetPublicKey(_ context.Context, req *keymanagerv1.GetPublicKeyRequest) (*keymanagerv1.GetPublicKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}

	p.entriesMtx.RLock()
	defer p.entriesMtx.RUnlock()

	entry, ok := p.entries[req.KeyId]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "key %q not found", req.KeyId)
	}

	return &keymanagerv1.GetPublicKeyResponse{
		PublicKey: entry.PublicKey,
	}, nil
}

// GetPublicKeys return the publicKey for all the keys
func (p *Plugin) GetPublicKeys(context.Context, *keymanagerv1.GetPublicKeysRequest) (*keymanagerv1.GetPublicKeysResponse, error) {
	var keys []*keymanagerv1.PublicKey
	p.entriesMtx.RLock()
	defer p.entriesMtx.RUnlock()
	for _, key := range p.entries {
		keys = append(keys, key.PublicKey)
	}

	return &keymanagerv1.GetPublicKeysResponse{PublicKeys: keys}, nil
}

// getKeyEntry gets the entry from the cache that matches the provided SPIRE Key ID
func (p *Plugin) getKeyEntry(keyID string) (ke keyEntry, ok bool) {
	p.entriesMtx.RLock()
	defer p.entriesMtx.RUnlock()

	ke, ok = p.entries[keyID]
	return ke, ok
}

// setKeyEntry adds the entry to the cache that matches the provided SPIRE Key ID
func (p *Plugin) setKeyEntry(keyID string, ke keyEntry) {
	p.entriesMtx.Lock()
	defer p.entriesMtx.Unlock()

	p.entries[keyID] = ke
}

// setCache replaces the entries cache with the provided key entries.
// This method must be called while holding the entriesMtx lock.
func (p *Plugin) setCache(keyEntries []*keyEntry) {
	p.entriesMtx.Lock()
	defer p.entriesMtx.Unlock()

	// Clear previous cache
	p.entries = make(map[string]keyEntry)

	// Add new entries to cache
	for _, e := range keyEntries {
		p.entries[e.PublicKey.Id] = *e
		p.log.Debug("Key loaded", "key_id", e.KeyID, "key_name", e.KeyName)
	}
}

// generateKeyName returns a new identifier to be used as a key name.
// The returned name has the form: spire-agent-key-<AGENT-ID>-<SPIRE-KEY-ID>,
// where AGENT-ID is the unique agent identifier and SPIRE-KEY-ID is provided
// through the spireKeyID parameter.
func (p *Plugin) generateKeyName(spireKeyID string) string {
	return fmt.Sprintf("%s-%s-%s", keyNamePrefix, p.agentID, spireKeyID)
}

func getAgentID(keyIdentifierValue, envVarName string) (string, error) {
	envValue := os.Getenv(envVarName)
	if envValue == "" {
		return "", status.Errorf(codes.InvalidArgument, "environment variable %q is not set", envVarName)
	}

	agentID := fmt.Sprintf("%s-%s", keyIdentifierValue, envValue)
	if len(agentID) > 256 {
		return "", status.Errorf(codes.InvalidArgument, "agent ID exceeds maximum length of 256 characters")
	}

	return agentID, nil
}

// protoKeyTypeToShared converts a proto KeyType to a shared KeyType.
func protoKeyTypeToShared(kt keymanagerv1.KeyType) azkv.KeyType {
	switch kt {
	case keymanagerv1.KeyType_RSA_2048:
		return azkv.KeyTypeRSA2048
	case keymanagerv1.KeyType_RSA_4096:
		return azkv.KeyTypeRSA4096
	case keymanagerv1.KeyType_EC_P256:
		return azkv.KeyTypeECP256
	case keymanagerv1.KeyType_EC_P384:
		return azkv.KeyTypeECP384
	default:
		return azkv.KeyTypeUnspecified
	}
}

// extractHashInfo extracts the hash algorithm and PSS flag from signer options.
func extractHashInfo(signerOpts any) (azkv.HashAlgorithm, bool, error) {
	switch opts := signerOpts.(type) {
	case *keymanagerv1.SignDataRequest_HashAlgorithm:
		return protoHashAlgoToShared(opts.HashAlgorithm), false, nil
	case *keymanagerv1.SignDataRequest_PssOptions:
		if opts.PssOptions == nil {
			return azkv.HashAlgorithmUnspecified, false, errors.New("invalid signerOpts: PSS options are required")
		}
		return protoHashAlgoToShared(opts.PssOptions.HashAlgorithm), true, nil
	default:
		return azkv.HashAlgorithmUnspecified, false, fmt.Errorf("unsupported signer opts type %T", opts)
	}
}

// protoHashAlgoToShared converts a proto HashAlgorithm to a shared HashAlgorithm.
func protoHashAlgoToShared(ha keymanagerv1.HashAlgorithm) azkv.HashAlgorithm {
	switch ha {
	case keymanagerv1.HashAlgorithm_SHA256:
		return azkv.HashAlgorithmSHA256
	case keymanagerv1.HashAlgorithm_SHA384:
		return azkv.HashAlgorithmSHA384
	case keymanagerv1.HashAlgorithm_SHA512:
		return azkv.HashAlgorithmSHA512
	default:
		return azkv.HashAlgorithmUnspecified
	}
}

// refreshKeysTask periodically refreshes keys in Azure Key Vault.
// Refresh interval is key_ttl / 2 (e.g., if TTL is 336h, refresh every 168h).
// Keys are updated with the same operations (Sign and Verify) to refresh the "Updated" timestamp,
// which prevents them from being considered stale and deleted.
func (p *Plugin) refreshKeysTask(ctx context.Context) {
	// Refresh immediately at startup
	if err := p.refreshKeys(ctx); err != nil {
		p.log.Warn("Failed to refresh keys at startup", "error", err)
	}
	p.notifyRefreshKeys(nil)

	// Calculate refresh interval (50% of TTL)
	refreshInterval := p.keyTTL / 2
	if refreshInterval < minimumRefreshInterval {
		refreshInterval = minimumRefreshInterval
	}

	ticker := p.hooks.clk.Ticker(refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			err := p.refreshKeys(ctx)
			p.notifyRefreshKeys(err)
		}
	}
}

func (p *Plugin) notifyRefreshKeys(err error) {
	if p.hooks.refreshKeysSignal != nil {
		p.hooks.refreshKeysSignal <- err
	}
}

func (p *Plugin) refreshKeys(ctx context.Context) error {
	p.log.Debug("Refreshing keys")

	// Copy entries to local slice while holding lock, then release for network I/O
	p.entriesMtx.RLock()
	entries := make([]keyEntry, 0, len(p.entries))
	for _, entry := range p.entries {
		entries = append(entries, entry)
	}
	p.entriesMtx.RUnlock()

	var errs []string
	for _, entry := range entries {
		keyName := entry.KeyName
		keyVersion := entry.keyVersion

		// Verify key still exists before updating
		_, err := p.keyVaultClient.GetKey(ctx, keyName, keyVersion, nil)
		if err != nil {
			p.log.Warn("failed fetching cached key to refresh it", keyNameTag, keyName, reasonTag, err)
			continue
		}

		// Update the key with the same operations to refresh the Updated timestamp
		_, err = p.keyVaultClient.UpdateKey(ctx, keyName, keyVersion, azkeys.UpdateKeyParameters{
			KeyOps: []*azkeys.JSONWebKeyOperation{to.Ptr(azkeys.JSONWebKeyOperationSign), to.Ptr(azkeys.JSONWebKeyOperationVerify)},
		}, nil)
		if err != nil {
			p.log.Error("Failed to refresh key", "key_id", entry.KeyID, keyNameTag, keyName, reasonTag, err)
			errs = append(errs, fmt.Sprintf("key %q: %v", keyName, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to refresh %d key(s): %s", len(errs), strings.Join(errs, "; "))
	}
	return nil
}

// cleanupStaleKeys runs once at startup (non-blocking) to delete orphaned keys.
// It scans all keys tagged with spire-agent-td matching the trust domain and
// deletes keys where Updated timestamp is older than max(key_ttl, minimumKeyTTL).
func (p *Plugin) cleanupStaleKeys(ctx context.Context) {
	p.log.Debug("Cleaning up stale keys")

	pager := p.keyVaultClient.NewListKeysPager(nil)
	now := p.hooks.clk.Now()

	// Use max(key_ttl, minimumKeyTTL) to prevent single agent with short TTL from deleting all keys
	staleThreshold := p.keyTTL
	if staleThreshold < minimumKeyTTL {
		staleThreshold = minimumKeyTTL
	}
	maxStaleTime := now.Add(-staleThreshold)

	for pager.More() {
		resp, err := pager.NextPage(ctx)
		if err != nil {
			p.log.Error("Failed to list keys for cleanup", reasonTag, err)
			return
		}

		for _, key := range resp.Value {
			// Skip keys that do not belong to this trust domain
			trustDomainTag, hasTD := key.Tags[tagNameAgentTrustDomain]
			if !hasTD || *trustDomainTag != p.trustDomain {
				continue
			}

			// If the key has not been updated for staleThreshold, delete it directly
			updated := key.Attributes.Updated
			if updated.Before(maxStaleTime) {
				keyName := key.KID.Name()
				_, err := p.keyVaultClient.DeleteKey(ctx, keyName, nil)
				if err != nil {
					var respErr *azcore.ResponseError
					if errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound {
						// Key already deleted, which is fine
						p.log.Debug("Stale key already deleted", keyNameTag, keyName)
					} else {
						p.log.Warn("Failed to delete stale key", keyNameTag, keyName, reasonTag, err)
					}
				} else {
					p.log.Debug("Stale key deleted", keyNameTag, keyName)
				}
			}
		}
	}
}
