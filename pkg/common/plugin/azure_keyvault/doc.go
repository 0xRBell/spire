// Package azure_keyvault provides shared utilities for Azure Key Vault
// key manager plugins used by both SPIRE server and agent.
//
// This package contains proto-agnostic types and utilities that can be
// used by both server and agent plugins, which use different proto
// packages (server/keymanager/v1 vs agent/keymanager/v1).
//
// The shared components include:
//   - CloudKeyManagementService interface for Azure Key Vault operations
//   - KeyType enum and utilities for key type conversions
//   - Signature conversion utilities (IEEE P1363 to ASN.1/DER)
//   - JWK to raw key conversion
//   - Fingerprint utilities
package azure_keyvault
