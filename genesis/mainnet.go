// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package genesis

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/LQC-labs/LQC-Mainnet-Development/app"
	chainconfig "github.com/LQC-labs/LQC-Mainnet-Development/chain/config"
	sdk "github.com/cosmos/cosmos-sdk/types"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"
	evmtypes "github.com/cosmos/evm/x/vm/types"
)

// These are input resource limits and a format version, not network parameters.
const MaxMainnetGenesisBytes = 16 << 20
const MaxMainnetConfigBytes = 1 << 20
const MainnetGenesisSchemaVersion = 1

// MainnetDocument is separate from the unchanged test-only Document. All
// network, economic, consensus and validator values must be supplied externally.
type MainnetDocument struct {
	genutiltypes.AppGenesis
	SchemaVersion uint32                    `json:"lqc_schema_version"`
	Profile       chainconfig.RuntimeConfig `json:"lqc_profile"`
}

// LoadedMainnet owns a hash-checked immutable input snapshot. Its constructors
// require an independent expected hash; they never approve or generate one.
type LoadedMainnet struct {
	raw      []byte
	document MainnetDocument
	digest   string
}

func (g *LoadedMainnet) SHA256() string                     { return g.digest }
func (g *LoadedMainnet) Bytes() []byte                      { return bytes.Clone(g.raw) }
func (g *LoadedMainnet) Profile() chainconfig.RuntimeConfig { return g.document.Profile }

type MainnetValidator struct {
	AccountAddress     string `json:"account_address"`
	ConsensusPublicKey string `json:"consensus_public_key"`
	SelfDelegation     string `json:"self_delegation"`
	VotingPower        int64  `json:"voting_power"`
}

// MainnetReport records offline input validation only, never launch approval.
type MainnetReport struct {
	GenesisSHA256  string             `json:"genesis_sha256"`
	ChainID        string             `json:"chain_id"`
	EVMChainID     uint64             `json:"evm_chain_id"`
	NativeDenom    string             `json:"native_denom"`
	DisplayDenom   string             `json:"display_denom"`
	Decimals       uint32             `json:"decimals"`
	TotalSupply    string             `json:"total_supply"`
	Validators     []MainnetValidator `json:"validators"`
	LaunchApproved bool               `json:"launch_approved"`
}

// DecodeMainnetConfig rejects incomplete profiles without filling defaults.
func DecodeMainnetConfig(raw []byte) (chainconfig.RuntimeConfig, error) {
	var cfg chainconfig.RuntimeConfig
	if len(raw) > MaxMainnetConfigBytes {
		return cfg, fmt.Errorf("runtime config exceeds size limit")
	}
	if err := decodeMainnetJSON(raw, &cfg); err != nil {
		return cfg, err
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	if cfg.Chain.NetworkKind != chainconfig.NetworkMainnet {
		return cfg, fmt.Errorf("explicit mainnet profile required")
	}
	return cfg, nil
}

func LoadMainnet(reader io.Reader, cfg chainconfig.RuntimeConfig, expectedSHA256 string) (*LoadedMainnet, error) {
	if reader == nil {
		return nil, fmt.Errorf("Genesis reader required")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.Chain.NetworkKind != chainconfig.NetworkMainnet {
		return nil, fmt.Errorf("explicit mainnet profile required")
	}
	h, err := hex.DecodeString(expectedSHA256)
	if err != nil || len(h) != sha256.Size || hex.EncodeToString(h) != expectedSHA256 {
		return nil, fmt.Errorf("explicit lowercase Genesis SHA-256 required")
	}
	raw, err := io.ReadAll(io.LimitReader(reader, MaxMainnetGenesisBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read Genesis: %w", err)
	}
	if len(raw) > MaxMainnetGenesisBytes {
		return nil, fmt.Errorf("Genesis exceeds size limit")
	}
	digest := sha256.Sum256(raw)
	if !bytes.Equal(digest[:], h) {
		return nil, fmt.Errorf("Genesis SHA-256 mismatch")
	}
	var document MainnetDocument
	if err := decodeMainnetJSON(raw, &document); err != nil {
		return nil, err
	}
	if document.SchemaVersion != MainnetGenesisSchemaVersion || document.Profile != cfg {
		return nil, fmt.Errorf("Genesis schema/profile mismatch")
	}
	if document.ChainID != cfg.Chain.CosmosChainID || len(document.ChainID) > genutiltypes.MaxChainIDLen || document.AppName != app.Name || document.AppVersion != app.Version {
		return nil, fmt.Errorf("Genesis chain/application identity mismatch")
	}
	if document.InitialHeight != 1 || document.GenesisTime.IsZero() || len(document.AppHash) != 0 {
		return nil, fmt.Errorf("explicit time, initial height 1 and empty app hash required")
	}
	if document.Consensus == nil || document.Consensus.Params == nil {
		return nil, fmt.Errorf("explicit consensus parameters required")
	}
	if err := document.Consensus.Params.ValidateBasic(); err != nil {
		return nil, fmt.Errorf("consensus parameters: %w", err)
	}
	// ConsensusGenesis has a custom decoder. Check its keys separately rather
	// than silently accepting fields ignored by that upstream decoder.
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, err
	}
	if err := checkMainnetJSONFields(envelope["consensus"], reflect.TypeOf(genutiltypes.ConsensusGenesis{})); err != nil {
		return nil, err
	}
	// Never call ValidateAndComplete: it can insert a time/height/parameters.
	return &LoadedMainnet{raw: raw, document: document, digest: expectedSHA256}, nil
}

func LoadMainnetFile(path string, cfg chainconfig.RuntimeConfig, expectedSHA256 string) (*LoadedMainnet, error) {
	raw, err := ReadMainnetInputFile(path, MaxMainnetGenesisBytes)
	if err != nil {
		return nil, err
	}
	return LoadMainnet(bytes.NewReader(raw), cfg, expectedSHA256)
}

// ValidateMainnet never calls InitChain, FinalizeBlock, Commit or a node API.
// The hash binds the complete supplied allocations, economics and consensus
// policy; this validation checks technical consistency, not policy approval.
func ValidateMainnet(a *app.App, g *LoadedMainnet) (report *MainnetReport, err error) {
	if a == nil || a.SDK == nil || g == nil {
		return nil, fmt.Errorf("application and loaded Genesis required")
	}
	before := a.SDK.LastCommitID()
	height := a.SDK.LastBlockHeight()
	defer func() {
		if failure := recover(); failure != nil {
			report = nil
			err = fmt.Errorf("invalid mainnet Genesis: %v", failure)
		}
		after := a.SDK.LastCommitID()
		if height != a.SDK.LastBlockHeight() || before.Version != after.Version || !bytes.Equal(before.Hash, after.Hash) {
			report = nil
			err = fmt.Errorf("Genesis validation changed committed state")
		}
	}()
	doc := &g.document
	if a.Profile != doc.Profile || a.SDK.ChainID() != doc.ChainID || sdk.GetConfig().GetBech32AccountAddrPrefix() != doc.Profile.Chain.Bech32Prefix {
		return nil, fmt.Errorf("application runtime profile mismatch")
	}
	ethCfg := evmtypes.GetEthChainConfig()
	if ethCfg == nil || ethCfg.ChainID == nil || !ethCfg.ChainID.IsUint64() || ethCfg.ChainID.Uint64() != doc.Profile.Chain.EVMChainID {
		return nil, fmt.Errorf("runtime EVM chain ID mismatch")
	}
	var state map[string]json.RawMessage
	if err := decodeMainnetJSON(doc.AppState, &state); err != nil {
		return nil, err
	}
	expected := a.SDK.BasicModuleManager.DefaultGenesis(a.SDK.AppCodec())
	for name, raw := range expected {
		if len(raw) == 0 {
			delete(expected, name)
		}
	}
	if len(state) != len(expected) {
		return nil, fmt.Errorf("unexpected or missing Genesis modules")
	}
	for name, defaults := range expected {
		raw := state[name]
		if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil, fmt.Errorf("missing Genesis module %s", name)
		}
		var template, supplied map[string]json.RawMessage
		if err := json.Unmarshal(defaults, &template); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &supplied); err != nil {
			return nil, err
		}
		if _, hasParams := template["params"]; hasParams && (len(supplied["params"]) == 0 || bytes.Equal(bytes.TrimSpace(supplied["params"]), []byte("null"))) {
			return nil, fmt.Errorf("explicit %s params required", name)
		}
	}
	if err := a.SDK.BasicModuleManager.ValidateGenesis(a.SDK.AppCodec(), a.SDK.GetTxConfig(), state); err != nil {
		return nil, fmt.Errorf("module Genesis: %w", err)
	}
	return validateMainnetState(a, doc, state, g.digest)
}

func decodeMainnetJSON(raw []byte, dst interface{}) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := uniqueMainnetJSON(dec, 0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON data")
	}
	dec = json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.Decode(new(interface{})) != io.EOF {
		return fmt.Errorf("trailing JSON data")
	}
	return nil
}

func uniqueMainnetJSON(dec *json.Decoder, depth int) error {
	if depth > 64 {
		return fmt.Errorf("JSON nesting exceeds limit")
	}
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delim != '{' && delim != '[' {
		return fmt.Errorf("invalid JSON delimiter")
	}
	seen := map[string]bool{}
	for dec.More() {
		if delim == '{' {
			key, err := dec.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[strings.ToLower(name)] {
				return fmt.Errorf("duplicate or invalid JSON object key")
			}
			seen[strings.ToLower(name)] = true
		}
		if err := uniqueMainnetJSON(dec, depth+1); err != nil {
			return err
		}
	}
	_, err = dec.Token()
	return err
}

// Check field names without replacing Comet's string-number JSON semantics.
func checkMainnetJSONFields(raw []byte, typ reflect.Type) error {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ.Kind() == reflect.Slice {
		// Comet HexBytes are JSON strings, not arrays. Its decoder validates them.
		if typ.Elem().Kind() == reflect.Uint8 {
			return nil
		}
		var array []json.RawMessage
		if err := json.Unmarshal(raw, &array); err != nil {
			return err
		}
		for _, value := range array {
			if err := checkMainnetJSONFields(value, typ.Elem()); err != nil {
				return err
			}
		}
		return nil
	}
	if typ.Kind() != reflect.Struct || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return err
	}
	fields := map[string]reflect.Type{}
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		fields[name] = field.Type
	}
	for name, value := range object {
		fieldType, ok := fields[name]
		if !ok {
			return fmt.Errorf("unknown consensus field %q", name)
		}
		if err := checkMainnetJSONFields(value, fieldType); err != nil {
			return err
		}
	}
	return nil
}
