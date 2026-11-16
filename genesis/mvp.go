package genesis

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"path/filepath"
	"regexp"
	"strings"

	"cosmossdk.io/math"
	"github.com/LQC-labs/LQC-Mainnet-Development/app"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"
	"github.com/cosmos/evm/crypto/ethsecp256k1"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
)

const MVPProfile = "lqc-mvp-isolated-v1"
const MVPGenesisTotal = "100000000000000000000"

type MVPAccount struct{ Role, Address, PublicKeyHex, Amount, GeneratedRunID string }

// Options are explicit caller inputs, never inferred from a home or env var.
// Public keys only: key creation/custody belongs to a separately approved run.
type MVPOptions struct {
	Enabled                                                          bool
	Profile, RunID, Home, CosmosChainID, EVMChainIDHex, Denom, Total string
	EVMChainID                                                       uint64
	Accounts                                                         []MVPAccount
	ExistingAddresses                                                []string
}

var mvpID = regexp.MustCompile(`^[a-z0-9]{8,32}$`)
var mvpInteger = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

func mvpDocument(raw []byte) (Document, error) {
	var doc Document
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(&doc); e != nil {
		return doc, e
	}
	if e := d.Decode(new(any)); e != io.EOF {
		return doc, fmt.Errorf("trailing MVP document")
	}
	return doc, nil
}
func mvpAmount(s string) (math.Int, error) {
	if len(s) > 78 || !mvpInteger.MatchString(s) {
		return math.Int{}, fmt.Errorf("canonical unsigned amount required")
	}
	n, ok := new(big.Int).SetString(s, 10)
	if !ok || n.BitLen() > 256 {
		return math.Int{}, fmt.Errorf("uint256 overflow")
	}
	return math.NewIntFromBigInt(n), nil
}
func (o MVPOptions) Validate() error {
	if !o.Enabled || o.Profile != MVPProfile {
		return fmt.Errorf("explicit MVP opt-in required")
	}
	if !mvpID.MatchString(o.RunID) || o.Home != filepath.Join("/tmp", "lqc-stage7-"+o.RunID, "home") {
		return fmt.Errorf("isolated run/home binding required")
	}
	if o.CosmosChainID != "lqc-devnet-test-1" || o.EVMChainID != 917001 || o.EVMChainIDHex != "0xdfe09" || o.Denom != "atest" || o.Total != MVPGenesisTotal {
		return fmt.Errorf("fixed MVP chain/100 TEST cap required")
	}
	if len(o.Accounts) != 3 {
		return fmt.Errorf("three fresh accounts required")
	}
	want := map[string]string{"deployer": "30000000000000000000", "test": "20000000000000000000", "reserve": "50000000000000000000"}
	roles, addresses := map[string]bool{}, map[string]bool{}
	sum := new(big.Int)
	for _, a := range o.Accounts {
		if roles[a.Role] || want[a.Role] != a.Amount || a.GeneratedRunID != o.RunID {
			return fmt.Errorf("duplicate role, allocation or generation run mismatch")
		}
		roles[a.Role] = true
		amount, e := mvpAmount(a.Amount)
		if e != nil {
			return e
		}
		sum.Add(sum, amount.BigInt())
		if sum.BitLen() > 256 {
			return fmt.Errorf("allocation sum overflow")
		}
		prefix, address, e := bech32.DecodeAndConvert(a.Address)
		canonical, _ := bech32.ConvertAndEncode("lqctest", address)
		if e != nil || prefix != "lqctest" || len(address) != 20 || canonical != a.Address {
			return fmt.Errorf("canonical lqctest address required")
		}
		if addresses[a.Address] {
			return fmt.Errorf("duplicate account")
		}
		addresses[a.Address] = true
		raw, e := hex.DecodeString(a.PublicKeyHex)
		if e != nil || len(raw) != 33 {
			return fmt.Errorf("compressed account public key required")
		}
		if _, e = gethcrypto.DecompressPubkey(raw); e != nil {
			return fmt.Errorf("invalid secp256k1 public key")
		}
		key := &ethsecp256k1.PubKey{Key: raw}
		if !bytes.Equal(key.Address(), address) {
			return fmt.Errorf("account/public key mismatch")
		}
		for _, old := range o.ExistingAddresses {
			if old == a.Address || strings.EqualFold(old, "0x"+hex.EncodeToString(address)) {
				return fmt.Errorf("existing account reuse forbidden")
			}
		}
	}
	if sum.String() != MVPGenesisTotal {
		return fmt.Errorf("supply mismatch or policy cap exceeded")
	}
	return nil
}
func (o MVPOptions) account(role string) MVPAccount {
	for _, a := range o.Accounts {
		if a.Role == role {
			return a
		}
	}
	return MVPAccount{}
}

// NewMVP reuses a genuinely signed legacy seed/gentx without generating keys,
// touching a home or re-signing. The caller must supply new-run public keys.
func NewMVP(a *app.App, o MVPOptions, signedSeed []byte) ([]byte, error) {
	if e := o.Validate(); e != nil {
		return nil, e
	}
	if a == nil {
		return nil, fmt.Errorf("app required")
	}
	if e := ValidateSingleValidator(a, signedSeed); e != nil {
		return nil, e
	}
	raw, e := assembleMVP(a, o, signedSeed)
	if e != nil {
		return nil, e
	}
	return raw, ValidateMVP(a, o, raw)
}
func assembleMVP(a *app.App, o MVPOptions, seed []byte) ([]byte, error) {
	if e := o.Validate(); e != nil {
		return nil, e
	}
	doc, e := mvpDocument(seed)
	if e != nil {
		return nil, e
	}
	var state map[string]json.RawMessage
	if e := json.Unmarshal(doc.AppState, &state); e != nil {
		return nil, e
	}
	cdc := a.SDK.AppCodec()
	var auth authtypes.GenesisState
	var bank banktypes.GenesisState
	if e := cdc.UnmarshalJSON(state[authtypes.ModuleName], &auth); e != nil {
		return nil, e
	}
	if e := cdc.UnmarshalJSON(state[banktypes.ModuleName], &bank); e != nil {
		return nil, e
	}
	accounts := authtypes.GenesisAccounts{}
	bank.Balances = nil
	for _, role := range []string{"deployer", "test", "reserve"} {
		v := o.account(role)
		address, e := sdk.AccAddressFromBech32(v.Address)
		if e != nil {
			return nil, e
		}
		pub, _ := hex.DecodeString(v.PublicKeyHex)
		accounts = append(accounts, authtypes.NewBaseAccount(address, &ethsecp256k1.PubKey{Key: pub}, 0, 0))
		amount, _ := mvpAmount(v.Amount)
		bank.Balances = append(bank.Balances, banktypes.Balance{Address: v.Address, Coins: sdk.NewCoins(sdk.NewCoin(o.Denom, amount))})
	}
	auth.Accounts, e = authtypes.PackAccounts(accounts)
	if e != nil {
		return nil, e
	}
	total, _ := mvpAmount(o.Total)
	bank.Supply = sdk.NewCoins(sdk.NewCoin(o.Denom, total))
	state[authtypes.ModuleName] = cdc.MustMarshalJSON(&auth)
	state[banktypes.ModuleName] = cdc.MustMarshalJSON(&bank)
	doc.AppState, e = json.Marshal(state)
	if e != nil {
		return nil, e
	}
	return json.MarshalIndent(doc, "", "  ")
}

// projectMVP checks ALL three auth/bank accounts first, then produces an
// in-memory one-account projection solely for unchanged legacy signature,
// gentx and unrelated-module validation. Original input is never rewritten.
func projectMVP(a *app.App, o MVPOptions, raw []byte) ([]byte, error) {
	if e := o.Validate(); e != nil {
		return nil, e
	}
	if a == nil {
		return nil, fmt.Errorf("app required")
	}
	doc, e := mvpDocument(raw)
	if e != nil {
		return nil, e
	}
	var state map[string]json.RawMessage
	if e := json.Unmarshal(doc.AppState, &state); e != nil {
		return nil, e
	}
	cdc := a.SDK.AppCodec()
	var auth authtypes.GenesisState
	var bank banktypes.GenesisState
	var gen genutiltypes.GenesisState
	if e := cdc.UnmarshalJSON(state[authtypes.ModuleName], &auth); e != nil {
		return nil, e
	}
	if e := cdc.UnmarshalJSON(state[banktypes.ModuleName], &bank); e != nil {
		return nil, e
	}
	if e := cdc.UnmarshalJSON(state[genutiltypes.ModuleName], &gen); e != nil {
		return nil, e
	}
	if len(auth.Accounts) != 3 || len(bank.Balances) != 3 || len(gen.GenTxs) != 1 {
		return nil, fmt.Errorf("MVP account/balance/gentx cardinality")
	}
	if e := a.SDK.BasicModuleManager.ValidateGenesis(cdc, a.SDK.GetTxConfig(), state); e != nil {
		return nil, fmt.Errorf("MVP module genesis invalid: %w", e)
	}
	accounts, e := authtypes.UnpackAccounts(auth.Accounts)
	if e != nil {
		return nil, e
	}
	want := map[string]MVPAccount{}
	for _, v := range o.Accounts {
		want[v.Address] = v
	}
	seen := map[string]bool{}
	var deployer authtypes.GenesisAccount
	for _, account := range accounts {
		v, ok := want[account.GetAddress().String()]
		base, baseOK := account.(*authtypes.BaseAccount)
		if !ok || !baseOK || seen[v.Address] || base.GetAccountNumber() != 0 || base.GetSequence() != 0 || base.GetPubKey() == nil || base.GetPubKey().Type() != ethsecp256k1.KeyType {
			return nil, fmt.Errorf("MVP auth account mismatch")
		}
		pub, _ := hex.DecodeString(v.PublicKeyHex)
		if !bytes.Equal(base.GetPubKey().Bytes(), pub) {
			return nil, fmt.Errorf("MVP account key mismatch")
		}
		seen[v.Address] = true
		if v.Role == "deployer" {
			deployer = base
		}
	}
	seen = map[string]bool{}
	sum := new(big.Int)
	for _, balance := range bank.Balances {
		v, ok := want[balance.Address]
		if !ok || seen[balance.Address] || !balance.Coins.IsValid() || len(balance.Coins) != 1 || balance.Coins[0].Denom != "atest" || balance.Coins[0].Amount.String() != v.Amount {
			return nil, fmt.Errorf("MVP bank amount/address mismatch")
		}
		seen[balance.Address] = true
		sum.Add(sum, balance.Coins[0].Amount.BigInt())
		if sum.BitLen() > 256 {
			return nil, fmt.Errorf("MVP bank overflow")
		}
	}
	if sum.String() != o.Total || !bank.Supply.IsValid() || len(bank.Supply) != 1 || bank.Supply[0].Denom != "atest" || bank.Supply[0].Amount.String() != o.Total || len(bank.SendEnabled) != 0 {
		return nil, fmt.Errorf("MVP supply conservation failed")
	}
	d := o.account("deployer")
	auth.Accounts, e = authtypes.PackAccounts(authtypes.GenesisAccounts{deployer})
	if e != nil {
		return nil, e
	}
	n, _ := mvpAmount(d.Amount)
	bank.Balances = []banktypes.Balance{{Address: d.Address, Coins: sdk.NewCoins(sdk.NewCoin("atest", n))}}
	bank.Supply = bank.Balances[0].Coins
	state[authtypes.ModuleName] = cdc.MustMarshalJSON(&auth)
	state[banktypes.ModuleName] = cdc.MustMarshalJSON(&bank)
	doc.AppState, e = json.Marshal(state)
	if e != nil {
		return nil, e
	}
	return json.Marshal(doc)
}
func ValidateMVP(a *app.App, o MVPOptions, raw []byte) (err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("invalid MVP genesis")
		}
	}()
	projected, e := projectMVP(a, o, raw)
	if e != nil {
		return e
	}
	in, e := singleValidatorInputs(a, projected)
	if e != nil {
		return e
	}
	if in.msg.Value.Amount.String() != "1000000000000000000" || in.account.String() != o.account("deployer").Address {
		return fmt.Errorf("exact 1 TEST bond from deployer required")
	}
	return nil
}
func MVPConsensusKey(a *app.App, o MVPOptions, raw []byte) (cryptotypes.PubKey, error) {
	if e := ValidateMVP(a, o, raw); e != nil {
		return nil, e
	}
	projected, e := projectMVP(a, o, raw)
	if e != nil {
		return nil, e
	}
	in, e := singleValidatorInputs(a, projected)
	if e != nil {
		return nil, e
	}
	return in.consensus, nil
}
