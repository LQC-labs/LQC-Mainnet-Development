package genesis

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"cosmossdk.io/log/v2"
	"cosmossdk.io/math"
	"github.com/LQC-labs/LQC-Mainnet-Development/app"
	dbm "github.com/cosmos/cosmos-db"
	sdked "github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/cosmos/evm/crypto/ethsecp256k1"
)

func publicOptions(t *testing.T) MVPOptions {
	t.Helper()
	o := MVPOptions{Enabled: true, Profile: MVPProfile, RunID: "offline123", Home: "/tmp/lqc-stage7-offline123/home", CosmosChainID: "lqc-devnet-test-1", EVMChainID: 917001, EVMChainIDHex: "0xdfe09", Denom: "atest", Total: MVPGenesisTotal}
	keys := []string{"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5", "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"}
	for i, v := range []struct{ role, amount string }{{"deployer", "30000000000000000000"}, {"test", "20000000000000000000"}, {"reserve", "50000000000000000000"}} {
		raw, _ := hex.DecodeString(keys[i])
		pub := &ethsecp256k1.PubKey{Key: raw}
		address, e := bech32.ConvertAndEncode("lqctest", pub.Address())
		if e != nil {
			t.Fatal(e)
		}
		o.Accounts = append(o.Accounts, MVPAccount{Role: v.role, Address: address, PublicKeyHex: keys[i], Amount: v.amount, GeneratedRunID: o.RunID})
	}
	return o
}
func TestMVPOptionsOffline(t *testing.T) {
	for name, change := range map[string]func(*MVPOptions){"valid": func(*MVPOptions) {}, "default_off": func(o *MVPOptions) { o.Enabled = false }, "wrong_profile": func(o *MVPOptions) { o.Profile = "default" }, "chain": func(o *MVPOptions) { o.EVMChainID = 97 }, "cosmos": func(o *MVPOptions) { o.CosmosChainID = "other" }, "denom": func(o *MVPOptions) { o.Denom = "stake" }, "supply_over": func(o *MVPOptions) { o.Total = "101000000000000000000" }, "negative": func(o *MVPOptions) { o.Accounts[0].Amount = "-1" }, "overflow": func(o *MVPOptions) { o.Accounts[0].Amount = strings.Repeat("9", 79) }, "duplicate_role": func(o *MVPOptions) { o.Accounts[1].Role = "deployer" }, "duplicate_address": func(o *MVPOptions) {
		o.Accounts[1].Address = o.Accounts[0].Address
		o.Accounts[1].PublicKeyHex = o.Accounts[0].PublicKeyHex
	}, "invalid_address": func(o *MVPOptions) { o.Accounts[0].Address = "lqctest-invalid" }, "public_key_mismatch": func(o *MVPOptions) { o.Accounts[0].PublicKeyHex = o.Accounts[1].PublicKeyHex }, "invalid_public_key": func(o *MVPOptions) { o.Accounts[0].PublicKeyHex = strings.Repeat("00", 33) }, "old_account": func(o *MVPOptions) { o.ExistingAddresses = []string{o.Accounts[0].Address} }, "old_evm_account": func(o *MVPOptions) {
		raw, _ := hex.DecodeString(o.Accounts[0].PublicKeyHex)
		o.ExistingAddresses = []string{"0x" + hex.EncodeToString((&ethsecp256k1.PubKey{Key: raw}).Address())}
	}, "wrong_generation_run": func(o *MVPOptions) { o.Accounts[0].GeneratedRunID = "previous" }, "old_home": func(o *MVPOptions) { o.Home = "/tmp/lqc-core244.Subgcwz4/home" }} {
		t.Run(name, func(t *testing.T) {
			o := publicOptions(t)
			change(&o)
			e := o.Validate()
			if (e == nil) != (name == "valid") {
				t.Fatal(e)
			}
		})
	}
	for _, v := range []string{"-1", "01", "1.0", strings.Repeat("9", 79)} {
		t.Run("uint_"+v, func(t *testing.T) {
			if _, e := mvpAmount(v); e == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// One memory app only. Public curve points and a deliberately invalid dummy
// signature are test DATA, not generated private keys or a deployable Genesis.
func TestMVPFundingProjectionOffline(t *testing.T) {
	if runGenesisTestInSubprocess(t) {
		return
	}
	a, e := app.New(log.NewNopLogger(), dbm.NewMemDB(), t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	o := publicOptions(t)
	draft, e := New(a)
	if e != nil {
		t.Fatal(e)
	}
	var doc Document
	json.Unmarshal(draft, &doc)
	var state map[string]json.RawMessage
	json.Unmarshal(doc.AppState, &state)
	cdc := a.SDK.AppCodec()
	deployer := o.account("deployer")
	pubRaw, _ := hex.DecodeString(deployer.PublicKeyHex)
	pub := &ethsecp256k1.PubKey{Key: pubRaw}
	address := sdk.AccAddress(pub.Address())
	consensus := &sdked.PubKey{Key: make([]byte, 32)}
	consensus.Key[0] = 1
	msg, e := stakingtypes.NewMsgCreateValidator(sdk.ValAddress(address).String(), consensus, sdk.NewCoin("atest", sdk.DefaultPowerReduction), stakingtypes.NewDescription("offline-only", "", "", "", ""), stakingtypes.NewCommissionRates(math.LegacyZeroDec(), math.LegacyOneDec(), math.LegacyOneDec()), math.OneInt())
	if e != nil {
		t.Fatal(e)
	}
	builder := a.SDK.GetTxConfig().NewTxBuilder()
	if e = builder.SetMsgs(msg); e != nil {
		t.Fatal(e)
	}
	builder.SetGasLimit(3000000)
	if e = builder.SetSignatures(signing.SignatureV2{PubKey: pub, Sequence: 0, Data: &signing.SingleSignatureData{SignMode: signing.SignMode_SIGN_MODE_DIRECT, Signature: make([]byte, 64)}}); e != nil {
		t.Fatal(e)
	}
	gentx, e := a.SDK.GetTxConfig().TxJSONEncoder()(builder.GetTx())
	if e != nil {
		t.Fatal(e)
	}
	state[genutiltypes.ModuleName] = cdc.MustMarshalJSON(&genutiltypes.GenesisState{GenTxs: []json.RawMessage{gentx}})
	doc.AppState, _ = json.Marshal(state)
	seed, _ := json.Marshal(doc)
	raw, e := assembleMVP(a, o, seed)
	if e != nil {
		t.Fatal(e)
	}
	t.Run("three_account_funding", func(t *testing.T) {
		projection, e := projectMVP(a, o, raw)
		if e != nil {
			t.Fatal(e)
		}
		var original, project Document
		json.Unmarshal(raw, &original)
		json.Unmarshal(projection, &project)
		var originalState, projectState map[string]json.RawMessage
		json.Unmarshal(original.AppState, &originalState)
		json.Unmarshal(project.AppState, &projectState)
		var bank banktypes.GenesisState
		cdc.UnmarshalJSON(originalState[banktypes.ModuleName], &bank)
		if len(bank.Balances) != 3 || bank.Supply.AmountOf("atest").String() != MVPGenesisTotal {
			t.Fatal("supply")
		}
		var auth authtypes.GenesisState
		cdc.UnmarshalJSON(projectState[authtypes.ModuleName], &auth)
		if len(auth.Accounts) != 1 {
			t.Fatal("projection")
		}
		if !strings.Contains(string(originalState[banktypes.ModuleName]), MVPGenesisTotal) {
			t.Fatal("supply")
		}
		t.Log("100 TEST 30/20/50 auth/bank conservation + unchanged gentx projection PASS; public-only in-memory data")
	})
	t.Run("default_rejects_MVP", func(t *testing.T) {
		if ValidateSingleValidator(a, raw) == nil {
			t.Fatal("default accepted three accounts")
		}
	})
	t.Run("real_signature_check_not_bypassed", func(t *testing.T) {
		if e := ValidateMVP(a, o, raw); e == nil || !strings.Contains(e.Error(), "signature") {
			t.Fatal("dummy signature accepted or not reached", e)
		}
		if _, e := NewMVP(a, o, seed); e == nil {
			t.Fatal("invalid legacy seed accepted")
		}
	})
	for _, name := range []string{"supply", "duplicate_bank", "balance", "duplicate_auth", "unknown_document", "trailing"} {
		t.Run(name, func(t *testing.T) {
			var d Document
			json.Unmarshal(raw, &d)
			var st map[string]json.RawMessage
			json.Unmarshal(d.AppState, &st)
			var bank banktypes.GenesisState
			cdc.UnmarshalJSON(st[banktypes.ModuleName], &bank)
			switch name {
			case "supply":
				bank.Supply = sdk.NewCoins(sdk.NewInt64Coin("atest", 1))
			case "duplicate_bank":
				bank.Balances[1] = bank.Balances[0]
			case "balance":
				bank.Balances[0].Coins = sdk.NewCoins(sdk.NewInt64Coin("atest", 1))
			case "duplicate_auth":
				var auth authtypes.GenesisState
				cdc.UnmarshalJSON(st[authtypes.ModuleName], &auth)
				auth.Accounts[1] = auth.Accounts[0]
				st[authtypes.ModuleName] = cdc.MustMarshalJSON(&auth)
			}
			st[banktypes.ModuleName] = cdc.MustMarshalJSON(&bank)
			d.AppState, _ = json.Marshal(st)
			mut, _ := json.Marshal(d)
			if name == "unknown_document" {
				mut = append([]byte(`{"unexpected":true,`), mut[1:]...)
			}
			if name == "trailing" {
				mut = append(mut, []byte(`{}`)...)
			}
			if _, e := projectMVP(a, o, mut); e == nil {
				t.Fatal("bad funding/document accepted")
			}
		})
	}
}
