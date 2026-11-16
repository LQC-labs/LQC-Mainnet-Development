//go:build linux

package mvpsafety

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"

	"github.com/LQC-labs/LQC-Mainnet-Development/app"
	"github.com/LQC-labs/LQC-Mainnet-Development/genesis"
	abci "github.com/cometbft/cometbft/abci/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
)

type EntryAccount struct {
	Role, Address, PublicKeyHex, Balance string
	Sequence                             uint64
}
type EntryValidator struct {
	Operator, PublicKeyHex, Tokens, Shares string
	Power                                  int64
	Bonded, Jailed                         bool
}
type EntryDelegation struct{ Delegator, Operator, Shares string }
type EntryState struct {
	CosmosChainID                       string
	EVMChainID                          uint64
	Denom, Supply, BondedBalance        string
	Height, VersionBefore, VersionAfter int64
	HashBefore, HashAfter               []byte
	Accounts                            []EntryAccount
	Validators, Updates                 []EntryValidator
	Delegations                         []EntryDelegation
}
type MVPEntryBackend interface {
	VerifySignedGenesis(context.Context, MVPRequest, []byte) error
	InitAndObserve(context.Context, MVPRequest, []byte) (EntryState, error)
}

// MVPEntryStep is the supported bounded coordinator connection. The caller
// registers its disposable-app/process cleanup resource before Run. Direct
// backend method calls do not establish any overall-runtime safety claim.
func MVPEntryStep(c *Coordinator, r MVPRequest, raw []byte, key string, b MVPEntryBackend) (Step, error) {
	if c == nil || !c.plan.intact() || r.Home != c.plan.Home || r.RunID != c.plan.RunID || !reflect.DeepEqual(r.Policy, c.p) || b == nil {
		return Step{}, fmt.Errorf("entry/coordinator binding required")
	}
	if e := r.Options.Validate(); e != nil {
		return Step{}, e
	}
	return Step{Name: "MVP-signed-gentx-InitChain-observation", Run: func(ctx context.Context) error { _, e := VerifyMVPEntry(ctx, r, raw, key, b); return e }}, nil
}

// VerifyMVPEntry is intended for a disposable in-memory app, NOT for an app
// already owned by a live node. Fake backends are the ONLY backends run by tests.
func VerifyMVPEntry(ctx context.Context, r MVPRequest, raw []byte, consensusHex string, b MVPEntryBackend) (EntryState, error) {
	if e := r.Policy.Validate(); e != nil {
		return EntryState{}, e
	}
	if e := r.Options.Validate(); e != nil {
		return EntryState{}, e
	}
	if r.RunID != r.Options.RunID || r.Home != r.Options.Home || r.Policy.GenesisTotal != r.Options.Total || b == nil {
		return EntryState{}, fmt.Errorf("entry request binding")
	}
	if e := ctx.Err(); e != nil {
		return EntryState{}, e
	}
	if e := b.VerifySignedGenesis(ctx, r, raw); e != nil {
		return EntryState{}, fmt.Errorf("signed Genesis verification failed")
	}
	if e := ctx.Err(); e != nil {
		return EntryState{}, e
	}
	state, e := b.InitAndObserve(ctx, r, raw)
	if e != nil {
		return state, e
	}
	if e = ctx.Err(); e != nil {
		return state, e
	}
	return state, CheckMVPEntryState(r, state, consensusHex)
}
func CheckMVPEntryState(r MVPRequest, s EntryState, key string) error {
	if e := r.Policy.Validate(); e != nil {
		return e
	}
	if e := r.Options.Validate(); e != nil {
		return e
	}
	pub, e := hex.DecodeString(key)
	if e != nil || len(pub) != 32 {
		return fmt.Errorf("consensus public key required")
	}
	if s.CosmosChainID != CosmosID || s.EVMChainID != EVMID || s.Denom != "atest" || s.Supply != r.Options.Total || s.BondedBalance != r.Policy.ValidatorBond || s.Height != 0 || s.VersionBefore != s.VersionAfter || !bytes.Equal(s.HashBefore, s.HashAfter) {
		return fmt.Errorf("InitChain identity/supply/commit conservation")
	}
	if len(s.Accounts) != 3 || len(s.Validators) != 1 || len(s.Updates) != 1 || len(s.Delegations) != 1 {
		return fmt.Errorf("runtime cardinality")
	}
	want := map[string]genesis.MVPAccount{}
	for _, a := range r.Options.Accounts {
		want[a.Role] = a
	}
	seen := map[string]bool{}
	for _, a := range s.Accounts {
		expected, ok := want[a.Role]
		amount := expected.Amount
		if a.Role == "deployer" {
			amount = "29000000000000000000"
		}
		if !ok || seen[a.Role] || a.Address != expected.Address || a.PublicKeyHex != expected.PublicKeyHex || a.Balance != amount {
			return fmt.Errorf("runtime account/key/balance mismatch")
		}
		seen[a.Role] = true
	}
	_, address, e := bech32.DecodeAndConvert(want["deployer"].Address)
	if e != nil {
		return e
	}
	operator, e := bech32.ConvertAndEncode("lqctestvaloper", address)
	if e != nil {
		return e
	}
	v, u, d := s.Validators[0], s.Updates[0], s.Delegations[0]
	shares, ok := new(big.Rat).SetString(v.Shares)
	if !ok || shares.Sign() <= 0 || v.Operator != operator || v.PublicKeyHex != key || v.Tokens != r.Policy.ValidatorBond || v.Power != 1 || !v.Bonded || v.Jailed || u.PublicKeyHex != key || u.Power != 1 || d.Delegator != want["deployer"].Address || d.Operator != operator || d.Shares != v.Shares {
		return fmt.Errorf("runtime validator/update/self-delegation mismatch")
	}
	return nil
}

// SDKEntryBackend is compile-bound to the pinned ABCI/SDK API. Its methods are
// not invoked by offline tests. InitChain is NOT part of node.Open/OpenMVP;
// a live node's Start handshake owns its own InitChain in a DIFFERENT app.
type SDKEntryBackend struct {
	App                         *app.App
	ApprovedDisposableMemoryApp bool
}

func (b SDKEntryBackend) VerifySignedGenesis(ctx context.Context, r MVPRequest, raw []byte) error {
	if !b.ApprovedDisposableMemoryApp {
		return fmt.Errorf("separate disposable-memory InitChain approval required")
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	return genesis.ValidateMVP(b.App, r.Options, raw)
}
func (b SDKEntryBackend) InitAndObserve(ctx context.Context, r MVPRequest, raw []byte) (EntryState, error) {
	var s EntryState
	if !b.ApprovedDisposableMemoryApp {
		return s, fmt.Errorf("separate disposable-memory InitChain approval required")
	}
	if e := ctx.Err(); e != nil {
		return s, e
	}
	a := b.App
	if a == nil || a.SDK.LastBlockHeight() != 0 {
		return s, fmt.Errorf("fresh disposable memory app required")
	}
	if e := genesis.ValidateMVP(a, r.Options, raw); e != nil {
		return s, e
	}
	var doc genesis.Document
	if e := json.Unmarshal(raw, &doc); e != nil {
		return s, e
	}
	before := a.SDK.LastCommitID()
	params := doc.Consensus.Params.ToProto()
	response, e := a.SDK.InitChain(&abci.RequestInitChain{ChainId: doc.ChainID, Time: doc.GenesisTime, InitialHeight: doc.InitialHeight, ConsensusParams: &params, AppStateBytes: doc.AppState})
	if e != nil {
		return s, e
	}
	if e = ctx.Err(); e != nil {
		return s, e
	}
	if response == nil {
		return s, fmt.Errorf("missing InitChain response")
	}
	sdkctx := a.SDK.NewContext(false)
	after := a.SDK.LastCommitID()
	s = EntryState{CosmosChainID: doc.ChainID, EVMChainID: a.Profile.Chain.EVMChainID, Denom: a.Profile.Chain.NativeDenom, Supply: a.SDK.BankKeeper.GetSupply(sdkctx, "atest").Amount.String(), BondedBalance: a.SDK.BankKeeper.GetBalance(sdkctx, authtypes.NewModuleAddress(stakingtypes.BondedPoolName), "atest").Amount.String(), Height: a.SDK.LastBlockHeight(), VersionBefore: before.Version, VersionAfter: after.Version, HashBefore: append([]byte{}, before.Hash...), HashAfter: append([]byte{}, after.Hash...)}
	for _, v := range r.Options.Accounts {
		address, e := sdk.AccAddressFromBech32(v.Address)
		if e != nil {
			return s, e
		}
		account := a.SDK.AccountKeeper.GetAccount(sdkctx, address)
		if account == nil || account.GetPubKey() == nil {
			return s, fmt.Errorf("missing runtime public account")
		}
		s.Accounts = append(s.Accounts, EntryAccount{Role: v.Role, Address: account.GetAddress().String(), PublicKeyHex: hex.EncodeToString(account.GetPubKey().Bytes()), Balance: a.SDK.BankKeeper.GetBalance(sdkctx, address, "atest").Amount.String(), Sequence: account.GetSequence()})
	}
	validators, e := a.SDK.StakingKeeper.GetAllValidators(sdkctx)
	if e != nil {
		return s, e
	}
	for _, v := range validators {
		pub, e := v.ConsPubKey()
		if e != nil {
			return s, e
		}
		s.Validators = append(s.Validators, EntryValidator{Operator: v.OperatorAddress, PublicKeyHex: hex.EncodeToString(pub.Bytes()), Tokens: v.Tokens.String(), Shares: v.DelegatorShares.String(), Power: v.ConsensusPower(a.SDK.StakingKeeper.PowerReduction(sdkctx)), Bonded: v.Status == stakingtypes.Bonded, Jailed: v.Jailed})
	}
	for _, v := range response.Validators {
		s.Updates = append(s.Updates, EntryValidator{PublicKeyHex: hex.EncodeToString(v.PubKey.GetEd25519()), Power: v.Power})
	}
	delegations, e := a.SDK.StakingKeeper.GetAllDelegations(sdkctx)
	if e != nil {
		return s, e
	}
	for _, v := range delegations {
		s.Delegations = append(s.Delegations, EntryDelegation{Delegator: v.DelegatorAddress, Operator: v.ValidatorAddress, Shares: v.Shares.String()})
	}
	return s, ctx.Err()
}
