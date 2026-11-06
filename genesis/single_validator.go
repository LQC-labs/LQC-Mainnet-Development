// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package genesis

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"cosmossdk.io/math"
	"github.com/LQC-labs/LQC-Mainnet-Development/app"
	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cosmos/cosmos-sdk/client/tx"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/cosmos/evm/crypto/ethsecp256k1"
)

// NewSingleValidator creates an isolated TEST-only genesis. Only the account
// key signs the gentx; consensus receives public information only. No key is
// serialized or logged. Callers own key custody and must never use real keys.
func NewSingleValidator(a *app.App, account cryptotypes.PrivKey, consensus cryptotypes.PubKey) ([]byte, error) {
	if account == nil || account.Type() != ethsecp256k1.KeyType || consensus == nil || consensus.Type() != "ed25519" {
		return nil, fmt.Errorf("test eth_secp256k1 account key and separate Ed25519 consensus public key required")
	}
	raw, err := New(a)
	if err != nil {
		return nil, err
	}
	var doc Document
	if err = json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	var state map[string]json.RawMessage
	if err = json.Unmarshal(doc.AppState, &state); err != nil {
		return nil, err
	}
	address := sdk.AccAddress(account.PubKey().Address())
	bond := sdk.DefaultPowerReduction
	funds := sdk.NewCoins(sdk.NewCoin("atest", bond.MulRaw(3)))
	var auth authtypes.GenesisState
	a.SDK.AppCodec().MustUnmarshalJSON(state[authtypes.ModuleName], &auth)
	auth.Accounts, err = authtypes.PackAccounts(authtypes.GenesisAccounts{authtypes.NewBaseAccount(address, account.PubKey(), 0, 0)})
	if err != nil {
		return nil, err
	}
	state[authtypes.ModuleName] = a.SDK.AppCodec().MustMarshalJSON(&auth)
	var bank banktypes.GenesisState
	a.SDK.AppCodec().MustUnmarshalJSON(state[banktypes.ModuleName], &bank)
	bank.Balances = []banktypes.Balance{{Address: address.String(), Coins: funds}}
	bank.Supply = funds
	state[banktypes.ModuleName] = a.SDK.AppCodec().MustMarshalJSON(&bank)
	msg, err := stakingtypes.NewMsgCreateValidator(sdk.ValAddress(address).String(), consensus,
		sdk.NewCoin("atest", bond), stakingtypes.NewDescription("lqc-isolated-test", "", "", "", ""),
		stakingtypes.NewCommissionRates(math.LegacyZeroDec(), math.LegacyOneDec(), math.LegacyOneDec()), math.OneInt())
	if err != nil {
		return nil, err
	}
	builder := a.SDK.GetTxConfig().NewTxBuilder()
	if err = builder.SetMsgs(msg); err != nil {
		return nil, err
	}
	builder.SetGasLimit(3_000_000)
	placeholder := signing.SignatureV2{PubKey: account.PubKey(), Data: &signing.SingleSignatureData{SignMode: signing.SignMode_SIGN_MODE_DIRECT}, Sequence: 0}
	if err = builder.SetSignatures(placeholder); err != nil {
		return nil, err
	}
	sig, err := tx.SignWithPrivKey(context.Background(), signing.SignMode_SIGN_MODE_DIRECT,
		authsigning.SignerData{Address: address.String(), ChainID: doc.ChainID, AccountNumber: 0, Sequence: 0, PubKey: account.PubKey()}, builder, account, a.SDK.GetTxConfig(), 0)
	if err != nil {
		return nil, err
	}
	if err = builder.SetSignatures(sig); err != nil {
		return nil, err
	}
	gentx, err := a.SDK.GetTxConfig().TxJSONEncoder()(builder.GetTx())
	if err != nil {
		return nil, err
	}
	state[genutiltypes.ModuleName] = a.SDK.AppCodec().MustMarshalJSON(&genutiltypes.GenesisState{GenTxs: []json.RawMessage{gentx}})
	doc.AppState, err = json.Marshal(state)
	if err != nil {
		return nil, err
	}
	output, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	output = append(output, '\n')
	return output, ValidateSingleValidator(a, output)
}

type singleValidatorInput struct {
	doc       Document
	account   sdk.AccAddress
	msg       *stakingtypes.MsgCreateValidator
	consensus cryptotypes.PubKey
	funds     sdk.Coins
}

// ValidateSingleValidator checks the signed input without initializing stores.
// It reuses the unchanged draft validator for every unrelated module/profile.
func ValidateSingleValidator(a *app.App, data []byte) error {
	_, err := singleValidatorInputs(a, data)
	return err
}

func singleValidatorInputs(a *app.App, data []byte) (input *singleValidatorInput, err error) {
	defer func() {
		if recover() != nil {
			input = nil
			err = fmt.Errorf("invalid single-validator genesis")
		}
	}()
	var doc Document
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&doc); err != nil {
		return nil, err
	}
	if err = decoder.Decode(new(interface{})); err != io.EOF {
		return nil, fmt.Errorf("trailing genesis data")
	}
	var state map[string]json.RawMessage
	if err = json.Unmarshal(doc.AppState, &state); err != nil {
		return nil, err
	}
	var auth authtypes.GenesisState
	var bank banktypes.GenesisState
	var gen genutiltypes.GenesisState
	cdc := a.SDK.AppCodec()
	if err = cdc.UnmarshalJSON(state[authtypes.ModuleName], &auth); err != nil {
		return nil, err
	}
	if err = cdc.UnmarshalJSON(state[banktypes.ModuleName], &bank); err != nil {
		return nil, err
	}
	if err = cdc.UnmarshalJSON(state[genutiltypes.ModuleName], &gen); err != nil {
		return nil, err
	}
	if len(auth.Accounts) != 1 || len(bank.Balances) != 1 || len(gen.GenTxs) != 1 {
		return nil, fmt.Errorf("exactly one account, balance and gentx required")
	}
	if err = a.SDK.BasicModuleManager.ValidateGenesis(cdc, a.SDK.GetTxConfig(), state); err != nil {
		return nil, fmt.Errorf("module genesis: %w", err)
	}
	accounts, err := authtypes.UnpackAccounts(auth.Accounts)
	if err != nil {
		return nil, err
	}
	acc, ok := accounts[0].(*authtypes.BaseAccount)
	if !ok || acc.GetAccountNumber() != 0 || acc.GetSequence() != 0 {
		return nil, fmt.Errorf("test base account number and sequence must be zero")
	}
	address := acc.GetAddress()
	funds := bank.Balances[0].Coins
	if bank.Balances[0].Address != address.String() || !funds.IsValid() || len(funds) != 1 || funds[0].Denom != "atest" || !funds[0].IsPositive() || !bank.Supply.Equal(funds) || len(bank.SendEnabled) != 0 {
		return nil, fmt.Errorf("inconsistent test balance or supply")
	}
	decoded, err := a.SDK.GetTxConfig().TxJSONDecoder()(gen.GenTxs[0])
	if err != nil {
		return nil, fmt.Errorf("invalid gentx encoding")
	}
	if len(decoded.GetMsgs()) != 1 {
		return nil, fmt.Errorf("exactly one create-validator message required")
	}
	msg, ok := decoded.GetMsgs()[0].(*stakingtypes.MsgCreateValidator)
	if !ok {
		return nil, fmt.Errorf("gentx must create a validator")
	}
	if err = msg.Validate(a.SDK.StakingKeeper.ValidatorAddressCodec()); err != nil {
		return nil, err
	}
	var consensus cryptotypes.PubKey
	if err = cdc.UnpackAny(msg.Pubkey, &consensus); err != nil {
		return nil, err
	}
	if consensus.Type() != "ed25519" || len(consensus.Bytes()) != 32 || msg.ValidatorAddress != sdk.ValAddress(address).String() || msg.Value.Denom != "atest" || msg.Value.Amount.LT(sdk.DefaultPowerReduction) || msg.Value.Amount.GT(funds.AmountOf("atest")) {
		return nil, fmt.Errorf("invalid validator identity, denomination or stake")
	}
	signed, ok := decoded.(authsigning.Tx)
	if !ok {
		return nil, fmt.Errorf("unsigned gentx")
	}
	signatures, err := signed.GetSignaturesV2()
	if err != nil || len(signatures) != 1 {
		return nil, fmt.Errorf("one gentx signature required")
	}
	signature := signatures[0]
	single, ok := signature.Data.(*signing.SingleSignatureData)
	if !ok || single.SignMode != signing.SignMode_SIGN_MODE_DIRECT || signature.Sequence != 0 || signature.PubKey == nil || signature.PubKey.Type() != ethsecp256k1.KeyType || !bytes.Equal(signature.PubKey.Address(), address) || acc.GetPubKey() == nil || !acc.GetPubKey().Equals(signature.PubKey) || !signed.GetFee().IsZero() || signed.GetGas() != 3_000_000 || signed.GetMemo() != "" || signed.GetTimeoutHeight() != 0 {
		return nil, fmt.Errorf("unexpected gentx signer or envelope")
	}
	signBytes, err := authsigning.GetSignBytesAdapter(context.Background(), a.SDK.GetTxConfig().SignModeHandler(), single.SignMode,
		authsigning.SignerData{Address: address.String(), ChainID: doc.ChainID, AccountNumber: 0, Sequence: 0, PubKey: signature.PubKey}, decoded)
	if err != nil || !signature.PubKey.VerifySignature(signBytes, single.Signature) {
		return nil, fmt.Errorf("invalid gentx signature or signing chain ID")
	}
	// Strip only the explicitly allowed account/funding/gentx additions. The
	// original validator still rejects injected staking validators/delegations,
	// consensus validators, EVM allocations, changed metadata and wrong profiles.
	auth.Accounts = nil
	bank.Balances = nil
	bank.Supply = nil
	gen.GenTxs = nil
	state[authtypes.ModuleName] = cdc.MustMarshalJSON(&auth)
	state[banktypes.ModuleName] = cdc.MustMarshalJSON(&bank)
	state[genutiltypes.ModuleName] = cdc.MustMarshalJSON(&gen)
	normalized := doc
	normalized.AppState, err = json.Marshal(state)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(normalized)
	if err != nil {
		return nil, err
	}
	if err = Validate(a, raw); err != nil {
		return nil, err
	}
	return &singleValidatorInput{doc: doc, account: address, msg: msg, consensus: consensus, funds: funds}, nil
}

// VerifySingleValidatorRuntime consumes a FRESH isolated application. It runs
// real gentx delivery through InitChain, never FinalizeBlock/Commit or a node.
// The application must be discarded after success OR failure. EVM globals
// require independent processes for independent runtime verifications.
func VerifySingleValidatorRuntime(a *app.App, data []byte) (err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("single-validator InitChain failed")
		}
	}()
	in, err := singleValidatorInputs(a, data)
	if err != nil {
		return err
	}
	if a.SDK.LastBlockHeight() != 0 {
		return fmt.Errorf("fresh isolated app required")
	}
	before := a.SDK.LastCommitID()
	params := in.doc.Consensus.Params.ToProto()
	response, err := a.SDK.InitChain(&abci.RequestInitChain{ChainId: in.doc.ChainID, Time: in.doc.GenesisTime, InitialHeight: in.doc.InitialHeight, ConsensusParams: &params, AppStateBytes: in.doc.AppState})
	if err != nil {
		return fmt.Errorf("gentx InitChain: %w", err)
	}
	ctx := a.SDK.NewContext(false)
	reduction := a.SDK.StakingKeeper.PowerReduction(ctx)
	power := in.msg.Value.Amount.Quo(reduction).Int64()
	if response == nil || len(response.Validators) != 1 || power <= 0 || response.Validators[0].Power != power || !bytes.Equal(response.Validators[0].PubKey.GetEd25519(), in.consensus.Bytes()) {
		return fmt.Errorf("incorrect InitChain validator update")
	}
	validators, err := a.SDK.StakingKeeper.GetAllValidators(ctx)
	if err != nil || len(validators) != 1 {
		return fmt.Errorf("expected exactly one runtime validator")
	}
	val := validators[0]
	pub, err := val.ConsPubKey()
	if err != nil || !pub.Equals(in.consensus) || val.OperatorAddress != in.msg.ValidatorAddress || val.Status != stakingtypes.Bonded || val.Jailed || !val.Tokens.Equal(in.msg.Value.Amount) {
		return fmt.Errorf("incorrect runtime validator")
	}
	delegations, err := a.SDK.StakingKeeper.GetAllDelegations(ctx)
	if err != nil || len(delegations) != 1 || delegations[0].DelegatorAddress != in.account.String() || delegations[0].ValidatorAddress != val.OperatorAddress || !delegations[0].Shares.Equal(val.DelegatorShares) {
		return fmt.Errorf("incorrect self-delegation")
	}
	bank := a.SDK.BankKeeper
	if !bank.GetBalance(ctx, in.account, "atest").Amount.Equal(in.funds.AmountOf("atest").Sub(val.Tokens)) || !bank.GetBalance(ctx, authtypes.NewModuleAddress(stakingtypes.BondedPoolName), "atest").Amount.Equal(val.Tokens) || !bank.GetSupply(ctx, "atest").Amount.Equal(in.funds.AmountOf("atest")) {
		return fmt.Errorf("runtime bank conservation failed")
	}
	after := a.SDK.LastCommitID()
	if a.SDK.LastBlockHeight() != 0 || before.Version != after.Version || !bytes.Equal(before.Hash, after.Hash) {
		return fmt.Errorf("unexpected block or commit")
	}
	return nil
}
