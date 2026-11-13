// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package genesis

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"

	"github.com/LQC-labs/LQC-Mainnet-Development/app"
	cmttypes "github.com/cometbft/cometbft/types"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/cosmos/evm/crypto/ethsecp256k1"
)

func validateMainnetGentxs(a *app.App, doc *MainnetDocument, auth authtypes.GenesisState, staking stakingtypes.GenesisState, gen genutiltypes.GenesisState, accounts map[string]*authtypes.BaseAccount, balances map[string]sdk.Coins) ([]MainnetValidator, error) {
	if len(gen.GenTxs) == 0 || uint64(len(gen.GenTxs)) > uint64(staking.Params.MaxValidators) {
		return nil, fmt.Errorf("nonempty gentx set within explicit max_validators required")
	}
	seenOwners := map[string]bool{}
	byKey := map[string]MainnetValidator{}
	validators := []MainnetValidator{}
	var totalPower int64
	for _, raw := range gen.GenTxs {
		decoded, err := a.SDK.GetTxConfig().TxJSONDecoder()(raw)
		if err != nil || len(decoded.GetMsgs()) != 1 {
			return nil, fmt.Errorf("gentx must contain one create-validator message")
		}
		msg, ok := decoded.GetMsgs()[0].(*stakingtypes.MsgCreateValidator)
		if !ok {
			return nil, fmt.Errorf("gentx must create a validator")
		}
		if err := msg.Validate(a.SDK.StakingKeeper.ValidatorAddressCodec()); err != nil {
			return nil, fmt.Errorf("create-validator: %w", err)
		}
		operator, err := sdk.ValAddressFromBech32(msg.ValidatorAddress)
		if err != nil {
			return nil, err
		}
		address := sdk.AccAddress(operator).String()
		account := accounts[address]
		if account == nil || seenOwners[address] || msg.Value.Denom != doc.Profile.Chain.NativeDenom || !msg.Value.IsPositive() || msg.Value.Amount.GT(balances[address].AmountOf(msg.Value.Denom)) || msg.Commission.Rate.LT(staking.Params.MinCommissionRate) {
			return nil, fmt.Errorf("invalid validator owner, funding, stake or commission")
		}
		var consensus cryptotypes.PubKey
		if err := a.SDK.AppCodec().UnpackAny(msg.Pubkey, &consensus); err != nil {
			return nil, err
		}
		if consensus == nil || consensus.Type() != "ed25519" || len(consensus.Bytes()) != 32 {
			return nil, fmt.Errorf("Ed25519 consensus public key required")
		}
		allowed := false
		for _, typ := range doc.Consensus.Params.Validator.PubKeyTypes {
			if typ == consensus.Type() {
				allowed = true
			}
		}
		if !allowed {
			return nil, fmt.Errorf("consensus key type not allowed by parameters")
		}
		key := hex.EncodeToString(consensus.Bytes())
		if _, exists := byKey[key]; exists {
			return nil, fmt.Errorf("duplicate consensus public key")
		}
		power := msg.Value.Amount.Quo(sdk.DefaultPowerReduction)
		if !power.IsInt64() || power.Int64() <= 0 || power.Int64() > cmttypes.MaxTotalVotingPower-totalPower {
			return nil, fmt.Errorf("invalid or excessive consensus voting power")
		}
		signed, ok := decoded.(authsigning.Tx)
		if !ok {
			return nil, fmt.Errorf("signed gentx required")
		}
		if err := signed.ValidateBasic(); err != nil {
			return nil, err
		}
		extensions, ok := decoded.(interface {
			GetExtensionOptions() []*codectypes.Any
			GetNonCriticalExtensionOptions() []*codectypes.Any
		})
		if !ok || len(extensions.GetExtensionOptions()) != 0 || len(extensions.GetNonCriticalExtensionOptions()) != 0 {
			return nil, fmt.Errorf("gentx extensions unsupported")
		}
		if !signed.GetFee().IsZero() || signed.GetGas() == 0 || signed.GetUnordered() || signed.GetTimeoutHeight() != 0 || len(signed.FeeGranter()) != 0 || !bytes.Equal(signed.FeePayer(), operator) || uint64(len([]rune(signed.GetMemo()))) > auth.Params.MaxMemoCharacters {
			return nil, fmt.Errorf("unsupported gentx envelope")
		}
		if gas := doc.Consensus.Params.Block.MaxGas; gas >= 0 && signed.GetGas() > uint64(gas) {
			return nil, fmt.Errorf("gentx gas exceeds consensus block gas limit")
		}
		signers, err := signed.GetSigners()
		if err != nil || len(signers) != 1 || !bytes.Equal(signers[0], operator) {
			return nil, fmt.Errorf("gentx signer/validator mismatch")
		}
		signatures, err := signed.GetSignaturesV2()
		if err != nil || len(signatures) != 1 {
			return nil, fmt.Errorf("one gentx signature required")
		}
		sig := signatures[0]
		single, ok := sig.Data.(*signing.SingleSignatureData)
		if !ok || single.SignMode != signing.SignMode_SIGN_MODE_DIRECT || sig.Sequence != 0 || sig.PubKey == nil || sig.PubKey.Type() != ethsecp256k1.KeyType || !bytes.Equal(sig.PubKey.Address(), operator) || account.GetPubKey() == nil || !account.GetPubKey().Equals(sig.PubKey) {
			return nil, fmt.Errorf("unsupported or inconsistent gentx signer")
		}
		// SDK signature verification uses account number zero at Genesis height.
		signBytes, err := authsigning.GetSignBytesAdapter(context.Background(), a.SDK.GetTxConfig().SignModeHandler(), single.SignMode, authsigning.SignerData{Address: address, ChainID: doc.ChainID, AccountNumber: 0, Sequence: 0, PubKey: sig.PubKey}, decoded)
		if err != nil || !sig.PubKey.VerifySignature(signBytes, single.Signature) {
			return nil, fmt.Errorf("invalid gentx signature or signing chain ID")
		}
		v := MainnetValidator{AccountAddress: address, ConsensusPublicKey: key, SelfDelegation: msg.Value.String(), VotingPower: power.Int64()}
		validators = append(validators, v)
		byKey[key] = v
		seenOwners[address] = true
		totalPower += power.Int64()
	}
	if len(doc.Consensus.Validators) > 0 {
		if len(doc.Consensus.Validators) != len(validators) {
			return nil, fmt.Errorf("declared consensus validator count mismatch")
		}
		seen := map[string]bool{}
		for _, declared := range doc.Consensus.Validators {
			if declared.PubKey == nil || declared.PubKey.Type() != "ed25519" || !bytes.Equal(declared.Address, declared.PubKey.Address()) {
				return nil, fmt.Errorf("invalid declared validator identity")
			}
			key := hex.EncodeToString(declared.PubKey.Bytes())
			actual, exists := byKey[key]
			if !exists || seen[key] || declared.Power != actual.VotingPower {
				return nil, fmt.Errorf("declared consensus key/power mismatch")
			}
			seen[key] = true
		}
	}
	return validators, nil
}
