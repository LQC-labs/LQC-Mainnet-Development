// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0
package genesis

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"testing"

	"cosmossdk.io/log/v2"
	"github.com/LQC-labs/LQC-Mainnet-Development/app"
	abci "github.com/cometbft/cometbft/abci/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/client/tx"
	"github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/cosmos/evm/crypto/ethsecp256k1"
)

func TestSignedSingleValidator(t *testing.T) {
	mode := os.Getenv("LQC_SIGNED_GENTX_CASE")
	if mode == "" {
		for _, name := range []string{"valid", "signature", "signing-chain", "document-chain", "denom", "stake", "balance", "duplicate-gentx", "duplicate-validator"} {
			t.Run(name, func(t *testing.T) {
				command := exec.Command(os.Args[0], "-test.run=^TestSignedSingleValidator$", "-test.v")
				command.Env = append(os.Environ(), "LQC_SIGNED_GENTX_CASE="+name)
				output, err := command.CombinedOutput()
				if err != nil {
					t.Fatalf("case %s failed: %v\n%s", name, err, output)
				}
				t.Log(string(output))
			})
		}
		return
	}
	a, err := app.New(log.NewNopLogger(), dbm.NewMemDB(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := a.Close(); err != nil {
			t.Error(err)
		}
	})
	account, err := ethsecp256k1.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	consensus := ed25519.GenPrivKey() // Separate algorithm/key, only public key enters Genesis.
	raw, err := NewSingleValidator(a, account, consensus.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	if err = Validate(a, raw); err == nil {
		t.Fatal("old draft validator accepted funded Genesis")
	}
	if mode == "valid" {
		if err = VerifySingleValidatorRuntime(a, raw); err != nil {
			t.Fatal(err)
		}
		t.Log("signed gentx InitChain PASS: one bonded validator, positive power, matching public key, self-delegation, bank conservation; no block/commit")
		return
	}
	var doc Document
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var state map[string]json.RawMessage
	if err = json.Unmarshal(doc.AppState, &state); err != nil {
		t.Fatal(err)
	}
	cdc := a.SDK.AppCodec()
	var gen genutiltypes.GenesisState
	cdc.MustUnmarshalJSON(state[genutiltypes.ModuleName], &gen)
	decoded, err := a.SDK.GetTxConfig().TxJSONDecoder()(gen.GenTxs[0])
	if err != nil {
		t.Fatal(err)
	}
	builder, err := a.SDK.GetTxConfig().WrapTxBuilder(decoded)
	if err != nil {
		t.Fatal(err)
	}
	msg := decoded.GetMsgs()[0].(*stakingtypes.MsgCreateValidator)
	signingChain := doc.ChainID
	switch mode {
	case "signature":
		signatures, err := builder.GetTx().GetSignaturesV2()
		if err != nil {
			t.Fatal(err)
		}
		signatures[0].Data.(*signing.SingleSignatureData).Signature[0] ^= 1
		if err = builder.SetSignatures(signatures...); err != nil {
			t.Fatal(err)
		}
	case "signing-chain":
		signingChain = "wrong-devnet-1"
	case "document-chain":
		doc.ChainID = "wrong-devnet-1"
	case "denom":
		msg.Value.Denom = "stake"
	case "stake":
		msg.Value.Amount = sdk.DefaultPowerReduction.SubRaw(1)
	case "balance":
		var bank banktypes.GenesisState
		cdc.MustUnmarshalJSON(state[banktypes.ModuleName], &bank)
		bank.Balances[0].Coins = sdk.NewCoins(sdk.NewCoin("atest", sdk.DefaultPowerReduction.SubRaw(1)))
		bank.Supply = bank.Balances[0].Coins
		state[banktypes.ModuleName] = cdc.MustMarshalJSON(&bank)
	case "duplicate-gentx":
		gen.GenTxs = append(gen.GenTxs, gen.GenTxs[0])
	case "duplicate-validator":
		var staking stakingtypes.GenesisState
		cdc.MustUnmarshalJSON(state[stakingtypes.ModuleName], &staking)
		val, err := stakingtypes.NewValidator(msg.ValidatorAddress, consensus.PubKey(), msg.Description)
		if err != nil {
			t.Fatal(err)
		}
		staking.Validators = []stakingtypes.Validator{val, val}
		state[stakingtypes.ModuleName] = cdc.MustMarshalJSON(&staking)
	default:
		t.Fatal("unknown test mode")
	}
	if mode == "denom" || mode == "stake" || mode == "signing-chain" {
		if err = builder.SetMsgs(msg); err != nil {
			t.Fatal(err)
		}
		sig, err := tx.SignWithPrivKey(context.Background(), signing.SignMode_SIGN_MODE_DIRECT,
			authsigning.SignerData{Address: sdk.AccAddress(account.PubKey().Address()).String(), ChainID: signingChain, PubKey: account.PubKey()}, builder, account, a.SDK.GetTxConfig(), 0)
		if err != nil {
			t.Fatal(err)
		}
		if err = builder.SetSignatures(sig); err != nil {
			t.Fatal(err)
		}
	}
	if mode == "signature" || mode == "denom" || mode == "stake" || mode == "signing-chain" {
		gen.GenTxs[0], err = a.SDK.GetTxConfig().TxJSONEncoder()(builder.GetTx())
		if err != nil {
			t.Fatal(err)
		}
	}
	state[genutiltypes.ModuleName] = cdc.MustMarshalJSON(&gen)
	doc.AppState, err = json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	bad, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidateSingleValidator(a, bad); err == nil {
		t.Fatalf("invalid case %s accepted", mode)
	}
	if err = VerifySingleValidatorRuntime(a, bad); err == nil {
		t.Fatalf("runtime entry accepted %s", mode)
	}
	// Independently exercise the actual SDK gentx ante/message pipeline with
	// malformed signed inputs. Do not rely solely on our input validator.
	if mode == "signature" || mode == "signing-chain" || mode == "denom" || mode == "stake" || mode == "balance" || mode == "duplicate-gentx" {
		params := doc.Consensus.Params.ToProto()
		var initErr error
		func() {
			defer func() {
				if recover() != nil {
					initErr = os.ErrInvalid
				}
			}()
			_, initErr = a.SDK.InitChain(&abci.RequestInitChain{ChainId: doc.ChainID, Time: doc.GenesisTime, InitialHeight: 1, ConsensusParams: &params, AppStateBytes: doc.AppState})
		}()
		if initErr == nil {
			t.Fatalf("SDK InitChain accepted %s", mode)
		}
	}
	t.Logf("%s rejected", mode)
}
