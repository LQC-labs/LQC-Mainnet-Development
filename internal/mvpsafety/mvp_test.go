package mvpsafety

import (
	"context"
	"encoding/hex"
	"errors"
	"github.com/LQC-labs/LQC-Mainnet-Development/genesis"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	"github.com/cosmos/evm/crypto/ethsecp256k1"
	"testing"
)

func mvpPublicAccounts(t *testing.T, run string) []genesis.MVPAccount {
	t.Helper()
	keys := []string{"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5", "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"}
	accounts := []genesis.MVPAccount{}
	for i, v := range []struct{ role, amount string }{{"deployer", "30000000000000000000"}, {"test", "20000000000000000000"}, {"reserve", "50000000000000000000"}} {
		raw, _ := hex.DecodeString(keys[i])
		address, e := bech32.ConvertAndEncode("lqctest", (&ethsecp256k1.PubKey{Key: raw}).Address())
		if e != nil {
			t.Fatal(e)
		}
		accounts = append(accounts, genesis.MVPAccount{Role: v.role, Address: address, PublicKeyHex: keys[i], Amount: v.amount, GeneratedRunID: run})
	}
	return accounts
}

type fakeMVPBoundary struct {
	calls   int
	request MVPRequest
	err     error
}

func (f *fakeMVPBoundary) BeforeOpen(ctx context.Context, r MVPRequest) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	f.calls++
	f.request = r
	return f.err
}
func TestMVPAdapterOffline(t *testing.T) {
	for _, name := range []string{"valid_to_preOpen", "not_opted_in", "old_account", "wrong_generation_run", "supply_over", "wrong_chain", "changed_policy", "tampered_plan", "cancelled", "boundary_failure"} {
		t.Run(name, func(t *testing.T) {
			cfg := config(t)
			co, _ := coordinator(t)
			a := GoAdapter{Config: cfg}
			p := co.plan
			accounts := mvpPublicAccounts(t, p.RunID)
			boundary := &fakeMVPBoundary{}
			opt := true
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch name {
			case "not_opted_in":
				opt = false
			case "old_account":
				a.Config.Policy.ExistingAccounts = []string{accounts[0].Address}
				co.p = a.Config.Policy
			case "wrong_generation_run":
				accounts[0].GeneratedRunID = "oldrun123"
			case "supply_over":
				accounts[0].Amount = "31000000000000000000"
			case "wrong_chain":
				a.Config.Policy.EVMChainID = 97
			case "changed_policy":
				a.Config.Policy.MaxGasPerTx = 4999999
			case "tampered_plan":
				p.Home = "/tmp/old"
			case "cancelled":
				cancel()
			case "boundary_failure":
				boundary.err = errors.New("fake preOpen failure")
			}
			var request MVPRequest
			report, e := co.Run(ctx, []Step{{Name: "MVP-public-config-preOpen", Run: func(ctx context.Context) error {
				var err error
				request, err = a.PrepareMVP(ctx, co, p, opt, accounts, boundary)
				return err
			}}})
			if name == "valid_to_preOpen" {
				if e != nil || report.Status != "PASS" || boundary.calls != 1 {
					t.Fatal(report, e, boundary)
				}
				if request.Options.Total != genesis.MVPGenesisTotal || request.Home != p.Home || len(request.Options.Accounts) != 3 {
					t.Fatal(request)
				}
				if e = (CoreMVPFactory{request.Options}).SupportsFunding(cfg.Policy); e != nil {
					t.Fatal(e)
				}
				if request.Policy.TotalSeconds != 240 || request.Policy.MaxGasPerTx != 5000000 || request.Policy.MintACap != "1000000000000000000000" || request.Policy.MintBCap != "1000000000" || request.Policy.WrapperDepositCap != "10000000000000000000" {
					t.Fatal("safety limits changed")
				}
				t.Log("MVP 100 TEST/3 public accounts handed to fake immediately-before-Open boundary; real Open/Start/keys/home: zero calls")
			} else {
				if e == nil || report.Status != "BLOCKED" {
					t.Fatal(report, e)
				}
				if name != "boundary_failure" && boundary.calls != 0 {
					t.Fatal("invalid plan reached boundary")
				}
			}
			t.Logf("status=%s preOpenCalls=%d errors=%v", report.Status, boundary.calls, report.Errors)
		})
	}
}
func TestMVPDefaultFactoryRemainsLegacy(t *testing.T) {
	if !errors.Is((CoreNodeFactory{}).SupportsFunding(config(t).Policy), ErrLegacyGenesis) {
		t.Fatal("default factory changed")
	}
	t.Log("legacy factory still rejects MVP funding; only explicit CoreMVPFactory accepts validated MVP options")
}
