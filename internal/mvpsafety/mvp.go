//go:build linux

package mvpsafety

import (
	"context"
	"fmt"
	"reflect"

	"github.com/LQC-labs/LQC-Mainnet-Development/genesis"
	corenode "github.com/LQC-labs/LQC-Mainnet-Development/node"
)

// MVPRequest contains only a public-key/address funding plan. No private keys,
// generated Genesis, DB, signing state or home files are read or created here.
type MVPRequest struct {
	Home    string
	Options genesis.MVPOptions
	Policy  Policy
	RunID   string
}
type MVPBoundary interface {
	BeforeOpen(context.Context, MVPRequest) error
}
type CoreMVPFactory struct{ Options genesis.MVPOptions }
type MVPTemplateAccount struct {
	Role, Amount                          string
	Address, PublicKeyHex, GeneratedRunID *string
}
type MVPTemplate struct {
	SchemaVersion                             int
	Profile                                   string
	Enabled                                   bool
	CosmosChainID                             string
	EVMChainID                                uint64
	EVMChainIDHex, Denom                      string
	Decimals                                  int
	Total                                     string
	Accounts                                  []MVPTemplateAccount
	Home, RunID                               *string
	BondFromDeployer                          string
	RequiresExplicitOptIn, ProductionApproved bool
}

func (a GoAdapter) template() error {
	var t MVPTemplate
	if e := file(a.Config.root, "config/flow/mvp/genesis-profile.json", &t); e != nil {
		return e
	}
	if t.SchemaVersion != 1 || t.Profile != genesis.MVPProfile || t.Enabled || t.CosmosChainID != CosmosID || t.EVMChainID != EVMID || t.EVMChainIDHex != "0xdfe09" || t.Denom != "atest" || t.Decimals != 18 || t.Total != a.Config.Policy.GenesisTotal || t.Home != nil || t.RunID != nil || t.BondFromDeployer != a.Config.Policy.ValidatorBond || !t.RequiresExplicitOptIn || t.ProductionApproved || len(t.Accounts) != 3 {
		return fmt.Errorf("inactive MVP funding template mismatch")
	}
	seen := map[string]bool{}
	want := map[string]string{}
	for _, v := range a.Config.Policy.Allocations {
		want[v.Role] = v.Amount
	}
	for _, v := range t.Accounts {
		if seen[v.Role] || want[v.Role] != v.Amount || v.Address != nil || v.PublicKeyHex != nil || v.GeneratedRunID != nil {
			return fmt.Errorf("configured/duplicate MVP template account forbidden")
		}
		seen[v.Role] = true
	}
	return nil
}
func (f CoreMVPFactory) SupportsFunding(p Policy) error {
	if e := p.Validate(); e != nil {
		return e
	}
	if e := f.Options.Validate(); e != nil {
		return e
	}
	if f.Options.Total != p.GenesisTotal {
		return fmt.Errorf("MVP funding/policy mismatch")
	}
	return nil
}
func (f CoreMVPFactory) Open(home string) (NodeRuntime, error) {
	return corenode.OpenMVP(home, f.Options)
}

// PrepareMVP reaches the injected pre-Open boundary only. It never calls
// CoreMVPFactory.Open, node.Open, Start, any key generator or home writer.
// Call it as a Coordinator step to retain timeouts, cancellation and evidence.
func (a GoAdapter) PrepareMVP(ctx context.Context, c *Coordinator, plan Plan, optIn bool, accounts []genesis.MVPAccount, boundary MVPBoundary) (MVPRequest, error) {
	fail := func(e error) (MVPRequest, error) { return MVPRequest{}, e }
	if e := a.Config.Validate(); e != nil {
		return fail(e)
	}
	if e := a.template(); e != nil {
		return fail(e)
	}
	if !optIn || !plan.intact() || c == nil || !c.plan.intact() || c.plan.seal != plan.seal || !reflect.DeepEqual(c.p, a.Config.Policy) || boundary == nil {
		return fail(fmt.Errorf("explicit MVP opt-in, unchanged policy, sealed plan and pre-Open boundary required"))
	}
	if e := ctx.Err(); e != nil {
		return fail(e)
	}
	options := genesis.MVPOptions{Enabled: true, Profile: genesis.MVPProfile, RunID: plan.RunID, Home: plan.Home, CosmosChainID: CosmosID, EVMChainID: EVMID, EVMChainIDHex: "0xdfe09", Denom: "atest", Total: a.Config.Policy.GenesisTotal, Accounts: append([]genesis.MVPAccount{}, accounts...), ExistingAddresses: append([]string{}, a.Config.Policy.ExistingAccounts...)}
	if e := (CoreMVPFactory{options}).SupportsFunding(a.Config.Policy); e != nil {
		return fail(e)
	}
	request := MVPRequest{Home: plan.Home, Options: options, Policy: a.Config.Policy, RunID: plan.RunID}
	if e := boundary.BeforeOpen(ctx, request); e != nil {
		return fail(e)
	}
	if e := ctx.Err(); e != nil {
		return fail(e)
	}
	return request, nil
}
