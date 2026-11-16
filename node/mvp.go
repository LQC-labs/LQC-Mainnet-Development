//go:build linux

package node

import (
	"fmt"
	"github.com/LQC-labs/LQC-Mainnet-Development/app"
	"github.com/LQC-labs/LQC-Mainnet-Development/genesis"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
)

// OpenMVP is an explicit, separate TEST-only entry. No environment flag,
// Genesis metadata or default Open invocation can activate this path.
func OpenMVP(home string, options genesis.MVPOptions) (*Node, error) {
	validator, err := mvpValidator(home, options)
	if err != nil {
		return nil, err
	}
	return openValidated(home, validator)
}
func mvpValidator(home string, options genesis.MVPOptions) (func(*app.App, []byte, cryptotypes.PubKey) error, error) {
	if err := options.Validate(); err != nil {
		return nil, err
	}
	if home != options.Home {
		return nil, fmt.Errorf("MVP home differs from sealed funding plan")
	}
	return func(a *app.App, raw []byte, stored cryptotypes.PubKey) error {
		actual, err := genesis.MVPConsensusKey(a, options, raw)
		if err != nil {
			return err
		}
		if stored == nil || !actual.Equals(stored) {
			return fmt.Errorf("MVP stored consensus key differs from signed gentx")
		}
		return nil
	}, nil
}
