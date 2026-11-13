//go:build linux

// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	chainconfig "github.com/LQC-labs/LQC-Mainnet-Development/chain/config"
	"github.com/LQC-labs/LQC-Mainnet-Development/genesis"
	"github.com/LQC-labs/LQC-Mainnet-Development/node"
	"github.com/spf13/cobra"
)

func startCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "start", Short: "Run a prepared isolated loopback test node; public Mainnet unavailable", Args: cobra.NoArgs}
	cmd.Flags().String("network", "", "Required explicit devnet or mainnet profile kind")
	cmd.Flags().String("config", "", "Required absolute runtime JSON path")
	cmd.Flags().String("genesis", "", "Required absolute Genesis path; must match prepared home")
	cmd.Flags().String("expected-genesis-sha256", "", "Required independently supplied Genesis SHA-256")
	cmd.Flags().String("home", "", "Required prepared absolute private test home; never initialized here")
	cmd.Flags().Bool("local-test-only", false, "Required acknowledgement of isolated loopback test scope")
	cmd.Flags().String("comet-rpc-listen", "127.0.0.1:26657", "Numeric loopback Comet RPC listener")
	cmd.Flags().String("p2p-listen", "127.0.0.1:26656", "Numeric loopback P2P listener")
	cmd.Flags().String("role", "validator", "Explicit validator or non-signing fullnode role")
	cmd.Flags().Bool("enable-p2p", false, "Enable explicit local peers; legacy single-validator mode remains default")
	cmd.Flags().String("seeds", "", "Explicit nodeID@127.0.0.1:port bootstrap peers; no PEX discovery")
	cmd.Flags().String("persistent-peers", "", "Explicit local persistent peers")
	cmd.Flags().Int("max-inbound-peers", 0, "Explicit local inbound peer limit")
	cmd.Flags().Int("max-outbound-peers", 0, "Explicit local outbound peer limit")
	cmd.Flags().String("evm-rpc-listen", "", "Optional numeric loopback EVM RPC listener; disabled when empty")
	cmd.Flags().Bool("preflight-only", false, "Internal fresh-process validation without opening prepared DBs")
	_ = cmd.Flags().MarkHidden("preflight-only")
	cmd.RunE = func(cmd *cobra.Command, _ []string) (err error) {
		get := func(name string) string { value, _ := cmd.Flags().GetString(name); return value }
		network, configPath, home := get("network"), get("config"), get("home")
		local, _ := cmd.Flags().GetBool("local-test-only")
		if !local || home == "" || configPath == "" || get("genesis") == "" || get("expected-genesis-sha256") == "" || (network != "devnet" && network != "mainnet") {
			return fmt.Errorf("explicit --network, --config, --genesis, --expected-genesis-sha256, --home and --local-test-only required; public Mainnet unavailable")
		}
		raw, err := genesis.ReadMainnetInputFile(configPath, genesis.MaxMainnetConfigBytes)
		if err != nil {
			return err
		}
		profile, err := node.DecodeRuntimeConfig(raw, chainconfig.NetworkKind(network))
		if err != nil {
			return err
		}
		options := node.RuntimeOptions{Network: chainconfig.NetworkKind(network), Profile: profile, GenesisPath: get("genesis"), ExpectedGenesisSHA256: get("expected-genesis-sha256"), LocalTestOnly: local, CometRPCListen: get("comet-rpc-listen"), P2PListen: get("p2p-listen"), EVMRPCListen: get("evm-rpc-listen")}
		options.Role = node.NodeRole(get("role"))
		options.EnableP2P, _ = cmd.Flags().GetBool("enable-p2p")
		options.Seeds = get("seeds")
		options.PersistentPeers = get("persistent-peers")
		options.MaxInboundPeers, _ = cmd.Flags().GetInt("max-inbound-peers")
		options.MaxOutboundPeers, _ = cmd.Flags().GetInt("max-outbound-peers")
		preflightOnly, _ := cmd.Flags().GetBool("preflight-only")
		if preflightOnly {
			result, err := node.PreflightRuntime(home, options)
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
		}
		ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		// A separate executable avoids configuring SDK/EVM globals twice and
		// rejects bad Genesis semantics before the parent opens a persistent DB.
		binary, err := os.Executable()
		if err != nil {
			return err
		}
		args := []string{"start", "--network", network, "--config", configPath, "--genesis", options.GenesisPath, "--expected-genesis-sha256", options.ExpectedGenesisSHA256, "--home", home, "--local-test-only", "--comet-rpc-listen", options.CometRPCListen, "--p2p-listen", options.P2PListen, "--evm-rpc-listen", options.EVMRPCListen, "--preflight-only"}
		args = append(args, "--role", string(options.Role), "--enable-p2p="+fmt.Sprint(options.EnableP2P), "--seeds", options.Seeds, "--persistent-peers", options.PersistentPeers, "--max-inbound-peers", fmt.Sprint(options.MaxInboundPeers), "--max-outbound-peers", fmt.Sprint(options.MaxOutboundPeers))
		child := exec.CommandContext(ctx, binary, args...)
		var output bytes.Buffer
		child.Stdout = &output
		child.Stderr = cmd.ErrOrStderr()
		if err := child.Run(); err != nil {
			return fmt.Errorf("runtime preflight failed: %w", err)
		}
		var result node.RuntimePreflightResult
		dec := json.NewDecoder(&output)
		dec.DisallowUnknownFields()
		encoded, _ := json.Marshal(profile)
		digest := sha256.Sum256(encoded)
		if dec.Decode(&result) != nil || dec.Decode(new(interface{})) != io.EOF || !result.LocalTestOnly || result.Role != string(options.EffectiveRole()) || result.GenesisSHA256 != options.ExpectedGenesisSHA256 || result.ChainID != profile.Chain.CosmosChainID || result.ProfileSHA256 != hex.EncodeToString(digest[:]) {
			return fmt.Errorf("invalid runtime preflight result")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := node.OpenRuntime(home, options)
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, n.Close()) }()
		if err := n.Start(ctx); err != nil {
			return err
		}
		address := ""
		if get("evm-rpc-listen") != "" {
			address, err = n.StartEVMRPC(ctx, get("evm-rpc-listen"))
			if err != nil {
				return err
			}
		}
		if err := json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]interface{}{"status": "running-local-test-only", "role": options.EffectiveRole(), "p2p_enabled": options.EnableP2P, "chain_id": profile.Chain.CosmosChainID, "evm_chain_id": profile.Chain.EVMChainID, "genesis_sha256": options.ExpectedGenesisSHA256, "evm_rpc_address": address, "public_mainnet_available": false}); err != nil {
			return err
		}
		return n.Wait(ctx)
	}
	return cmd
}
