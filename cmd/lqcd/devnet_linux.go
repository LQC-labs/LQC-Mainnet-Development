//go:build linux

// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/LQC-labs/LQC-Mainnet-Development/app"
	"github.com/LQC-labs/LQC-Mainnet-Development/node"
	"github.com/spf13/cobra"
)

func addDevnetCommands(root *cobra.Command) {
	devnet := &cobra.Command{Use: "devnet", Short: "Prepare an isolated single-validator TEST Devnet"}
	var newHome string
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Prepare a NEW TEST Devnet home with persistent validator keys",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !filepath.IsAbs(newHome) {
				return fmt.Errorf("explicit absolute NEW test --home required")
			}
			if err := withGenesisApp(func(a *app.App) error {
				return node.InitDevnetHome(a, newHome)
			}); err != nil {
				return err
			}
			_, err := fmt.Fprintln(cmd.OutOrStdout(), newHome)
			return err
		},
	}
	initCmd.Flags().StringVar(&newHome, "home", "", "New absolute TEST Devnet home; parent must exist")
	devnet.AddCommand(initCmd)
	root.AddCommand(devnet, startDevnetCommand())
}

func startDevnetCommand() *cobra.Command {
	var home string
	var testDevnet, evmRPC bool
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Run a prepared isolated TEST Devnet node on loopback",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) (err error) {
			if !testDevnet {
				return fmt.Errorf("explicit --test-devnet is required")
			}
			if !filepath.IsAbs(home) {
				return fmt.Errorf("explicit absolute existing test --home required")
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			if err = ctx.Err(); err != nil {
				return err
			}
			n, err := node.Open(home)
			if err != nil {
				return err
			}
			defer func() { err = errors.Join(err, n.Close()) }()
			if err = n.Start(ctx); err != nil {
				return err
			}
			if evmRPC {
				address, rpcErr := n.StartEVMRPC(ctx, "127.0.0.1:8545")
				if rpcErr != nil {
					return fmt.Errorf("start TEST Devnet EVM RPC: %w", rpcErr)
				}
				if _, err = fmt.Fprintf(cmd.OutOrStdout(), "EVM RPC ready at http://%s\n", address); err != nil {
					return err
				}
			}
			<-ctx.Done()
			return nil
		},
	}
	cmd.Flags().BoolVar(&testDevnet, "test-devnet", false, "Explicitly select the isolated TEST Devnet")
	cmd.Flags().StringVar(&home, "home", "", "Absolute home prepared by lqcd devnet init")
	cmd.Flags().BoolVar(&evmRPC, "evm-rpc", false, "Enable the TEST Devnet EVM JSON-RPC at 127.0.0.1:8545")
	return cmd
}
