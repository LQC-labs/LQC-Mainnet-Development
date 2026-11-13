// SPDX-License-Identifier: Apache-2.0
package flowtestassets

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestResolverPolicy(t *testing.T) {
	absent := t.TempDir()
	if _, err := Resolve("", []string{absent}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("optional absence not distinguished", err)
	}
	for _, explicit := range []string{"relative", filepath.Join(absent, "missing"), absent} {
		if _, err := Resolve(explicit, []string{absent}); err == nil || errors.Is(err, ErrUnavailable) {
			t.Fatal("explicit missing/invalid root did not fail", explicit, err)
		}
	}
	root := t.TempDir()
	p := filepath.Join(root, marker)
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve("", []string{root}); err == nil || errors.Is(err, ErrUnavailable) {
		t.Fatal("partial directory silently skipped", err)
	}
	if err := os.WriteFile(p, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := Resolve(root, nil); err != nil || got != root {
		t.Fatal("explicit bundle not selected", got, err)
	}
	if _, err := Resolve(filepath.Join(absent, "missing"), []string{root}); err == nil {
		t.Fatal("explicit root silently fell back")
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(p, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve("", []string{root}); err == nil || errors.Is(err, ErrUnavailable) {
		t.Fatal("malformed existing marker skipped", err)
	}
}
