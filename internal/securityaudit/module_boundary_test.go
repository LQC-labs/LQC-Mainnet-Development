package securityaudit

import (
	"path/filepath"
	"testing"
)

// Keep the main module free of raw etcd SDK access. P0 custody is a separate
// module and is deliberately not an exception to this production source gate.
func TestMainModuleSDKBoundary(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	report, err := ScanDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range report.Findings {
		t.Error(finding.String())
	}
}
