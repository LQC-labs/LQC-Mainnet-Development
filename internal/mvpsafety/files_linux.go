//go:build linux

package mvpsafety

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
)

type OSInspector struct{}

func (OSInspector) Inspect(p string) (PathInfo, error) {
	st, e := os.Lstat(p)
	if os.IsNotExist(e) {
		return PathInfo{}, nil
	}
	if e != nil {
		return PathInfo{}, e
	}
	return PathInfo{Exists: true, Symlink: st.Mode()&os.ModeSymlink != 0}, nil
}

// FileEvidenceSink never overwrites an earlier result. A failed/partial write
// remains for inspection and cannot authorize another stage.
type FileEvidenceSink struct{ path string }

func NewFileEvidenceSink(plan Plan) (*FileEvidenceSink, error) {
	if !plan.intact() {
		return nil, fmt.Errorf("validated untampered new plan required")
	}
	return &FileEvidenceSink{path: filepath.Join(plan.Root, "evidence", "safety.json")}, nil
}
func (s *FileEvidenceSink) Save(ctx context.Context, r Report) (string, error) {
	if e := ctx.Err(); e != nil {
		return "", e
	}
	data, e := json.MarshalIndent(r, "", "  ")
	if e != nil {
		return "", e
	}
	// Walk parent components without following symlinks.
	parent := filepath.Dir(s.path)
	for cur := parent; ; cur = filepath.Dir(cur) {
		st, e := os.Lstat(cur)
		if e != nil {
			return "", e
		}
		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("unsafe evidence directory")
		}
		if cur == "/" {
			break
		}
	}
	fd, e := unix.Open(s.path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return "", e
	}
	f := os.NewFile(uintptr(fd), s.path)
	defer f.Close()
	if e = ctx.Err(); e != nil {
		return "", e
	}
	if _, e = f.Write(data); e != nil {
		return "", e
	}
	if e = f.Sync(); e != nil {
		return "", e
	}
	if e = f.Close(); e != nil {
		return "", e
	}
	d, e := os.Open(parent)
	if e != nil {
		return "", e
	}
	defer d.Close()
	if e = d.Sync(); e != nil {
		return "", e
	}
	if e = ctx.Err(); e != nil {
		return "", e
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}
