// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package genesis

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// rejectDuplicateJSONKeys rejects ambiguous JSON object members at every depth.
// Standard encoding/json otherwise accepts the last duplicate field.
func rejectDuplicateJSONKeys(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	if err := scanUniqueJSONValue(d); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON data")
	}
	return nil
}

func scanUniqueJSONValue(d *json.Decoder) error {
	t, err := d.Token()
	if err != nil {
		return err
	}
	start, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch start {
	case '{':
		seen := make(map[string]struct{})
		for d.More() {
			keyToken, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("invalid JSON object key")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}
			if err := scanUniqueJSONValue(d); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := scanUniqueJSONValue(d); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter")
	}
	end, err := d.Token()
	if err != nil {
		return err
	}
	closing, ok := end.(json.Delim)
	if !ok || (start == '{' && closing != '}') || (start == '[' && closing != ']') {
		return fmt.Errorf("unbalanced JSON container")
	}
	return nil
}
