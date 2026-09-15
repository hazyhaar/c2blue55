package main

import (
	"bytes"
	"encoding/json"
)

func validEnvelope(data []byte) bool {
	var object map[string]json.RawMessage
	if json.Unmarshal(data, &object) != nil || object == nil {
		return false
	}
	var version string
	if json.Unmarshal(object["jsonrpc"], &version) != nil || version != "2.0" {
		return false
	}
	for key := range object {
		switch key {
		case "jsonrpc", "id", "method", "params", "result", "error":
		default:
			return false
		}
	}
	var method string
	if raw, exists := object["method"]; exists {
		if json.Unmarshal(raw, &method) != nil || method == "" {
			return false
		}
	}
	if method == "tools/call" {
		var params map[string]json.RawMessage
		if json.Unmarshal(object["params"], &params) != nil || params == nil {
			return false
		}
		for key := range params {
			switch key {
			case "name", "arguments", "_meta":
			default:
				return false
			}
		}
	}
	return true
}

// Reject duplicate decoded keys at every depth, including tool arguments.
func uniqueJSON(data []byte) bool {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value func(int) bool
	value = func(depth int) bool {
		if depth > 128 {
			return false
		}
		t, err := d.Token()
		if err != nil {
			return false
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return true
		}
		seen := map[string]bool{}
		for d.More() {
			if delim == '{' {
				key, err := d.Token()
				if err != nil {
					return false
				}
				s, ok := key.(string)
				if !ok || seen[s] {
					return false
				}
				seen[s] = true
			}
			if !value(depth + 1) {
				return false
			}
		}
		_, err = d.Token()
		return err == nil
	}
	return value(0)
}

func validCall(method, id, name, args []byte, hasID bool) bool {
	if hasID && (len(id) == 0 || (id[0] != '"' && id[0] != '-' && (id[0] < '0' || id[0] > '9') && string(id) != "null")) {
		return false
	}
	if string(method) == "tools/call" {
		return len(name) != 0 && len(args) != 0 && args[0] == '{'
	}
	return true
}
