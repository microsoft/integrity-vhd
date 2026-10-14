package main

import (
	"encoding/json"
	"fmt"
)

// Serialize the full config selected by the layer manifest parser, not its
// rootfs-only projection. Raw JSON must not be encoded as a base64 string.
func encodeImageConfig(config any) (json.RawMessage, error) {
	var data []byte
	var err error
	switch value := config.(type) {
	case json.RawMessage:
		data = value
	case []byte:
		data = value
	default:
		data, err = json.Marshal(value)
	}
	if err != nil {
		return nil, fmt.Errorf("encode image config: %w", err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil || object == nil {
		return nil, fmt.Errorf("image config must be a JSON object")
	}
	return json.RawMessage(data), nil
}
