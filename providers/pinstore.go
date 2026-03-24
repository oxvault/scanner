package providers

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

type pinStore struct {
	dir string // directory to store pins (e.g., .oxvault/)
}

func NewPinStore(dir string) PinStore {
	return &pinStore{dir: dir}
}

func (s *pinStore) Pin(tools []MCPTool) error {
	if err := os.MkdirAll(s.dir, 0755); err != nil {
		return fmt.Errorf("create pin directory: %w", err)
	}

	pins := make(map[string]string, len(tools))
	for _, tool := range tools {
		pins[tool.Name] = hashTool(tool)
	}

	data, err := json.MarshalIndent(pins, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal pins: %w", err)
	}

	path := filepath.Join(s.dir, "pins.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write pins: %w", err)
	}

	return nil
}

func (s *pinStore) Check(tools []MCPTool) ([]PinDiff, error) {
	stored, err := s.Load()
	if err != nil {
		return nil, fmt.Errorf("load pins: %w", err)
	}

	var diffs []PinDiff

	for _, tool := range tools {
		currentHash := hashTool(tool)
		storedHash, exists := stored[tool.Name]

		if !exists {
			diffs = append(diffs, PinDiff{
				ToolName:    tool.Name,
				NewHash:     currentHash,
				Changed:     true,
				Description: "New tool — not in pinned baseline",
			})
			continue
		}

		changed := currentHash != storedHash
		diff := PinDiff{
			ToolName: tool.Name,
			OldHash:  storedHash,
			NewHash:  currentHash,
			Changed:  changed,
		}
		if changed {
			diff.Description = "Tool description or schema changed — possible rug pull"
		}
		diffs = append(diffs, diff)
	}

	// Check for removed tools
	currentNames := make(map[string]bool, len(tools))
	for _, tool := range tools {
		currentNames[tool.Name] = true
	}
	for name, hash := range stored {
		if !currentNames[name] {
			diffs = append(diffs, PinDiff{
				ToolName:    name,
				OldHash:     hash,
				Changed:     true,
				Description: "Tool removed from server",
			})
		}
	}

	return diffs, nil
}

func (s *pinStore) Load() (map[string]string, error) {
	path := filepath.Join(s.dir, "pins.json")

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no pins found — run 'oxvault pin' first")
		}
		return nil, fmt.Errorf("read pins: %w", err)
	}

	var pins map[string]string
	if err := json.Unmarshal(data, &pins); err != nil {
		return nil, fmt.Errorf("parse pins: %w", err)
	}

	return pins, nil
}

// hashTool creates a deterministic SHA-256 hash of a tool's identity.
// Covers name, description, and input schema — any change triggers a rug pull alert.
func hashTool(tool MCPTool) string {
	canonical := struct {
		Name        string         `json:"name"`
		Description string         `json:"description"`
		InputSchema map[string]any `json:"inputSchema"`
	}{
		Name:        tool.Name,
		Description: tool.Description,
		InputSchema: tool.InputSchema,
	}

	data, err := json.Marshal(canonical)
	if err != nil {
		// Fallback to name + description
		data = []byte(tool.Name + tool.Description)
	}

	// Sort keys for determinism
	var normalized any
	if err := json.Unmarshal(data, &normalized); err != nil {
		// If unmarshal fails, fall back to the raw data
		hash := sha256.Sum256(data)
		return fmt.Sprintf("%x", hash)
	}
	sortedData, _ := marshalSorted(normalized)

	hash := sha256.Sum256(sortedData)
	return fmt.Sprintf("%x", hash)
}

// marshalSorted produces deterministic JSON by sorting map keys
func marshalSorted(v any) ([]byte, error) {
	switch val := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		result := []byte("{")
		for i, k := range keys {
			if i > 0 {
				result = append(result, ',')
			}
			keyBytes, _ := json.Marshal(k)
			valBytes, _ := marshalSorted(val[k])
			result = append(result, keyBytes...)
			result = append(result, ':')
			result = append(result, valBytes...)
		}
		result = append(result, '}')
		return result, nil
	default:
		return json.Marshal(v)
	}
}
