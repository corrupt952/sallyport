package workspace

import (
	"fmt"
	"os"
	"path/filepath"
)

const configTemplate = `{
  // Environment variables applied while inside this workspace.
  // WORKSPACE_PATH is exported automatically.
  "env": {
  },
}
`

// Create writes a sallyport.jsonc template into dir and nothing else; wiring other
// tools stays out of scope so the config file remains the whole contract.
func Create(dir string) error {
	path := filepath.Join(dir, ConfigFileName)
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("already exists: %s", path)
	}
	if err := os.WriteFile(path, []byte(configTemplate), 0o644); err != nil {
		return err
	}
	Ok("created %s", path)
	// The user authored this file a moment ago; asking them to approve their
	// own template would be pure ceremony.
	return Trust(path)
}
