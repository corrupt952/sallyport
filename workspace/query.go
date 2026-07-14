package workspace

import (
	"fmt"
	"os"
	"path/filepath"
)

// CurrentName trusts WORKSPACE_PATH first so it stays correct inside hook
// sessions even when cwd has moved outside the workspace.
func CurrentName() (string, error) {
	if p := os.Getenv("WORKSPACE_PATH"); p != "" {
		return filepath.Base(p), nil
	}
	pwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	if root := FindRoot(pwd); root != "" {
		return filepath.Base(root), nil
	}
	return "", fmt.Errorf("not inside a workspace")
}
