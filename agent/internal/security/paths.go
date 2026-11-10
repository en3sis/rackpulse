package security

import "path/filepath"

func hostPath(root, path string) string {
	if root == "" || root == "/" {
		return path
	}
	return filepath.Join(root, path)
}
