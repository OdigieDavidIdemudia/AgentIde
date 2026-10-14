package modules

import "strings"

// joinStrings joins a slice of strings with a separator.
func joinStrings(strs []string, sep string) string {
	return strings.Join(strs, sep)
}