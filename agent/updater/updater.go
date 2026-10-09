// Package updater implements agent self-update. The dashboard advertises a
// newer build (version + download URL + SHA-256) over the existing WebSocket
// command channel; the agent downloads it, verifies the hash, and swaps the
// running executable in place via a detached helper script, then restarts.
package updater

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"agentide/core"
)

// Manifest describes an available agent update, as sent by the dashboard.
type Manifest struct {
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
}

const throttleWindow = 10 * time.Minute

// Apply downloads, verifies, and installs an update. It returns nil once the
// replacement helper has been launched; the caller should then let the process
// exit so the helper can overwrite the locked executable.
func Apply(m Manifest, logger *core.Logger) error {
	if m.URL == "" || m.SHA256 == "" {
		return fmt.Errorf("update manifest incomplete (url and sha256 are required)")
	}
	if recentlyAttempted(m.Version) {
		return fmt.Errorf("update to %s was attempted less than %s ago — skipping to avoid a loop", m.Version, throttleWindow)
	}
	recordAttempt(m.Version)

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}
	newPath := exePath + ".new"

	logger.Info("Updater: downloading new agent", map[string]interface{}{
		"version": m.Version, "url": m.URL,
	})

	if err := download(m.URL, newPath); err != nil {
		return fmt.Errorf("download failed: %w", err)
	}

	got, err := sha256File(newPath)
	if err != nil {
		return fmt.Errorf("hash new binary: %w", err)
	}
	if !strings.EqualFold(got, m.SHA256) {
		_ = os.Remove(newPath)
		return fmt.Errorf("sha256 mismatch: expected %s got %s", m.SHA256, got)
	}
	logger.Info("Updater: download verified", map[string]interface{}{"sha256": got})

	if err := swapAndRestart(exePath, newPath, logger); err != nil {
		return fmt.Errorf("launch updater: %w", err)
	}

	logger.Info("Updater: replacement scheduled — agent will restart on the new build", map[string]interface{}{
		"version": m.Version,
	})
	return nil
}

// download fetches url into dest atomically (temp file + rename).
func download(url, dest string) error {
	client := &http.Client{
		Timeout: 5 * time.Minute,
		Transport: &http.Transport{
			// The dashboard uses a self-signed certificate by default
			// (same trust model as the WebSocket connection). Integrity of
			// the payload is guaranteed by the SHA-256 check in Apply.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	tmp := dest + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	_ = os.Remove(dest)
	return os.Rename(tmp, dest)
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func attemptFile() string {
	return filepath.Join(os.TempDir(), "agentide_update_attempt.json")
}

func recentlyAttempted(version string) bool {
	if version == "" {
		return false
	}
	data, err := os.ReadFile(attemptFile())
	if err != nil {
		return false
	}
	var rec struct {
		Version string `json:"version"`
		Unix    int64  `json:"unix"`
	}
	if json.Unmarshal(data, &rec) != nil {
		return false
	}
	return rec.Version == version && time.Since(time.Unix(rec.Unix, 0)) < throttleWindow
}

func recordAttempt(version string) {
	data, _ := json.Marshal(map[string]interface{}{
		"version": version,
		"unix":    time.Now().Unix(),
	})
	_ = os.WriteFile(attemptFile(), data, 0644)
}
