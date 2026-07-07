package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestParseSemver(t *testing.T) {
	tests := []struct {
		in                  string
		major, minor, patch int
	}{
		{"1.2.3", 1, 2, 3},
		{"v1.2.3", 1, 2, 3},
		{"0.4.1", 0, 4, 1},
		{"2", 2, 0, 0},
		{"1.2", 1, 2, 0},
		{"1.2.3-rc1", 1, 2, 3},
		{" v0.4.0 ", 0, 4, 0},
		// Non-numeric components have no digit prefix, so they parse as 0
		// rather than erroring — this only matters for a malformed release
		// tag, which the version comparison then treats as "not newer".
		{"x.y.z", 0, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			major, minor, patch, err := parseSemver(tt.in)
			if err != nil {
				t.Fatalf("parseSemver(%q): unexpected error: %v", tt.in, err)
			}
			if major != tt.major || minor != tt.minor || patch != tt.patch {
				t.Errorf("parseSemver(%q) = %d.%d.%d, want %d.%d.%d", tt.in, major, minor, patch, tt.major, tt.minor, tt.patch)
			}
		})
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"0.4.0", "0.4.1", -1},
		{"0.4.1", "0.4.0", 1},
		{"0.4.1", "0.4.1", 0},
		{"v0.4.1", "0.4.1", 0},
		{"0.4.9", "0.5.0", -1},
		{"0.9.9", "1.0.0", -1},
		{"1.0.0", "0.9.9", 1},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_vs_%s", tt.a, tt.b), func(t *testing.T) {
			got, err := compareVersions(tt.a, tt.b)
			if err != nil {
				t.Fatalf("compareVersions(%q, %q): unexpected error: %v", tt.a, tt.b, err)
			}
			if got != tt.want {
				t.Errorf("compareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestArchiveName(t *testing.T) {
	tests := []struct {
		version, goos, goarch, want string
	}{
		{"0.4.1", "darwin", "arm64", "scanner_0.4.1_darwin_arm64.tar.gz"},
		{"0.4.1", "linux", "amd64", "scanner_0.4.1_linux_amd64.tar.gz"},
		{"0.4.1", "windows", "amd64", "scanner_0.4.1_windows_amd64.zip"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := archiveName(tt.version, tt.goos, tt.goarch)
			if got != tt.want {
				t.Errorf("archiveName(%q, %q, %q) = %q, want %q", tt.version, tt.goos, tt.goarch, got, tt.want)
			}
		})
	}
}

func TestBinaryFileName(t *testing.T) {
	if got := binaryFileName("windows"); got != "oxvault.exe" {
		t.Errorf("binaryFileName(windows) = %q, want oxvault.exe", got)
	}
	if got := binaryFileName("linux"); got != "oxvault" {
		t.Errorf("binaryFileName(linux) = %q, want oxvault", got)
	}
}

func TestVerifyChecksum(t *testing.T) {
	archiveBytes := []byte("fake-archive-contents")
	sum := sha256.Sum256(archiveBytes)
	hexSum := hex.EncodeToString(sum[:])

	checksums := fmt.Appendf(nil, "%s  scanner_0.4.1_linux_amd64.tar.gz\n%s  checksums.txt\n", hexSum, "deadbeef")

	if err := verifyChecksum(archiveBytes, checksums, "scanner_0.4.1_linux_amd64.tar.gz"); err != nil {
		t.Errorf("verifyChecksum: unexpected error: %v", err)
	}

	if err := verifyChecksum([]byte("tampered"), checksums, "scanner_0.4.1_linux_amd64.tar.gz"); err == nil {
		t.Error("verifyChecksum: expected mismatch error, got nil")
	}

	if err := verifyChecksum(archiveBytes, checksums, "scanner_0.4.1_darwin_arm64.tar.gz"); err == nil {
		t.Error("verifyChecksum: expected missing-entry error, got nil")
	}
}

func buildTarGz(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(content))}); err != nil {
		t.Fatalf("write tar header: %v", err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatalf("write tar content: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	return buf.Bytes()
}

func buildZip(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(name)
	if err != nil {
		t.Fatalf("create zip entry: %v", err)
	}
	if _, err := w.Write(content); err != nil {
		t.Fatalf("write zip content: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}
	return buf.Bytes()
}

func TestExtractBinaryFromArchive(t *testing.T) {
	content := []byte("#!/bin/sh\necho fake-binary\n")

	t.Run("tar.gz", func(t *testing.T) {
		data := buildTarGz(t, "oxvault", content)
		got, err := extractBinaryFromArchive(data, "scanner_0.4.1_linux_amd64.tar.gz", "oxvault")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(got, content) {
			t.Errorf("extracted content mismatch: got %q, want %q", got, content)
		}
	})

	t.Run("zip", func(t *testing.T) {
		data := buildZip(t, "oxvault.exe", content)
		got, err := extractBinaryFromArchive(data, "scanner_0.4.1_windows_amd64.zip", "oxvault.exe")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(got, content) {
			t.Errorf("extracted content mismatch: got %q, want %q", got, content)
		}
	})

	t.Run("not found", func(t *testing.T) {
		data := buildTarGz(t, "somethingelse", content)
		if _, err := extractBinaryFromArchive(data, "scanner_0.4.1_linux_amd64.tar.gz", "oxvault"); err == nil {
			t.Error("expected not-found error, got nil")
		}
	})
}

func TestFetchLatestRelease(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/oxvault/scanner/releases/latest" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v0.4.1","assets":[{"name":"scanner_0.4.1_linux_amd64.tar.gz","browser_download_url":"https://example.com/a.tar.gz"}]}`))
	}))
	defer srv.Close()

	rel, err := fetchLatestRelease(srv.Client(), srv.URL, "oxvault/scanner")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rel.TagName != "v0.4.1" {
		t.Errorf("TagName = %q, want v0.4.1", rel.TagName)
	}
	if len(rel.Assets) != 1 || rel.Assets[0].Name != "scanner_0.4.1_linux_amd64.tar.gz" {
		t.Errorf("Assets = %+v, want one matching asset", rel.Assets)
	}
}

func TestFetchLatestRelease_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Not Found"}`))
	}))
	defer srv.Close()

	if _, err := fetchLatestRelease(srv.Client(), srv.URL, "oxvault/scanner"); err == nil {
		t.Error("expected error for 404 response, got nil")
	}
}

func TestReplaceExecutable(t *testing.T) {
	dir := t.TempDir()
	execPath := filepath.Join(dir, "oxvault")

	if err := os.WriteFile(execPath, []byte("old-binary"), 0o755); err != nil {
		t.Fatalf("seed old binary: %v", err)
	}

	newContent := []byte("new-binary")
	if err := replaceExecutable(execPath, newContent); err != nil {
		t.Fatalf("replaceExecutable: unexpected error: %v", err)
	}

	got, err := os.ReadFile(execPath)
	if err != nil {
		t.Fatalf("read replaced binary: %v", err)
	}
	if !bytes.Equal(got, newContent) {
		t.Errorf("replaced binary content = %q, want %q", got, newContent)
	}

	if _, err := os.Stat(execPath + ".old"); !os.IsNotExist(err) {
		t.Errorf("expected .old file to be cleaned up, stat err = %v", err)
	}

	info, err := os.Stat(execPath)
	if err != nil {
		t.Fatalf("stat replaced binary: %v", err)
	}
	if info.Mode().Perm()&0o100 == 0 {
		t.Errorf("replaced binary is not executable: mode %v", info.Mode())
	}
}

func TestEnvOrDefault(t *testing.T) {
	const key = "OXVAULT_TEST_ENV_OR_DEFAULT"
	t.Setenv(key, "")
	if got := envOrDefault(key, "fallback"); got != "fallback" {
		t.Errorf("envOrDefault with unset env = %q, want fallback", got)
	}
	t.Setenv(key, "custom")
	if got := envOrDefault(key, "fallback"); got != "custom" {
		t.Errorf("envOrDefault with set env = %q, want custom", got)
	}
}
