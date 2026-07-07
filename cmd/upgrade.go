package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// upgradeRepo is the GitHub repo releases are checked against. Override with
// $OXVAULT_UPDATE_REPO (and $OXVAULT_UPDATE_API_URL / $OXVAULT_UPDATE_DOWNLOAD_URL
// for the API/asset hosts) to point the command at a scratch repo for testing.
const upgradeRepo = "oxvault/scanner"

// upgradeBinaryName is the archive/zip entry name to extract, matching the
// GoReleaser `builds[0].binary` setting. GoReleaser appends ".exe" for
// windows builds automatically.
const upgradeBinaryName = "oxvault"

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type githubRelease struct {
	TagName string        `json:"tag_name"`
	Assets  []githubAsset `json:"assets"`
}

// newUpgradeCmd builds `oxvault upgrade` — checks GitHub releases for a newer
// version and, unless --check is passed, downloads it, verifies its checksum
// against checksums.txt, and replaces the running binary in place.
func newUpgradeCmd() *cobra.Command {
	var (
		checkOnly bool
		assumeYes bool
	)

	cmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Check for and install the latest oxvault release",
		Long: `Checks GitHub releases for a newer oxvault version and, unless --check is
passed, downloads it, verifies its checksum, and replaces the running binary.

  oxvault upgrade          Check and install (prompts for confirmation)
  oxvault upgrade --check  Only report whether a newer version exists
  oxvault upgrade -y       Install without prompting`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUpgrade(checkOnly, assumeYes)
		},
	}

	cmd.Flags().BoolVar(&checkOnly, "check", false, "Only check for a newer version, don't install it")
	cmd.Flags().BoolVarP(&assumeYes, "yes", "y", false, "Install without confirmation prompt")
	return cmd
}

func runUpgrade(checkOnly, assumeYes bool) error {
	repo := envOrDefault("OXVAULT_UPDATE_REPO", upgradeRepo)
	apiBase := envOrDefault("OXVAULT_UPDATE_API_URL", "https://api.github.com")
	downloadBase := envOrDefault("OXVAULT_UPDATE_DOWNLOAD_URL", "https://github.com")

	client := &http.Client{Timeout: 30 * time.Second}

	rel, err := fetchLatestRelease(client, apiBase, repo)
	if err != nil {
		return fmt.Errorf("check latest release: %w", err)
	}

	current := stripV(version)
	latest := stripV(rel.TagName)

	cmp, err := compareVersions(current, latest)
	if err != nil {
		return fmt.Errorf("compare versions: %w", err)
	}

	bold := color.New(color.Bold)
	green := color.New(color.FgGreen)
	dim := color.New(color.Faint)

	if cmp >= 0 {
		fmt.Fprintf(os.Stderr, "  %s Already on the latest version (%s).\n",
			green.Sprint("✓"), bold.Sprintf("v%s", current))
		return nil
	}

	fmt.Fprintf(os.Stderr, "  Update available: %s → %s\n",
		dim.Sprintf("v%s", current), bold.Sprintf("v%s", latest))

	if checkOnly {
		fmt.Fprintf(os.Stderr, "  Run %s to install.\n", bold.Sprint("oxvault upgrade"))
		return nil
	}

	if !assumeYes && !confirmUpgrade(current, latest) {
		fmt.Fprintln(os.Stderr, "  Aborted.")
		return nil
	}

	archive := archiveName(latest, runtime.GOOS, runtime.GOARCH)
	trimmedDownloadBase := strings.TrimSuffix(downloadBase, "/")
	archiveURL := fmt.Sprintf("%s/%s/releases/download/v%s/%s", trimmedDownloadBase, repo, latest, archive)
	checksumsURL := fmt.Sprintf("%s/%s/releases/download/v%s/checksums.txt", trimmedDownloadBase, repo, latest)

	fmt.Fprintf(os.Stderr, "  Downloading %s...\n", archive)
	archiveBytes, err := downloadAsset(client, archiveURL)
	if err != nil {
		return fmt.Errorf("download %s: %w", archive, err)
	}
	checksumsBytes, err := downloadAsset(client, checksumsURL)
	if err != nil {
		return fmt.Errorf("download checksums.txt: %w", err)
	}
	if err := verifyChecksum(archiveBytes, checksumsBytes, archive); err != nil {
		return fmt.Errorf("verify checksum: %w", err)
	}
	fmt.Fprintf(os.Stderr, "  %s Checksum verified.\n", green.Sprint("✓"))

	binBytes, err := extractBinaryFromArchive(archiveBytes, archive, binaryFileName(runtime.GOOS))
	if err != nil {
		return fmt.Errorf("extract binary: %w", err)
	}

	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate running binary: %w", err)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return fmt.Errorf("resolve running binary path: %w", err)
	}

	if err := replaceExecutable(execPath, binBytes); err != nil {
		return fmt.Errorf("install new binary: %w", err)
	}

	fmt.Fprintf(os.Stderr, "  %s Upgraded %s → %s\n",
		green.Sprint("✓"), dim.Sprintf("v%s", current), bold.Sprintf("v%s", latest))
	return nil
}

// confirmUpgrade prompts on stderr and reads a y/N answer from stdin.
func confirmUpgrade(current, latest string) bool {
	fmt.Fprintf(os.Stderr, "  Install oxvault v%s (current: v%s)? [y/N] ", latest, current)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes"
}

// fetchLatestRelease calls GET {apiBase}/repos/{repo}/releases/latest.
func fetchLatestRelease(client *http.Client, apiBase, repo string) (*githubRelease, error) {
	endpoint := fmt.Sprintf("%s/repos/%s/releases/latest", strings.TrimSuffix(apiBase, "/"), repo)

	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "oxvault-cli/"+version)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get %s: %w", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github api %s: %d\nbody: %s", endpoint, resp.StatusCode, snippet(body, 512))
	}

	var rel githubRelease
	if err := json.Unmarshal(body, &rel); err != nil {
		return nil, fmt.Errorf("parse release json: %w", err)
	}
	return &rel, nil
}

// downloadAsset GETs a URL and returns the body, following redirects (the
// default http.Client behavior) — GitHub release assets 302 to
// objects.githubusercontent.com.
func downloadAsset(client *http.Client, url string) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: status %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 256<<20))
}

// archiveName mirrors the GoReleaser archives.name_template
// ("{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}"). ProjectName
// defaults to the repo name ("scanner"), not the "oxvault" binary name —
// see scripts/install.sh, which hits the same real release assets.
func archiveName(version, goos, goarch string) string {
	ext := "tar.gz"
	if goos == "windows" {
		ext = "zip"
	}
	return fmt.Sprintf("scanner_%s_%s_%s.%s", version, goos, goarch, ext)
}

// binaryFileName is the archive entry to extract for the given OS.
func binaryFileName(goos string) string {
	if goos == "windows" {
		return upgradeBinaryName + ".exe"
	}
	return upgradeBinaryName
}

// verifyChecksum checks archiveBytes' SHA-256 against the matching line in
// checksums.txt (GoReleaser's `sha256sum`-format output: "<hex>  <filename>").
func verifyChecksum(archiveBytes, checksumsTxt []byte, archiveName string) error {
	sum := sha256.Sum256(archiveBytes)
	actual := hex.EncodeToString(sum[:])

	scanner := bufio.NewScanner(bytes.NewReader(checksumsTxt))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 || fields[1] != archiveName {
			continue
		}
		if fields[0] != actual {
			return fmt.Errorf("checksum mismatch for %s: expected %s, got %s", archiveName, fields[0], actual)
		}
		return nil
	}
	return fmt.Errorf("no checksum entry found for %s", archiveName)
}

// extractBinaryFromArchive pulls binName out of a .tar.gz or .zip archive,
// matched by the format implied by archiveName's extension.
func extractBinaryFromArchive(archiveBytes []byte, archiveName, binName string) ([]byte, error) {
	if strings.HasSuffix(archiveName, ".zip") {
		return extractFromZip(archiveBytes, binName)
	}
	return extractFromTarGz(archiveBytes, binName)
}

func extractFromTarGz(data []byte, binName string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("open gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar entry: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg || filepath.Base(hdr.Name) != binName {
			continue
		}
		return io.ReadAll(io.LimitReader(tr, 512<<20))
	}
	return nil, fmt.Errorf("%s not found in archive", binName)
}

func extractFromZip(data []byte, binName string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}
	for _, f := range zr.File {
		if filepath.Base(f.Name) != binName {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("open zip entry: %w", err)
		}
		defer func() { _ = rc.Close() }()
		return io.ReadAll(io.LimitReader(rc, 512<<20))
	}
	return nil, fmt.Errorf("%s not found in archive", binName)
}

// replaceExecutable atomically swaps execPath for newBinary: the current
// binary is renamed aside (a running process keeps its open inode on Unix,
// and this dodges Windows' can't-overwrite-a-running-exe lock), the new one
// is renamed into place, then the aside copy is best-effort removed.
func replaceExecutable(execPath string, newBinary []byte) error {
	dir := filepath.Dir(execPath)
	tmp, err := os.CreateTemp(dir, ".oxvault-upgrade-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() // no-op once renamed into place

	if _, err := tmp.Write(newBinary); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp binary: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp binary: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		return fmt.Errorf("chmod temp binary: %w", err)
	}

	oldPath := execPath + ".old"
	_ = os.Remove(oldPath)
	if err := os.Rename(execPath, oldPath); err != nil {
		return fmt.Errorf("move current binary aside: %w", err)
	}
	if err := os.Rename(tmpPath, execPath); err != nil {
		_ = os.Rename(oldPath, execPath) // best-effort restore
		return fmt.Errorf("install new binary: %w", err)
	}
	_ = os.Remove(oldPath)
	return nil
}

// compareVersions returns -1/0/1 for a<b, a==b, a>b, comparing major.minor.patch.
func compareVersions(a, b string) (int, error) {
	aMaj, aMin, aPat, err := parseSemver(a)
	if err != nil {
		return 0, err
	}
	bMaj, bMin, bPat, err := parseSemver(b)
	if err != nil {
		return 0, err
	}
	for _, pair := range [3][2]int{{aMaj, bMaj}, {aMin, bMin}, {aPat, bPat}} {
		if pair[0] != pair[1] {
			if pair[0] < pair[1] {
				return -1, nil
			}
			return 1, nil
		}
	}
	return 0, nil
}

// parseSemver reads up to three dot-separated numeric components from a
// version string, stopping each component at its first non-digit character
// so suffixes like "1-rc1" parse as 1. Missing trailing components are 0.
func parseSemver(v string) (major, minor, patch int, err error) {
	v = stripV(v)
	parts := strings.SplitN(v, ".", 3)
	nums := make([]int, 3)
	for i := 0; i < len(parts) && i < 3; i++ {
		digits := parts[i]
		for j, r := range digits {
			if r < '0' || r > '9' {
				digits = digits[:j]
				break
			}
		}
		if digits == "" {
			continue
		}
		n, cerr := strconv.Atoi(digits)
		if cerr != nil {
			return 0, 0, 0, fmt.Errorf("parse version %q: %w", v, cerr)
		}
		nums[i] = n
	}
	return nums[0], nums[1], nums[2], nil
}

func stripV(v string) string {
	return strings.TrimPrefix(strings.TrimSpace(v), "v")
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
