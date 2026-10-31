package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// pinnedChecksums are the SHA-256 sums of the frp v0.71.1 release archives,
// from frp_sha256_checksums.txt, embedded so the default install does not
// trust a checksum file fetched from the same place as the archive.
var pinnedChecksums = map[string]string{
	"darwin_amd64":  "8acb59b6fb998cc8d209d1373d90bf70fa5ec3efeb4dfbc7bda6ce3abd78cb45",
	"darwin_arm64":  "d15d0324b99e14619c9aa46e37f6db588c06a09be4bc6f7948890b6b61077842",
	"linux_amd64":   "1d9875210972a5d1a62b2dc4c48df45ab0af05d3ca1b5e494a014428259df803",
	"linux_arm64":   "8edf590b0c396fa42f9c147121a76af83cfc2002b08f5aef0ea1008c43482019",
	"windows_amd64": "b90074b2b6a1d792a7a40f085ac6d276bcab2d1bc60201f8a86ca53ce65ce821",
	"windows_arm64": "6c25afb4058f7708937db7064836fec593e941de0e6c2c255982335a9b16d370",
}

// githubBaseURL and githubAPIURL are overridden in tests.
var (
	githubBaseURL = "https://github.com/fatedier/frp/releases/download"
	githubAPIURL  = "https://api.github.com/repos/fatedier/frp/releases/latest"
)

// binDir is where install-frpc puts frpc: per-user, outside PATH, one
// directory per version so an upgrade never replaces a binary in use.
//
//	Linux    $XDG_DATA_HOME/nordray-tunnel/frp/v<version> (default ~/.local/share)
//	macOS    ~/Library/Application Support/nordray-tunnel/frp/v<version>
//	Windows  %AppData%\nordray-tunnel\frp\v<version>
var binDir = func(version string) (string, error) {
	base := os.Getenv("XDG_DATA_HOME")
	if base == "" && runtime.GOOS == "linux" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "share")
	}
	if base == "" {
		var err error
		if base, err = os.UserConfigDir(); err != nil {
			return "", err
		}
	}
	return filepath.Join(base, "nordray-tunnel", "frp", "v"+version), nil
}

func frpcName() string { return exeName("frpc") }

func exeName(base string) string {
	if runtime.GOOS == "windows" {
		return base + ".exe"
	}
	return base
}

// installedFrpc returns the path of an installed frpc of the given version.
func installedFrpc(version string) string {
	dir, err := binDir(version)
	if err != nil {
		return ""
	}
	p := filepath.Join(dir, frpcName())
	if _, err := os.Stat(p); err != nil {
		return ""
	}
	return p
}

func cmdInstallFrpc(args []string) error {
	fs, _ := newFlags("install-frpc", "[--version VERSION|latest] [-o DIR] [--frps]")
	version := fs.String("version", frpVersion, "frp `version` to install; the default is the version nordray-tunnel is tested with, \"latest\" asks GitHub")
	out := fs.String("o", "", "install into this `directory` instead of the per-user default")
	withFrps := fs.Bool("frps", false, "also install frps (for local tests; agents only need frpc)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	names := []string{"frpc"}
	if *withFrps {
		names = append(names, "frps")
	}
	paths, err := installFrp(strings.TrimPrefix(*version, "v"), *out, names)
	if err != nil {
		return err
	}
	for _, p := range paths {
		fmt.Println("Installed", p)
	}
	if *out == "" {
		fmt.Println("nordray-tunnel run uses it automatically; --frpc overrides it.")
	}
	return nil
}

// installFrpc installs frpc into the per-user default directory.
func installFrpc(version string) (string, error) {
	paths, err := installFrp(version, "", []string{"frpc"})
	if err != nil {
		return "", err
	}
	return paths[0], nil
}

// installFrp downloads one frp release archive, verifies it and extracts
// the named binaries into dir (default: binDir for the version).
func installFrp(version, dir string, names []string) ([]string, error) {
	client := &http.Client{Timeout: 5 * time.Minute}
	if version == "latest" {
		var rel struct {
			TagName string `json:"tag_name"`
		}
		resp, err := client.Get(githubAPIURL)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&rel) != nil || rel.TagName == "" {
			return nil, fmt.Errorf("could not resolve the latest frp release (HTTP %d)", resp.StatusCode)
		}
		version = strings.TrimPrefix(rel.TagName, "v")
	}
	platform := runtime.GOOS + "_" + runtime.GOARCH
	ext := ".tar.gz"
	if runtime.GOOS == "windows" {
		ext = ".zip"
	}
	archive := fmt.Sprintf("frp_%s_%s%s", version, platform, ext)
	base := fmt.Sprintf("%s/v%s/", githubBaseURL, version)

	want := ""
	if version == frpVersion {
		want = pinnedChecksums[platform]
	}
	if want == "" {
		fmt.Fprintf(os.Stderr, "warning: frp %s is not the version nordray-tunnel is tested with (%s); its checksum comes from the same release\n", version, frpVersion)
		sum, err := releaseChecksum(client, base+"frp_sha256_checksums.txt", archive)
		if err != nil {
			return nil, err
		}
		want = sum
	}

	if dir == "" {
		var err error
		if dir, err = binDir(version); err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(dir, "download-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	fmt.Printf("Downloading %s...\n", base+archive)
	resp, err := client.Get(base + archive)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: HTTP %d", archive, resp.StatusCode)
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, 200<<20)); err != nil {
		return nil, err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return nil, fmt.Errorf("checksum mismatch for %s: got %s, want %s", archive, got, want)
	}
	var paths []string
	for _, n := range names {
		if _, err := tmp.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		out := filepath.Join(dir, exeName(n))
		if err := extractBinary(tmp, ext, exeName(n), out); err != nil {
			return nil, err
		}
		paths = append(paths, out)
	}
	return paths, nil
}

func releaseChecksum(client *http.Client, url, archive string) (string, error) {
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download checksums: HTTP %d", resp.StatusCode)
	}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if f := strings.Fields(sc.Text()); len(f) == 2 && f[1] == archive {
			return f[0], nil
		}
	}
	return "", fmt.Errorf("no checksum for %s in the release", archive)
}

// extractBinary copies one named binary out of the verified archive.
func extractBinary(f *os.File, ext, name, out string) error {
	var src io.Reader
	switch ext {
	case ".zip":
		fi, err := f.Stat()
		if err != nil {
			return err
		}
		zr, err := zip.NewReader(f, fi.Size())
		if err != nil {
			return err
		}
		for _, zf := range zr.File {
			if path.Base(zf.Name) == name && !zf.FileInfo().IsDir() {
				rc, err := zf.Open()
				if err != nil {
					return err
				}
				defer rc.Close()
				src = rc
				break
			}
		}
	default:
		gz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		tr := tar.NewReader(gz)
		for {
			hdr, err := tr.Next()
			if err != nil {
				return fmt.Errorf("%s not found in archive: %w", name, err)
			}
			if path.Base(hdr.Name) == name && hdr.Typeflag == tar.TypeReg {
				src = tr
				break
			}
		}
	}
	if src == nil {
		return fmt.Errorf("%s not found in archive", name)
	}
	tmp := out + ".tmp"
	w, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, io.LimitReader(src, 200<<20)); err != nil {
		w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, out)
}
