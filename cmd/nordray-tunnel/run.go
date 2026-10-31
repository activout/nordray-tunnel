package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"syscall"
	"time"
)

// adminServer is frpc's own web server, bound to loopback. status reads it
// and add/remove use it to reload frpc.
type adminServer struct {
	Port           int
	User, Password string
}

func localAdmin(s *State) (*adminServer, error) {
	pw, err := ensureSecret(s.Name, "frpc-admin-password")
	if err != nil {
		return nil, fmt.Errorf("credential store: %w", err)
	}
	if s.AdminPort == 0 {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		s.AdminPort = l.Addr().(*net.TCPAddr).Port
		l.Close()
		if err := s.save(); err != nil {
			return nil, err
		}
	}
	return &adminServer{Port: s.AdminPort, User: "nordray", Password: pw}, nil
}

// writeLocalAgent regenerates the configuration that run uses on the
// operator's machine.
func writeLocalAgent(s *State) (string, error) {
	token, err := getSecret(s.Name, "tunnel-token")
	if err != nil || token == "" {
		return "", fmt.Errorf("no tunnel token for installation %q in the credential store; run setup, or run --config with an exported configuration", s.Name)
	}
	admin, err := localAdmin(s)
	if err != nil {
		return "", err
	}
	cfg, err := buildFrpcConfig(s, token, admin)
	if err != nil {
		return "", err
	}
	dir, err := stateDir(s.Name)
	if err != nil {
		return "", err
	}
	return writeAgentFiles(filepath.Join(dir, "agent"), s, cfg)
}

// applyToRunningAgent rewrites the local configuration and asks a running
// frpc to reload it.
func applyToRunningAgent(s *State) {
	if _, err := writeLocalAgent(s); err != nil {
		fmt.Println("Local agent configuration not updated:", err)
		return
	}
	admin, err := localAdmin(s)
	if err != nil {
		return
	}
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/api/reload", admin.Port), nil)
	req.SetBasicAuth(admin.User, admin.Password)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		fmt.Println("The local agent is not running; the change applies at the next: nordray-tunnel run --name", s.Name)
		return
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		fmt.Println("Reloaded the running agent.")
	} else {
		fmt.Printf("The running agent did not reload (HTTP %d); restart nordray-tunnel run.\n", resp.StatusCode)
	}
	fmt.Println("Exported agents on other machines need a fresh: nordray-tunnel agent-config")
}

func cmdRun(args []string) error {
	fs, name := newFlags("run", "[--config FILE] [--frpc PATH]")
	config := fs.String("config", "", "run an exported frpc.toml instead of this machine's installation")
	frpcPath := fs.String("frpc", "", "path to the frpc `binary` (default: frpc in PATH)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	path := *config
	if path == "" {
		s, err := loadState(*name)
		if err != nil {
			return err
		}
		if err := s.mustExist(); err != nil {
			return err
		}
		if path, err = writeLocalAgent(s); err != nil {
			return err
		}
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	bin, err := findFrpc(*frpcPath)
	if err != nil {
		return err
	}
	return runChild(bin, abs)
}

var versionPattern = regexp.MustCompile(`\d+\.\d+\.\d+`)

func findFrpc(explicit string) (string, error) {
	// Order: --frpc, the version install-frpc put in place, then PATH.
	bin := explicit
	if bin == "" {
		bin = installedFrpc(frpVersion)
	}
	if bin == "" {
		var err error
		if bin, err = exec.LookPath("frpc"); err != nil {
			return "", fmt.Errorf("frpc not found; run: nordray-tunnel install-frpc (or pass --frpc)")
		}
	}
	out, err := exec.Command(bin, "-v").Output()
	if err != nil {
		return "", fmt.Errorf("%s -v: %w", bin, err)
	}
	if v := versionPattern.FindString(string(out)); v != frpVersion {
		fmt.Fprintf(os.Stderr, "warning: %s is frpc %s; nordray-tunnel is tested with %s\n", bin, v, frpVersion)
	}
	return bin, nil
}

// runChild runs frpc in the configuration's directory (so ca.pem resolves
// next to it), forwards SIGINT and SIGTERM, and returns its exit status.
func runChild(bin, config string) error {
	cmd := exec.Command(bin, "-c", config)
	cmd.Dir = filepath.Dir(config)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	go func() {
		for s := range sig {
			_ = cmd.Process.Signal(s)
		}
	}()
	err := cmd.Wait()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		if code := exit.ExitCode(); code >= 0 {
			return exitError{code}
		}
		return exitError{1}
	}
	return err
}

func cmdAgentConfig(args []string) error {
	fs, name := newFlags("agent-config", "-o DIR")
	out := fs.String("o", "", "output `directory` (created with private permissions)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("-o DIR is required")
	}
	s, err := loadState(*name)
	if err != nil {
		return err
	}
	if err := s.mustExist(); err != nil {
		return err
	}
	token, err := getSecret(s.Name, "tunnel-token")
	if err != nil || token == "" {
		return fmt.Errorf("no tunnel token for installation %q in the credential store", s.Name)
	}
	cfg, err := buildFrpcConfig(s, token, nil)
	if err != nil {
		return err
	}
	path, err := writeAgentFiles(*out, s, cfg)
	if err != nil {
		return err
	}
	fmt.Printf("Wrote %s and %s.\n", path, filepath.Join(*out, caFileName))
	fmt.Println("frpc.toml contains the tunnel token: copy the directory over a private channel and keep it readable only by the agent's user.")
	fmt.Println("On the agent machine: nordray-tunnel run --config " + filepath.Join(filepath.Base(*out), "frpc.toml"))
	fmt.Println("All holders of this token are trusted operators of the installation: the token does not limit which hostnames an agent may serve.")
	return nil
}
