package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// State holds the non-secret identifiers and desired configuration of one
// installation. Secrets live in the OS credential store (see secrets.go).
type State struct {
	Name      string `json:"name"`
	Region    string `json:"region"`
	Transport string `json:"transport"` // "wss" or "anycast"
	Image     Image  `json:"image"`

	AppID       string `json:"appId,omitempty"`
	ContainerID string `json:"containerId,omitempty"`

	AppEndpointID   string `json:"appEndpointId,omitempty"`
	AppPullZoneID   int64  `json:"appPullZoneId,omitempty"`
	AppPullZoneName string `json:"appPullZoneName,omitempty"`

	TunnelEndpointID string `json:"tunnelEndpointId,omitempty"`
	TunnelPullZoneID int64  `json:"tunnelPullZoneId,omitempty"`
	TunnelHost       string `json:"tunnelHost,omitempty"`

	AnycastEndpointID string `json:"anycastEndpointId,omitempty"`
	AnycastAddr       string `json:"anycastAddr,omitempty"` // host:port

	ShieldZoneID int64 `json:"shieldZoneId,omitempty"`

	// Relay TLS for the anycast transport. Public material only: the server
	// key is in the credential store and the CA key is discarded after
	// signing, so nobody can issue further relay certificates.
	CACert     string `json:"caCert,omitempty"`
	ServerCert string `json:"serverCert,omitempty"`

	AdminPort int     `json:"adminPort,omitempty"`
	Proxies   []Proxy `json:"proxies,omitempty"`
}

// Proxy is one published local service.
type Proxy struct {
	Name        string `json:"name"`
	Hostname    string `json:"hostname"`
	LocalIP     string `json:"localIp"`
	LocalPort   int    `json:"localPort"`
	DNSZoneID   int64  `json:"dnsZoneId,omitempty"`
	DNSRecordID int64  `json:"dnsRecordId,omitempty"`
}

var namePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)

func validName(kind, name string) error {
	if !namePattern.MatchString(name) {
		return fmt.Errorf("invalid %s %q: use 1-32 lower-case letters, digits and hyphens", kind, name)
	}
	return nil
}

// configRoot is overridden in tests.
var configRoot = func() (string, error) {
	dir, err := os.UserConfigDir()
	return filepath.Join(dir, "nordray-tunnel"), err
}

func stateDir(name string) (string, error) {
	if err := validName("installation name", name); err != nil {
		return "", err
	}
	root, err := configRoot()
	return filepath.Join(root, name), err
}

// loadState returns the saved state, or a fresh one when none exists.
func loadState(name string) (*State, error) {
	dir, err := stateDir(name)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return &State{Name: name}, nil
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("read %s: %w", filepath.Join(dir, "state.json"), err)
	}
	return &s, nil
}

// mustExist returns an error when the installation has not been set up.
func (s *State) mustExist() error {
	if s.AppID == "" {
		return fmt.Errorf("installation %q is not set up; run: nordray-tunnel setup --name %s", s.Name, s.Name)
	}
	return nil
}

// save writes the state atomically so a crash never leaves it half written.
func (s *State) save() error {
	dir, err := stateDir(s.Name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, "state.json.tmp")
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, "state.json"))
}

func (s *State) proxy(name string) *Proxy {
	for i := range s.Proxies {
		if s.Proxies[i].Name == name {
			return &s.Proxies[i]
		}
	}
	return nil
}
