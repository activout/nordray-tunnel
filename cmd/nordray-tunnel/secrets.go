package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/zalando/go-keyring"
	"golang.org/x/term"
)

const keyringService = "nordray-tunnel"

// Credential store entries. The Bunny key is account-wide; the others belong
// to one installation.
func secretKey(installation, kind string) string {
	if kind == "bunny-api-key" {
		return kind
	}
	return installation + "/" + kind
}

func getSecret(installation, kind string) (string, error) {
	v, err := keyring.Get(keyringService, secretKey(installation, kind))
	if errors.Is(err, keyring.ErrNotFound) {
		return "", nil
	}
	return v, err
}

func setSecret(installation, kind, value string) error {
	return keyring.Set(keyringService, secretKey(installation, kind), value)
}

func deleteSecret(installation, kind string) {
	_ = keyring.Delete(keyringService, secretKey(installation, kind))
}

// ensureSecret returns the stored secret, generating 32 random bytes when absent.
func ensureSecret(installation, kind string) (string, error) {
	v, err := getSecret(installation, kind)
	if err != nil || v != "" {
		return v, err
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	v = hex.EncodeToString(b)
	return v, setSecret(installation, kind, v)
}

// readPassword is replaced in tests.
var readPassword = func() (string, error) {
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	return string(b), err
}

// bunnyAPIKey resolves the Bunny API key: an explicitly named environment
// variable, then the credential store, then a hidden prompt. The key is never
// accepted as a command-line value.
func bunnyAPIKey(envName string) (string, error) {
	if envName != "" {
		v := strings.TrimSpace(os.Getenv(envName))
		if v == "" {
			return "", fmt.Errorf("environment variable %s is empty", envName)
		}
		return v, nil
	}
	if v, err := getSecret("", "bunny-api-key"); err == nil && v != "" {
		return v, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("no Bunny API key stored and no terminal for a prompt; use --api-key-env NAME")
	}
	fmt.Print("Bunny API key (input hidden): ")
	v, err := readPassword()
	v = strings.TrimSpace(v)
	if err != nil || v == "" {
		return "", errors.New("no Bunny API key given")
	}
	if err := setSecret("", "bunny-api-key", v); err != nil {
		fmt.Fprintln(os.Stderr, "warning: could not save the key in the credential store:", err)
	} else {
		fmt.Println("Saved the Bunny API key in the OS credential store.")
	}
	return v, nil
}
