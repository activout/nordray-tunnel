package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func cmdDestroy(args []string) error {
	fs, name := newFlags("destroy", "[--yes]")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	keyEnv := fs.String("api-key-env", "", "read the Bunny API key from this environment `variable`")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := loadState(*name)
	if err != nil {
		return err
	}
	fmt.Printf("This deletes every resource installation %q created, by ID:\n", s.Name)
	for _, p := range s.Proxies {
		if p.DNSRecordID != 0 {
			fmt.Printf("  DNS record %d (%s)\n", p.DNSRecordID, p.Hostname)
		}
	}
	if s.AppID != "" {
		fmt.Printf("  Magic Containers app %s with its endpoints%s\n", s.AppID, map[bool]string{true: " and Anycast IP " + s.AnycastAddr}[s.AnycastAddr != ""])
	}
	for _, id := range []int64{s.AppPullZoneID, s.TunnelPullZoneID} {
		if id != 0 {
			fmt.Printf("  pull zone %d\n", id)
		}
	}
	fmt.Println("  local state and credential store entries for this installation")
	if !*yes {
		fmt.Printf("Type the installation name (%s) to confirm: ", s.Name)
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if strings.TrimSpace(line) != s.Name {
			return errors.New("cancelled")
		}
	}
	key, err := bunnyAPIKey(*keyEnv)
	if err != nil {
		return err
	}
	return destroy(context.Background(), newBunny(key), s)
}

// destroy deletes resources in dependency order and saves progress after
// each step, so an interrupted destroy can simply be run again.
func destroy(ctx context.Context, b *bunny, s *State) error {
	del := func(path string) error {
		if err := b.do(ctx, http.MethodDelete, path, nil, nil); err != nil && !isNotFound(err) {
			return err
		}
		return nil
	}
	for i := range s.Proxies {
		p := &s.Proxies[i]
		if p.DNSRecordID != 0 {
			if err := del(fmt.Sprintf("/dnszone/%d/records/%d", p.DNSZoneID, p.DNSRecordID)); err != nil {
				return err
			}
			fmt.Printf("Deleted DNS record %d.\n", p.DNSRecordID)
			p.DNSRecordID = 0
			if err := s.save(); err != nil {
				return err
			}
		}
	}
	anycast := s.AnycastAddr
	if s.AppID != "" {
		if err := del("/mc/apps/" + url.PathEscape(s.AppID)); err != nil {
			return err
		}
		fmt.Printf("Deleted Magic Containers app %s.\n", s.AppID)
		s.AppID, s.ContainerID, s.AppEndpointID, s.TunnelEndpointID, s.AnycastEndpointID, s.AnycastAddr = "", "", "", "", "", ""
		if err := s.save(); err != nil {
			return err
		}
	}
	// Deleting an app leaves its pull zones behind (measured 31 October 2026).
	for _, id := range []*int64{&s.TunnelPullZoneID, &s.AppPullZoneID} {
		if *id != 0 {
			if err := del(fmt.Sprintf("/pullzone/%d", *id)); err != nil {
				return err
			}
			fmt.Printf("Deleted pull zone %d.\n", *id)
			*id = 0
			if err := s.save(); err != nil {
				return err
			}
		}
	}
	if s.ShieldZoneID != 0 {
		fmt.Printf("Shield zone %d remains: the Shield API has no delete operation. It is on the free plan and points at the deleted pull zone.\n", s.ShieldZoneID)
	}
	if anycast != "" {
		waitClosed(anycast)
	}
	for _, kind := range []string{"tunnel-token", "relay-tls-key", "frpc-admin-password"} {
		deleteSecret(s.Name, kind)
	}
	dir, err := stateDir(s.Name)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	fmt.Printf("Installation %q is gone. A Bunny API key saved in the credential store is kept for other installations.\n", s.Name)
	return nil
}

// waitClosed waits for the deleted relay to stop answering: the app API
// reports deletion at once, but the relay answered on its Anycast IP for
// about four minutes when measured.
var waitClosed = func(addr string) {
	deadline := time.Now().Add(8 * time.Minute)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			fmt.Printf("The relay no longer answers on %s.\n", addr)
			return
		}
		c.Close()
		fmt.Printf("The relay still answers on %s; waiting for Bunny to stop it...\n", addr)
		time.Sleep(30 * time.Second)
	}
	fmt.Printf("The relay still answers on %s after 8 minutes; check the Magic Containers dashboard.\n", addr)
}
