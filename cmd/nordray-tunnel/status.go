package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

func cmdStatus(args []string) error {
	fs, name := newFlags("status", "[--remote]")
	remote := fs.Bool("remote", false, "also query Bunny (needs the API key)")
	keyEnv := fs.String("api-key-env", "", "read the Bunny API key from this environment `variable`")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := loadState(*name)
	if err != nil {
		return err
	}
	if err := s.mustExist(); err != nil {
		return err
	}
	fmt.Printf("Installation  %s\nTransport     %s\nRegion        %s\nApp           %s\nImage         %s@%s\n",
		s.Name, s.Transport, s.Region, s.AppID, s.Image, short(s.Image.Digest))
	if s.Transport == "wss" {
		fmt.Printf("Tunnel        wss://%s:443 (pull zone %d)\n", s.TunnelHost, s.TunnelPullZoneID)
	} else {
		fmt.Printf("Tunnel        tls://%s (server name %s)\n", s.AnycastAddr, relayServerName)
	}
	fmt.Printf("Visitors      pull zone %d, Shield zone %d\n", s.AppPullZoneID, s.ShieldZoneID)

	agent := agentStatus(s)
	fmt.Println("\nProxies:")
	if len(s.Proxies) == 0 {
		fmt.Println("  none; add one with: nordray-tunnel add")
	}
	for _, p := range s.Proxies {
		state := "agent not running here"
		if agent != nil {
			state = "not registered"
			if a, ok := agent[p.Name]; ok {
				state = a
			}
		}
		fmt.Printf("  %-16s https://%s → http://%s:%d  [%s]\n", p.Name, p.Hostname, p.LocalIP, p.LocalPort, state)
	}

	if !*remote {
		return nil
	}
	key, err := bunnyAPIKey(*keyEnv)
	if err != nil {
		return err
	}
	ctx, b := context.Background(), newBunny(key)
	app, err := b.getApp(ctx, s.AppID)
	if err != nil {
		return err
	}
	fmt.Printf("\nRelay         %s, %d pod(s)\n", app.Status, len(app.ContainerInstances))
	z, err := b.getPullZone(ctx, s.AppPullZoneID)
	if err != nil {
		return err
	}
	for _, p := range s.Proxies {
		found, cert := z.hostname(p.Hostname)
		fmt.Printf("  %-16s hostname on zone: %t, certificate: %t\n", p.Name, found, cert)
	}
	var sz struct {
		Data struct {
			LearningMode     bool `json:"learningMode"`
			WafExecutionMode int  `json:"wafExecutionMode"`
		} `json:"data"`
	}
	if err := b.do(ctx, http.MethodGet, fmt.Sprintf("/shield/shield-zone/%d", s.ShieldZoneID), nil, &sz); err != nil {
		return err
	}
	mode := map[int]string{0: "log only", 1: "block"}[sz.Data.WafExecutionMode]
	fmt.Printf("Shield        WAF %s, learning mode %t\n", mode, sz.Data.LearningMode)
	return nil
}

func short(d string) string {
	if len(d) > 19 {
		return d[:19] + "…"
	}
	return d
}

// agentStatus asks the local frpc admin server for proxy states; nil means
// no agent is running on this machine.
func agentStatus(s *State) map[string]string {
	if s.AdminPort == 0 {
		return nil
	}
	pw, err := getSecret(s.Name, "frpc-admin-password")
	if err != nil || pw == "" {
		return nil
	}
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/api/status", s.AdminPort), nil)
	req.SetBasicAuth("nordray", pw)
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var byType map[string][]struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Err    string `json:"err"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&byType) != nil {
		return nil
	}
	out := map[string]string{}
	for _, list := range byType {
		for _, p := range list {
			out[p.Name] = p.Status
			if p.Err != "" {
				out[p.Name] += ": " + p.Err
			}
		}
	}
	return out
}
