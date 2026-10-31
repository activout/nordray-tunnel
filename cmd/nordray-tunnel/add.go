package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var hostnamePattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

func cmdAdd(args []string) error {
	fs, name := newFlags("add", "<proxy> --hostname app.example.se --local http://127.0.0.1:8080")
	hostname := fs.String("hostname", "", "public `hostname` to serve")
	local := fs.String("local", "", "local HTTP service `URL`, for example http://127.0.0.1:8080")
	keyEnv := fs.String("api-key-env", "", "read the Bunny API key from this environment `variable`")
	proxyName, err := parseWithName(fs, args)
	if err != nil {
		return err
	}
	h := strings.ToLower(strings.TrimSuffix(*hostname, "."))
	if !hostnamePattern.MatchString(h) {
		return fmt.Errorf("--hostname %q is not a valid public hostname", *hostname)
	}
	ip, port, err := parseLocal(*local)
	if err != nil {
		return err
	}
	s, err := loadState(*name)
	if err != nil {
		return err
	}
	if err := s.mustExist(); err != nil {
		return err
	}
	for _, p := range s.Proxies {
		if p.Hostname == h && p.Name != proxyName {
			return fmt.Errorf("hostname %s is already used by proxy %q", h, p.Name)
		}
	}
	p := s.proxy(proxyName)
	if p != nil && p.Hostname != h {
		return fmt.Errorf("proxy %q already serves %s; remove it first", proxyName, p.Hostname)
	}
	if p == nil {
		s.Proxies = append(s.Proxies, Proxy{Name: proxyName, Hostname: h})
		p = &s.Proxies[len(s.Proxies)-1]
	}
	p.LocalIP, p.LocalPort = ip, port
	if err := s.save(); err != nil {
		return err
	}
	key, err := bunnyAPIKey(*keyEnv)
	if err != nil {
		return err
	}
	ctx := context.Background()
	if err := publish(ctx, newBunny(key), s, p); err != nil {
		return err
	}
	applyToRunningAgent(s)
	return nil
}

// parseWithName parses flags that may come before or after the positional name.
func parseWithName(fs interface {
	Parse([]string) error
	Args() []string
}, args []string) (string, error) {
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	rest := fs.Args()
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		name := rest[0]
		if err := fs.Parse(rest[1:]); err != nil {
			return "", err
		}
		if len(fs.Args()) > 0 {
			return "", fmt.Errorf("unexpected arguments: %v", fs.Args())
		}
		return name, validName("proxy name", name)
	}
	return "", errors.New("missing proxy name")
}

// parseLocal accepts http://host[:port]. HTTPS local targets are not
// supported yet: they need verified certificate handling in frpc.
func parseLocal(raw string) (string, int, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
		return "", 0, fmt.Errorf("--local must be http://host[:port], got %q (HTTPS local targets are not supported yet)", raw)
	}
	port := 80
	if p := u.Port(); p != "" {
		port, err = strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 {
			return "", 0, fmt.Errorf("invalid port in --local %q", raw)
		}
	}
	return u.Hostname(), port, nil
}

// publish attaches the hostname to the app pull zone, creates its DNS record
// when the zone is in Bunny DNS, and issues the free certificate.
func publish(ctx context.Context, b *bunny, s *State, p *Proxy) error {
	z, err := b.getPullZone(ctx, s.AppPullZoneID)
	if err != nil {
		return err
	}
	found, hasCert := z.hostname(p.Hostname)
	if !found {
		if err := b.do(ctx, http.MethodPost, fmt.Sprintf("/pullzone/%d/addHostname", s.AppPullZoneID), map[string]string{"Hostname": p.Hostname}, nil); err != nil {
			return err
		}
		fmt.Printf("Added %s to pull zone %d.\n", p.Hostname, s.AppPullZoneID)
	}

	external := false
	if p.DNSRecordID == 0 {
		zone, rel, err := b.dnsZoneFor(ctx, p.Hostname)
		if err != nil {
			return err
		}
		if zone == nil {
			external = true
			fmt.Printf("\nDNS for %s is not in Bunny DNS. Create this record with your DNS provider:\n  %s. CNAME %s.b-cdn.net.\n\n", p.Hostname, p.Hostname, z.Name)
		} else {
			for _, r := range zone.Records {
				if strings.EqualFold(r.Name, rel) {
					if r.Type == 7 && r.Value == z.Name {
						p.DNSZoneID, p.DNSRecordID = zone.ID, r.ID // already points at our pull zone
						break
					}
					return fmt.Errorf("a DNS record for %s already exists in zone %s (record %d); remove it or choose another hostname", p.Hostname, zone.Domain, r.ID)
				}
			}
			if p.DNSRecordID == 0 {
				var rec struct {
					ID int64 `json:"Id"`
				}
				err := b.do(ctx, http.MethodPut, fmt.Sprintf("/dnszone/%d/records", zone.ID), map[string]any{
					"Type": 7, "Name": rel, "Value": z.Name, "PullZoneId": s.AppPullZoneID, "Ttl": 300,
				}, &rec)
				if err != nil {
					return err
				}
				p.DNSZoneID, p.DNSRecordID = zone.ID, rec.ID
				fmt.Printf("Created DNS record %d in %s.\n", rec.ID, zone.Domain)
			}
			if err := s.save(); err != nil {
				return err
			}
		}
	}

	if !hasCert {
		if err := issueCertificate(ctx, b, p.Hostname, external); err != nil {
			return err
		}
	}
	// Redirect plain HTTP to HTTPS, so the X-Forwarded-Proto: https the
	// agent sets is always true.
	if err := b.do(ctx, http.MethodPost, fmt.Sprintf("/pullzone/%d/setForceSSL", s.AppPullZoneID), map[string]any{"Hostname": p.Hostname, "ForceSSL": true}, nil); err != nil {
		return err
	}
	waitForEdge(p.Hostname)
	return nil
}

func issueCertificate(ctx context.Context, b *bunny, hostname string, external bool) error {
	deadline := time.Now().Add(3 * time.Minute)
	for {
		err := b.do(ctx, http.MethodGet, "/pullzone/loadFreeCertificate?hostname="+url.QueryEscape(hostname), nil, nil)
		if err == nil {
			fmt.Printf("Issued a certificate for %s.\n", hostname)
			return nil
		}
		if time.Now().After(deadline) {
			if external {
				fmt.Printf("The certificate for %s is pending: create the DNS record above, then run add again.\n", hostname)
				return nil
			}
			return fmt.Errorf("certificate for %s: %w", hostname, err)
		}
		time.Sleep(pollInterval)
	}
}

// waitForEdge waits until the CDN edge presents a valid certificate for the
// hostname; issuance took about 75 seconds to reach the edge when measured.
var waitForEdge = func(hostname string) {
	deadline := time.Now().Add(4 * time.Minute)
	for {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", hostname+":443", &tls.Config{ServerName: hostname})
		if err == nil {
			c.Close()
			fmt.Printf("https://%s/ is live.\n", hostname)
			return
		}
		if time.Now().After(deadline) {
			fmt.Printf("https://%s/ does not present its certificate yet; it usually appears within a few minutes.\n", hostname)
			return
		}
		time.Sleep(15 * time.Second)
	}
}

func cmdRemove(args []string) error {
	fs, name := newFlags("remove", "<proxy>")
	keyEnv := fs.String("api-key-env", "", "read the Bunny API key from this environment `variable`")
	proxyName, err := parseWithName(fs, args)
	if err != nil {
		return err
	}
	s, err := loadState(*name)
	if err != nil {
		return err
	}
	p := s.proxy(proxyName)
	if p == nil {
		return fmt.Errorf("no proxy %q in installation %q", proxyName, s.Name)
	}
	key, err := bunnyAPIKey(*keyEnv)
	if err != nil {
		return err
	}
	ctx, b := context.Background(), newBunny(key)
	if p.DNSRecordID != 0 {
		err := b.do(ctx, http.MethodDelete, fmt.Sprintf("/dnszone/%d/records/%d", p.DNSZoneID, p.DNSRecordID), nil, nil)
		if err != nil && !isNotFound(err) {
			return err
		}
		fmt.Printf("Deleted DNS record %d.\n", p.DNSRecordID)
	}
	if s.AppPullZoneID != 0 {
		err := b.do(ctx, http.MethodDelete, fmt.Sprintf("/pullzone/%d/removeHostname", s.AppPullZoneID), map[string]string{"Hostname": p.Hostname}, nil)
		if err != nil && !isNotFound(err) {
			return err
		}
		fmt.Printf("Removed %s from pull zone %d.\n", p.Hostname, s.AppPullZoneID)
	}
	kept := s.Proxies[:0]
	for _, x := range s.Proxies {
		if x.Name != proxyName {
			kept = append(kept, x)
		}
	}
	s.Proxies = kept
	if err := s.save(); err != nil {
		return err
	}
	applyToRunningAgent(s)
	return nil
}
