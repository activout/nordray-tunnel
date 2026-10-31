package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// bunnyBaseURL is overridden in tests.
var bunnyBaseURL = "https://api.bunny.net"

// bunny is a thin client for the few Bunny API calls this tool makes.
// Response bodies are never logged: Magic Containers echoes environment
// variables, including secrets, in clear text.
type bunny struct {
	key  string
	http *http.Client
}

func newBunny(key string) *bunny {
	return &bunny{key: key, http: &http.Client{Timeout: 60 * time.Second}}
}

// apiError is a non-2xx response.
type apiError struct {
	Method, Path string
	Status       int
	Message      string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("%s %s: HTTP %d %s", e.Method, e.Path, e.Status, e.Message)
}

func isNotFound(err error) bool {
	var e *apiError
	return errors.As(err, &e) && e.Status == http.StatusNotFound
}

func (b *bunny) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		j, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(j)
	}
	req, err := http.NewRequestWithContext(ctx, method, bunnyBaseURL+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("AccessKey", b.key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := b.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		// Strip the query: it can contain hostnames but never secrets; the
		// path is enough to identify the call.
		return &apiError{Method: method, Path: strings.SplitN(path, "?", 2)[0], Status: resp.StatusCode, Message: errorMessage(data)}
	}
	if out == nil || len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}

// errorMessage extracts the human-readable message from an error body. Error
// bodies are error descriptions, not echoed resources, so this is safe to show.
func errorMessage(data []byte) string {
	var m struct {
		Message string `json:"Message"`
		Msg     string `json:"message"`
		Title   string `json:"title"`
		Detail  string `json:"detail"`
	}
	if json.Unmarshal(data, &m) == nil {
		for _, s := range []string{m.Message, m.Msg, m.Detail, m.Title} {
			if s != "" {
				return s
			}
		}
	}
	return ""
}

// --- Magic Containers -----------------------------------------------------

type mcEnv struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type mcPortMapping struct {
	ContainerPort int      `json:"containerPort"`
	ExposedPort   int      `json:"exposedPort,omitempty"`
	Protocols     []string `json:"protocols,omitempty"`
}

type mcEndpointSpec struct {
	DisplayName string `json:"displayName"`
	CDN         *struct {
		IsSslEnabled bool            `json:"isSslEnabled"`
		PortMappings []mcPortMapping `json:"portMappings"`
	} `json:"cdn,omitempty"`
	Anycast *struct {
		Type         string          `json:"type"`
		PortMappings []mcPortMapping `json:"portMappings"`
	} `json:"anycast,omitempty"`
}

func cdnEndpoint(name string, port int) mcEndpointSpec {
	e := mcEndpointSpec{DisplayName: name}
	e.CDN = &struct {
		IsSslEnabled bool            `json:"isSslEnabled"`
		PortMappings []mcPortMapping `json:"portMappings"`
	}{PortMappings: []mcPortMapping{{ContainerPort: port}}}
	return e
}

func anycastEndpoint(name string, port int) mcEndpointSpec {
	e := mcEndpointSpec{DisplayName: name}
	e.Anycast = &struct {
		Type         string          `json:"type"`
		PortMappings []mcPortMapping `json:"portMappings"`
	}{Type: "iPv4", PortMappings: []mcPortMapping{{ContainerPort: port, ExposedPort: port, Protocols: []string{"tcp"}}}}
	return e
}

// mcEndpoint is an endpoint as the API returns it.
type mcEndpoint struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Type        string `json:"type"`
	PublicHost  string `json:"publicHost"`
	PullZoneID  string `json:"pullZoneId"`
}

func (e mcEndpoint) pullZone() int64 {
	id, _ := strconv.ParseInt(e.PullZoneID, 10, 64)
	return id
}

type mcApp struct {
	ID                 string `json:"id"`
	Status             string `json:"status"`
	ContainerTemplates []struct {
		ID        string       `json:"id"`
		Name      string       `json:"name"`
		ImageTag  string       `json:"imageTag"`
		Digest    string       `json:"imageDigest"`
		Env       []mcEnv      `json:"environmentVariables"`
		Endpoints []mcEndpoint `json:"endpoints"`
	} `json:"containerTemplates"`
	ContainerInstances []struct {
		PodID string `json:"podId"`
	} `json:"containerInstances"`
}

func (b *bunny) getApp(ctx context.Context, id string) (*mcApp, error) {
	var a mcApp
	return &a, b.do(ctx, http.MethodGet, "/mc/apps/"+url.PathEscape(id), nil, &a)
}

func (b *bunny) listEndpoints(ctx context.Context, appID string) ([]mcEndpoint, error) {
	var r struct {
		Items []mcEndpoint `json:"items"`
	}
	return r.Items, b.do(ctx, http.MethodGet, "/mc/apps/"+url.PathEscape(appID)+"/endpoints", nil, &r)
}

type mcRegistry struct {
	ID       int64  `json:"id"`
	HostName string `json:"hostName"`
	IsPublic bool   `json:"isPublic"`
	UserName string `json:"userName"`
}

func (b *bunny) registries(ctx context.Context) ([]mcRegistry, error) {
	var r struct {
		Items []mcRegistry `json:"items"`
	}
	return r.Items, b.do(ctx, http.MethodGet, "/mc/registries", nil, &r)
}

func (b *bunny) digest(ctx context.Context, img Image) (string, error) {
	var r struct {
		Digest string `json:"digest"`
	}
	err := b.do(ctx, http.MethodPost, "/mc/registries/digest", map[string]string{
		"registryId": img.RegistryID, "imageName": img.Name, "imageNamespace": img.Namespace, "tag": img.Tag,
	}, &r)
	if err == nil && r.Digest == "" {
		err = fmt.Errorf("registry returned no digest for %s", img)
	}
	return r.Digest, err
}

// --- CDN pull zones -------------------------------------------------------

type pullZone struct {
	ID        int64  `json:"Id"`
	Name      string `json:"Name"`
	Hostnames []struct {
		Value          string `json:"Value"`
		HasCertificate bool   `json:"HasCertificate"`
	} `json:"Hostnames"`
	EnableWebSockets bool `json:"EnableWebSockets"`
	AddHostHeader    bool `json:"AddHostHeader"`
	EnableSmartCache bool `json:"EnableSmartCache"`
}

func (b *bunny) getPullZone(ctx context.Context, id int64) (*pullZone, error) {
	var z pullZone
	return &z, b.do(ctx, http.MethodGet, fmt.Sprintf("/pullzone/%d", id), nil, &z)
}

func (b *bunny) updatePullZone(ctx context.Context, id int64, settings map[string]any) error {
	return b.do(ctx, http.MethodPost, fmt.Sprintf("/pullzone/%d", id), settings, nil)
}

func (z *pullZone) hostname(h string) (found, cert bool) {
	for _, x := range z.Hostnames {
		if strings.EqualFold(x.Value, h) {
			return true, x.HasCertificate
		}
	}
	return false, false
}

// --- Shield ---------------------------------------------------------------

// shieldSettings enforces WAF and DDoS protection immediately. New zones start
// in a seven-day learning mode that only logs. Challenge levels are avoided
// because they break non-browser clients.
func shieldSettings(id int64) map[string]any {
	z := map[string]any{"learningMode": false, "wafEnabled": true, "wafExecutionMode": 1, "dDoSShieldSensitivity": 2}
	if id != 0 {
		z["shieldZoneId"] = id
	}
	return z
}

// --- DNS ------------------------------------------------------------------

type dnsZone struct {
	ID      int64  `json:"Id"`
	Domain  string `json:"Domain"`
	Records []struct {
		ID    int64  `json:"Id"`
		Type  int    `json:"Type"`
		Name  string `json:"Name"`
		Value string `json:"Value"`
	} `json:"Records"`
}

// dnsZoneFor finds the Bunny DNS zone that holds hostname, if any, and the
// record name relative to it.
func (b *bunny) dnsZoneFor(ctx context.Context, hostname string) (*dnsZone, string, error) {
	var best *dnsZone
	for page := 1; ; page++ {
		var r struct {
			Items        []dnsZone `json:"Items"`
			HasMoreItems bool      `json:"HasMoreItems"`
		}
		if err := b.do(ctx, http.MethodGet, fmt.Sprintf("/dnszone?page=%d&perPage=1000", page), nil, &r); err != nil {
			return nil, "", err
		}
		for i := range r.Items {
			z := &r.Items[i]
			d := strings.ToLower(z.Domain)
			if (hostname == d || strings.HasSuffix(hostname, "."+d)) && (best == nil || len(d) > len(best.Domain)) {
				best = z
			}
		}
		if !r.HasMoreItems {
			break
		}
	}
	if best == nil {
		return nil, "", nil
	}
	var full dnsZone
	if err := b.do(ctx, http.MethodGet, fmt.Sprintf("/dnszone/%d", best.ID), nil, &full); err != nil {
		return nil, "", err
	}
	return &full, strings.TrimSuffix(strings.TrimSuffix(hostname, strings.ToLower(full.Domain)), "."), nil
}
