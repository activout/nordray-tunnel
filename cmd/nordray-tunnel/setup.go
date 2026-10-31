package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	tunnelPort = 7000 // frps bindPort, see relay/frps.toml
	vhostPort  = 8080 // frps vhostHTTPPort
)

// pollInterval is shortened in tests.
var pollInterval = 5 * time.Second

func cmdSetup(args []string) error {
	fs, name := newFlags("setup", "[options]")
	region := fs.String("region", "", "Magic Containers region `id`, for example DK (required on first setup)")
	transport := fs.String("transport", "", "tunnel transport: wss (default) or anycast (paid IPv4)")
	image := fs.String("image", "", "pinned relay image `host/namespace/name:tag` (required on first setup)")
	registryID := fs.String("registry-id", "", "Magic Containers image registry `id`, when more than one matches the image host")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	keyEnv := fs.String("api-key-env", "", "read the Bunny API key from this environment `variable` (opt-in for automation)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := loadState(*name)
	if err != nil {
		return err
	}
	if *region != "" {
		s.Region = strings.ToUpper(*region)
	}
	if *transport != "" {
		s.Transport = *transport
	}
	if s.Transport == "" {
		s.Transport = "wss"
	}
	if s.Transport != "wss" && s.Transport != "anycast" {
		return fmt.Errorf("--transport must be wss or anycast")
	}
	if s.Region == "" {
		return errors.New("--region is required on first setup (see https://bunny.net/docs/magic-containers/regions)")
	}
	if *image != "" {
		img, err := parseImage(*image)
		if err != nil {
			return err
		}
		img.RegistryID = *registryID
		s.Image = img
	}
	if s.Image.Name == "" {
		return errors.New("--image is required on first setup, for example ghcr.io/activout/nordray-tunnel-relay:sha-<commit>")
	}
	key, err := bunnyAPIKey(*keyEnv)
	if err != nil {
		return err
	}
	return reconcile(context.Background(), newBunny(key), s, *yes)
}

func cmdUpdate(args []string) error {
	fs, name := newFlags("update", "--image host/namespace/name:tag")
	image := fs.String("image", "", "pinned relay image `host/namespace/name:tag`")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
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
	img, err := parseImage(*image)
	if err != nil {
		return err
	}
	img.RegistryID = s.Image.RegistryID
	if img.Host != s.Image.Host {
		img.RegistryID = ""
	}
	s.Image = img
	key, err := bunnyAPIKey(*keyEnv)
	if err != nil {
		return err
	}
	fmt.Println("Updating the relay restarts it: agents reconnect on their own (about 30 seconds without service measured on 31 October 2026).")
	return reconcile(context.Background(), newBunny(key), s, *yes)
}

// reconcile brings the account to the desired state, identifying every
// resource by the ID saved in the state file. Resources are never matched by
// name, so unrelated resources in the account are never touched. State is
// saved after every creation, so a failure part-way can be resumed by
// running setup again.
func reconcile(ctx context.Context, b *bunny, s *State, yes bool) error {
	var app *mcApp
	if s.AppID != "" {
		a, err := b.getApp(ctx, s.AppID)
		switch {
		case isNotFound(err):
			fmt.Printf("Magic Containers app %s no longer exists; it will be created again.\n", s.AppID)
			warnOrphans(s)
			s.AppID, s.ContainerID, s.AppEndpointID, s.TunnelEndpointID, s.AnycastEndpointID = "", "", "", "", ""
			s.AppPullZoneID, s.TunnelPullZoneID, s.ShieldZoneID = 0, 0, 0
			s.TunnelHost, s.AnycastAddr, s.AppPullZoneName = "", "", ""
		case err != nil:
			return err
		default:
			app = a
		}
	}

	actions := plan(s, app)
	printPlan(s, actions)
	if needsConfirmation(actions) && !yes && !confirm(os.Stdin, "Create or delete these resources in your Bunny account?") {
		return errors.New("cancelled")
	}

	if err := resolveImage(ctx, b, s); err != nil {
		return err
	}
	token, err := ensureSecret(s.Name, "tunnel-token")
	if err != nil {
		return fmt.Errorf("credential store: %w", err)
	}
	env, err := relayEnv(s, token)
	if err != nil {
		return err
	}

	if app == nil {
		if err := createApp(ctx, b, s, env); err != nil {
			return err
		}
	} else if err := updateApp(ctx, b, s, env); err != nil {
		return err
	}
	if err := readEndpoints(ctx, b, s); err != nil {
		return err
	}
	if err := configureZones(ctx, b, s); err != nil {
		return err
	}
	if err := waitActive(ctx, b, s); err != nil {
		return err
	}
	fmt.Printf("\nInstallation %q is ready (transport %s).\n", s.Name, s.Transport)
	fmt.Printf("Next: nordray-tunnel add <proxy> --name %s --hostname <public hostname> --local http://127.0.0.1:<port>\n", s.Name)
	return nil
}

type action struct{ verb, what string }

func plan(s *State, app *mcApp) []action {
	var a []action
	appName := "nordray-tunnel-" + s.Name
	if app == nil {
		a = append(a, action{"create", fmt.Sprintf("Magic Containers app %s in %s (1 replica, shared runtime, image %s)", appName, s.Region, s.Image)})
		a = append(a, action{"create", fmt.Sprintf("CDN endpoint app → container %d (own pull zone, Host forwarded, no cache, no WebSockets)", vhostPort)})
		a = append(a, action{"create", "Shield zone on the app pull zone (WAF block, DDoS medium, no learning mode)"})
	} else {
		a = append(a, action{"update", fmt.Sprintf("Magic Containers app %s: image %s and environment (restarts the relay)", s.AppID, s.Image)})
	}
	switch s.Transport {
	case "wss":
		if s.TunnelEndpointID == "" {
			a = append(a, action{"create", fmt.Sprintf("CDN endpoint tunnel → container %d (own pull zone, WebSockets on)", tunnelPort)})
		}
		if s.AnycastEndpointID != "" {
			a = append(a, action{"delete", fmt.Sprintf("Anycast endpoint %s (%s) and its IPv4 address", s.AnycastEndpointID, s.AnycastAddr)})
		}
	case "anycast":
		if s.AnycastEndpointID == "" {
			a = append(a, action{"create", fmt.Sprintf("Anycast IPv4 endpoint → container %d (frp TLS with an installation CA)", tunnelPort)})
		}
		if s.TunnelEndpointID != "" {
			a = append(a, action{"delete", fmt.Sprintf("CDN tunnel endpoint %s and its pull zone %d", s.TunnelEndpointID, s.TunnelPullZoneID)})
		}
	}
	return a
}

func needsConfirmation(actions []action) bool {
	for _, a := range actions {
		if a.verb != "update" {
			return true
		}
	}
	return false
}

func printPlan(s *State, actions []action) {
	fmt.Printf("Plan for installation %q (transport %s, region %s):\n", s.Name, s.Transport, s.Region)
	for _, a := range actions {
		fmt.Printf("  %-7s %s\n", a.verb, a.what)
	}
	fmt.Println(`
Costs to expect (Bunny list prices checked on 31 October 2026; recheck
https://bunny.net/docs/magic-containers/pricing before relying on them):
  container  CPU $0.02 per CPU-hour, RAM $0.005 per GB-hour in 64 MB blocks
  visitors   CDN bandwidth on the app pull zone; Shield free plan $0`)
	if s.Transport == "wss" {
		fmt.Println(`  tunnel     CDN WebSockets $0.235 per million connection-minutes
             (one connection per agent, about $0.01 a month), plus CDN
             bandwidth again: every visitor byte crosses the CDN twice`)
	} else {
		fmt.Println(`  tunnel     Anycast IPv4 $2 per month while attached, shared by every
             agent and service; tunnel traffic is Magic Containers egress
             ($0.01/GB in Europe and North America)`)
	}
	fmt.Println()
}

func warnOrphans(s *State) {
	for _, id := range []int64{s.AppPullZoneID, s.TunnelPullZoneID} {
		if id != 0 {
			fmt.Printf("  Pull zone %d from the old app may still exist: Bunny keeps pull zones when an app is deleted. Check it in the dashboard.\n", id)
		}
	}
}

// resolveImage picks the registry and pins the tag to its current digest.
func resolveImage(ctx context.Context, b *bunny, s *State) error {
	if s.Image.RegistryID == "" {
		regs, err := b.registries(ctx)
		if err != nil {
			return err
		}
		var public, private []mcRegistry
		for _, r := range regs {
			if strings.EqualFold(r.HostName, s.Image.Host) {
				if r.IsPublic {
					public = append(public, r)
				} else {
					private = append(private, r)
				}
			}
		}
		switch {
		case len(private) == 1:
			s.Image.RegistryID = fmt.Sprint(private[0].ID)
		case len(private) > 1:
			return fmt.Errorf("several image registries for %s are connected; choose one with --registry-id", s.Image.Host)
		case len(public) > 0:
			s.Image.RegistryID = fmt.Sprint(public[0].ID)
		default:
			return fmt.Errorf("no Magic Containers image registry for %s; connect it first (https://bunny.net/docs/magic-containers/image-registries)", s.Image.Host)
		}
	}
	digest, err := b.digest(ctx, s.Image)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", s.Image, err)
	}
	s.Image.Digest = digest
	return s.save()
}

// relayEnv builds the relay environment. Magic Containers has no separate
// secret type: these values are plain environment variables, visible in the
// dashboard and echoed by the API.
func relayEnv(s *State, token string) ([]mcEnv, error) {
	env := []mcEnv{{"NORDRAY_TUNNEL_TOKEN", token}, {"NORDRAY_LOG_LEVEL", "info"}}
	if s.Transport != "anycast" {
		return append(env, mcEnv{"NORDRAY_TLS_FORCE", "false"}), nil
	}
	key, err := getSecret(s.Name, "relay-tls-key")
	if err != nil {
		return nil, fmt.Errorf("credential store: %w", err)
	}
	if key == "" || s.ServerCert == "" {
		ca, cert, k, err := newRelayPKI(s.Name)
		if err != nil {
			return nil, err
		}
		if err := setSecret(s.Name, "relay-tls-key", k); err != nil {
			return nil, fmt.Errorf("credential store: %w", err)
		}
		s.CACert, s.ServerCert, key = ca, cert, k
		if err := s.save(); err != nil {
			return nil, err
		}
	}
	return append(env, mcEnv{"NORDRAY_TLS_FORCE", "true"}, mcEnv{"NORDRAY_TLS_CERT", s.ServerCert}, mcEnv{"NORDRAY_TLS_KEY", key}), nil
}

func tcpProbe(port int) map[string]any {
	return map[string]any{"tcpSocket": map[string]any{"request": map[string]any{"portNumber": port}}, "periodSeconds": 10, "failureThreshold": 3}
}

func desiredEndpoints(s *State) []mcEndpointSpec {
	eps := []mcEndpointSpec{cdnEndpoint("app", vhostPort)}
	if s.Transport == "anycast" {
		return append(eps, anycastEndpoint("tunnel-anycast", tunnelPort))
	}
	return append(eps, cdnEndpoint("tunnel", tunnelPort))
}

func createApp(ctx context.Context, b *bunny, s *State, env []mcEnv) error {
	body := map[string]any{
		"name":           "nordray-tunnel-" + s.Name,
		"runtimeType":    "shared",
		"autoScaling":    map[string]int{"min": 1, "max": 1},
		"regionSettings": map[string]any{"allowedRegionIds": []string{s.Region}, "requiredRegionIds": []string{s.Region}, "maxAllowedRegions": 1},
		"containerTemplates": []map[string]any{{
			"name": "relay", "imageName": s.Image.Name, "imageNamespace": s.Image.Namespace, "imageTag": s.Image.Tag,
			"imageDigest": s.Image.Digest, "imageRegistryId": s.Image.RegistryID, "imagePullPolicy": "ifNotPresent",
			"probes":               map[string]any{"startup": tcpProbe(vhostPort), "readiness": tcpProbe(vhostPort)},
			"environmentVariables": env,
			"endpoints":            desiredEndpoints(s),
		}},
	}
	var r struct {
		ID string `json:"id"`
	}
	if err := b.do(ctx, http.MethodPost, "/mc/apps", body, &r); err != nil {
		return err
	}
	if r.ID == "" {
		return errors.New("Magic Containers returned no app ID")
	}
	s.AppID = r.ID
	fmt.Printf("Created Magic Containers app %s.\n", s.AppID)
	return s.save()
}

func updateApp(ctx context.Context, b *bunny, s *State, env []mcEnv) error {
	if s.ContainerID == "" {
		return errors.New("state has no container ID; run setup again after checking the app in the dashboard")
	}
	base := "/mc/apps/" + url.PathEscape(s.AppID) + "/containers/" + url.PathEscape(s.ContainerID)
	err := b.do(ctx, http.MethodPatch, base, map[string]any{
		"imageTag": s.Image.Tag, "imageDigest": s.Image.Digest, "imageRegistryId": s.Image.RegistryID, "environmentVariables": env,
	}, nil)
	if err != nil {
		return err
	}
	eps, err := b.listEndpoints(ctx, s.AppID)
	if err != nil {
		return err
	}
	has := map[string]bool{}
	for _, e := range eps {
		has[e.ID] = true
	}
	// Create missing endpoints, then remove the one for the other transport.
	for _, want := range desiredEndpoints(s) {
		id := map[string]string{"app": s.AppEndpointID, "tunnel": s.TunnelEndpointID, "tunnel-anycast": s.AnycastEndpointID}[want.DisplayName]
		if id != "" && has[id] {
			continue
		}
		var r struct {
			ID string `json:"id"`
		}
		if err := b.do(ctx, http.MethodPost, base+"/endpoints", want, &r); err != nil {
			return err
		}
		fmt.Printf("Created endpoint %s.\n", r.ID)
	}
	if s.Transport == "anycast" && s.TunnelEndpointID != "" {
		if err := deleteEndpoint(ctx, b, s, s.TunnelEndpointID); err != nil {
			return err
		}
		if s.TunnelPullZoneID != 0 {
			if err := b.do(ctx, http.MethodDelete, fmt.Sprintf("/pullzone/%d", s.TunnelPullZoneID), nil, nil); err != nil && !isNotFound(err) {
				return err
			}
		}
		s.TunnelEndpointID, s.TunnelPullZoneID, s.TunnelHost = "", 0, ""
	}
	if s.Transport == "wss" && s.AnycastEndpointID != "" {
		if err := deleteEndpoint(ctx, b, s, s.AnycastEndpointID); err != nil {
			return err
		}
		s.AnycastEndpointID, s.AnycastAddr = "", ""
	}
	return s.save()
}

func deleteEndpoint(ctx context.Context, b *bunny, s *State, id string) error {
	err := b.do(ctx, http.MethodDelete, "/mc/apps/"+url.PathEscape(s.AppID)+"/endpoints/"+url.PathEscape(id), nil, nil)
	if err == nil || isNotFound(err) {
		fmt.Printf("Deleted endpoint %s.\n", id)
		return nil
	}
	return err
}

// readEndpoints records the IDs and addresses Bunny returned. Endpoints are
// matched by display name only inside our own app.
func readEndpoints(ctx context.Context, b *bunny, s *State) error {
	deadline := time.Now().Add(3 * time.Minute)
	for {
		app, err := b.getApp(ctx, s.AppID)
		if err != nil {
			return err
		}
		if len(app.ContainerTemplates) != 1 {
			return fmt.Errorf("app %s has %d containers; expected 1", s.AppID, len(app.ContainerTemplates))
		}
		s.ContainerID = app.ContainerTemplates[0].ID
		eps, err := b.listEndpoints(ctx, s.AppID)
		if err != nil {
			return err
		}
		for _, e := range eps {
			switch e.DisplayName {
			case "app":
				s.AppEndpointID, s.AppPullZoneID = e.ID, e.pullZone()
			case "tunnel":
				s.TunnelEndpointID, s.TunnelPullZoneID, s.TunnelHost = e.ID, e.pullZone(), e.PublicHost
			case "tunnel-anycast":
				s.AnycastEndpointID, s.AnycastAddr = e.ID, e.PublicHost
			}
		}
		if err := s.save(); err != nil {
			return err
		}
		ready := s.AppPullZoneID != 0 && (s.Transport == "wss" && s.TunnelPullZoneID != 0 && s.TunnelHost != "" ||
			s.Transport == "anycast" && strings.Contains(s.AnycastAddr, ":"))
		if ready {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("endpoints did not get addresses within 3 minutes; run setup again later")
		}
		time.Sleep(pollInterval)
	}
}

// configureZones applies the settings measured to be necessary on
// 31 October 2026: Magic Containers creates pull zones with WebSockets on and
// without Host forwarding, and Shield zones start in learning mode.
func configureZones(ctx context.Context, b *bunny, s *State) error {
	z, err := b.getPullZone(ctx, s.AppPullZoneID)
	if err != nil {
		return err
	}
	s.AppPullZoneName = z.Name
	if err := b.updatePullZone(ctx, s.AppPullZoneID, map[string]any{
		"AddHostHeader": true, "EnableWebSockets": false, "EnableSmartCache": false,
		"CacheControlMaxAgeOverride": 0, "CacheControlPublicMaxAgeOverride": 0,
	}); err != nil {
		return err
	}
	if s.TunnelPullZoneID != 0 {
		if err := b.updatePullZone(ctx, s.TunnelPullZoneID, map[string]any{"EnableWebSockets": true, "EnableSmartCache": false}); err != nil {
			return err
		}
	}
	if s.ShieldZoneID == 0 {
		var existing struct {
			Data struct {
				ShieldZoneID int64 `json:"shieldZoneId"`
			} `json:"data"`
		}
		err := b.do(ctx, http.MethodGet, fmt.Sprintf("/shield/shield-zone/get-by-pullzone/%d", s.AppPullZoneID), nil, &existing)
		switch {
		case err == nil && existing.Data.ShieldZoneID != 0:
			s.ShieldZoneID = existing.Data.ShieldZoneID
		case err == nil || isNotFound(err):
			var created struct {
				Data struct {
					ShieldZone struct {
						ShieldZoneID int64 `json:"shieldZoneId"`
					} `json:"shieldZone"`
				} `json:"data"`
			}
			if err := b.do(ctx, http.MethodPost, "/shield/shield-zone", map[string]any{"pullZoneId": s.AppPullZoneID, "shieldZone": map[string]any{"wafEnabled": true}}, &created); err != nil {
				return err
			}
			s.ShieldZoneID = created.Data.ShieldZone.ShieldZoneID
			fmt.Printf("Created Shield zone %d.\n", s.ShieldZoneID)
		default:
			return err
		}
		if err := s.save(); err != nil {
			return err
		}
	}
	return b.do(ctx, http.MethodPatch, "/shield/shield-zone", map[string]any{"shieldZoneId": s.ShieldZoneID, "shieldZone": shieldSettings(s.ShieldZoneID)}, nil)
}

func waitActive(ctx context.Context, b *bunny, s *State) error {
	deadline := time.Now().Add(5 * time.Minute)
	for {
		app, err := b.getApp(ctx, s.AppID)
		if err != nil {
			return err
		}
		if app.Status == "active" {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("app %s is still %q after 5 minutes; check its logs in the dashboard and run setup again", s.AppID, app.Status)
		}
		fmt.Printf("Waiting for the relay (%s)...\n", app.Status)
		time.Sleep(pollInterval)
	}
}
