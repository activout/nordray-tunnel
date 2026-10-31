package main

import (
	"fmt"
	"strings"
)

// Image identifies the relay container image. Deployments are pinned to Digest.
type Image struct {
	Host       string `json:"host"`
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
	Tag        string `json:"tag"`
	Digest     string `json:"digest,omitempty"`
	RegistryID string `json:"registryId,omitempty"`
}

func (i Image) String() string { return fmt.Sprintf("%s/%s/%s:%s", i.Host, i.Namespace, i.Name, i.Tag) }

// parseImage accepts host/namespace/name:tag, for example
// ghcr.io/activout/nordray-tunnel-relay:sha-abc. Magic Containers addresses
// images by namespace, name and tag, and pins them by digest itself.
func parseImage(ref string) (Image, error) {
	bad := fmt.Errorf("invalid image %q: want host/namespace/name:tag", ref)
	if strings.Contains(ref, "@") {
		return Image{}, fmt.Errorf("invalid image %q: give a tag; the digest is resolved and pinned automatically", ref)
	}
	host, rest, ok := strings.Cut(ref, "/")
	if !ok || !strings.Contains(host, ".") {
		return Image{}, bad
	}
	slash := strings.LastIndex(rest, "/")
	if slash <= 0 {
		return Image{}, bad
	}
	ns, nameTag := rest[:slash], rest[slash+1:]
	name, tag, ok := strings.Cut(nameTag, ":")
	if !ok || name == "" || tag == "" || tag == "latest" {
		return Image{}, fmt.Errorf("invalid image %q: give an explicit, immutable tag (not latest)", ref)
	}
	return Image{Host: strings.ToLower(host), Namespace: ns, Name: name, Tag: tag}, nil
}
