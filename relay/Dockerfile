# Nordray Tunnels relay: unmodified upstream frps with a baked-in config.
# Upstream image pinned by multi-arch index digest (frp v0.71.1, Alpine based).
FROM fatedier/frps:v0.71.1@sha256:48720c81f048e842f7f0b8053753c1a8514053d59d2dee8a953f67995de73a18

COPY frps.toml /etc/frp/frps.toml
COPY --chmod=0555 entrypoint.sh /usr/local/bin/nordray-relay
ENV NORDRAY_LOG_LEVEL=info
# Unprivileged ports only, so no root is needed.
USER 65534:65534
EXPOSE 7000 8080
ENTRYPOINT ["/usr/local/bin/nordray-relay"]
