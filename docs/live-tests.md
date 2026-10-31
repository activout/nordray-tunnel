# Live tests

Two manual workflows test against the real Bunny account. Both run only when started from the Actions tab, share one concurrency lock (`live-bunny`) and are never cancelled part-way.

| Workflow | What it changes in Bunny | Use it for |
| --- | --- | --- |
| `live-quick` | Only the container of the standing installation (`update --image`). No DNS, no new resources. | Every relay or agent change: about five minutes |
| `live-e2e` | Everything, from nothing: app, pull zones, Shield, DNS record `e2e-<run id>.nordray.net` and certificate. Torn down at the end. | Before releases, and after changes to setup, add or destroy |

Both need the environment `live-bunny` with the secret `BUNNY_API_KEY`. The key gives full access to the account, so give the environment a required reviewer.

## The standing installation for live-quick

Create it once from an operator machine with the CLI built from main:

```sh
nordray-tunnel setup --name quick --region DK --image ghcr.io/activout/nordray-tunnel-relay:sha-<main commit>
nordray-tunnel add web --name quick --hostname tunnel-test.nordray.net --local http://127.0.0.1:18081
```

Then store what the workflow needs. The state has IDs and addresses only. The token comes from the OS credential store (on macOS: `security find-generic-password -s nordray-tunnel -a quick/tunnel-token -w`):

```sh
gh variable set LIVE_QUICK_STATE < "<config dir>/nordray-tunnel/quick/state.json"
gh secret set LIVE_QUICK_TUNNEL_TOKEN --env live-bunny
```

`update` does not change the IDs, so the variable stays valid. It costs about the price of the idle container (frps fits in one 64 MB block) plus nothing for the tunnel while no agent is connected. Remove it with `nordray-tunnel destroy --name quick`, then delete the variable and the secret.

## Cautions

- Every `live-e2e` run leaves a free Shield zone: the Shield API has no delete operation.
- Certificates are issued per hostname. `live-e2e` uses a new hostname each run, which stays well inside the per-domain limit. Every hostname also appears in public Certificate Transparency logs.
- GitHub's runners are in data centres; Shield may occasionally challenge them. The live checks log a 403 as such.
