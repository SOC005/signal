# Sentinel Atlas

**Sentinel Atlas** is a polished, privacy-conscious browser dashboard for triaging IPv4, IPv6, domains, and ASN identifiers. It is designed for authorized incident-response, fraud-review, and public-safety workflows—not for surveillance or URL reputation checks.

## What it does

- Validates IPv4, IPv6, domains, and ASN values locally before making a request.
- Performs live, no-key IP network and abuse-contact lookups through [RIPEstat](https://stat.ripe.net/).
- Resolves A, AAAA, MX, NS, and TXT DNS records using Cloudflare DNS-over-HTTPS and retrieves domain registration data through RDAP.
- Clearly separates observed routing data from **VPN/proxy risk signals**. The interface never claims a VPN or proxy result without a configured, attributable risk-data provider.
- Keeps a local, in-browser case history; no query history is sent to a Sentinel Atlas server because there is no server.

> **Important:** Use only for a legitimate, authorized purpose. Network attribution is probabilistic: registrant, ASN, and abuse-contact data do not identify a person. Follow applicable law, due process, retention policy, and provider terms before acting on results.

## Run locally

This is a dependency-free static app. Any static server will work:

```bash
python3 -m http.server 8080
```

Then browse to `http://localhost:8080`.

## Data sources and limitations

| Data | Source | Notes |
| --- | --- | --- |
| Prefix, ASN, abuse contact | RIPEstat | Public Internet-routing information; coverage and freshness vary. |
| DNS | Cloudflare DNS-over-HTTPS | Live public DNS only. |
| Registration | RDAP.org | The authoritative registry response varies by TLD/RIR. |
| VPN/proxy | Optional provider integration | Requires an approved provider with legal authorization. The app intentionally displays “not assessed” by default. |

No identity resolution, device tracking, credential lookup, or URL scanning is included.

## GitHub publishing

Push this repository to GitHub and enable **Settings → Pages → Deploy from a branch → main / root** to publish the static application.

