# Evidence tables: Netkeep misattribution (2026-11)

Companion to [2026-11-misattribution.md](2026-11-misattribution.md). Everything here is derived from the live daemon and its journal; nothing was modified.

All times are `+03:30`. Rule creation times are decoded from `ui-<epoch_secs>`. Counts are as-of the stated snapshot and will drift.

---

## A. Corpus, commands, and field definitions

### A.1 Corpus

| Artifact | Value |
|---|---|
| Journal | 2,414,333 lines, 2026-09-30 09:50:44 → 2026-11-12 09:46:58 |
| `policy:` verdicts | 199,073 |
| `transparent proxy:` lines | 2,154,978 |
| `sweep_pending: auto-resolving` | 3,674 |
| `dns-forwarder: … process=… domain=…` | 29,896 |
| Flow events | 5,000 (2026-11-12 00:17–09:43) |
| Rules at 09:41 / 10:39 / 2026-11-13 00:25 | 599 / 604 / 602 |

The journal is 420 MB and stays outside the repository. Rule dumps and flow dumps are JSON from the control socket.

### A.2 Read-only capture

```bash
# Rules (no writes)
netkeep-cli rule list --format json > rules.json

# Flows
netkeep-cli flow list --limit 5000 --format json > flows.json

# Journal
journalctl -u netkeepd -o short-iso > journal.txt

# A single rule
netkeep-cli rule list --id ui-1794205260 --format json
```

The daemon runs as root; `/var/lib/netkeep/netkeep.db` is root-only. The database was never opened directly. No `allow`, `deny`, `route`, `pending resolve`, or config command was issued during the investigation.

### A.3 `policy:` line grammar

```
policy: id=<rule-id> action=<Allow|Route|Deny|Ask> process=<None|Some("<name>")>[ (<app-label>)] domain=<None|Some("<domain>")> dst=<ip>:<port> src=:<source-port>
```

`src=` is the client source port only; the client IP is not in the policy line. The rule id is the id of the rule that produced the verdict, not the flow id.

### A.4 `transparent proxy:` line grammar

```
transparent proxy: <client-ip>:<source-port> -> <target-host>:<port> via <proxy-ip>:<port>
```

`target-host` is what the proxy dialled. It can be the in-band name, a DNS-derived hint, or a fallback candidate; the proxy logs retries separately. It is the best available in-band evidence, not an infallible one.

### A.5 `sweep_pending` grammar

```
sweep_pending: auto-resolving <pending-id> (<None|Some("<process>")> → <action>)
```

The line deliberately omits the rule id, the domain, and the destination. Rule ids must be reconstructed from their epoch or from the surrounding policy lines.

### A.6 Confidence labels used in the report

- **Proven:** directly visible in `policy:`/`transparent proxy:`/`sweep_pending:` lines or in the rule store.
- **Inferred:** the mechanism fits all observations, but the exact upstream step was not logged.
- **Not established:** the available evidence cannot decide it.

---

## B. Rule store snapshots

| Snapshot | Rules | Permanent | UntilRestart | Allow | Route | Deny |
|---|---|---|---|---|---|---|
| 2026-11-12 09:41 (`rules.json`) | 599 | 596 | 3 | 298 | 267 | 34 |
| 2026-11-12 10:39 (`rules_now.json`) | 604 | 597 | 7 | 302 | 267 | 35 |
| 2026-11-13 00:25 (live) | 602 | 599 | 3 | 298 | 268 | 36 |

Destination kinds at 09:41: `DomainExact` 427, `DomainWildcard` 129, `Any` 34, `IpExact` 9.

Rules with `process_name: null`: 22. Rules with `process_exe: null`: 116.

The eight rules added between 09:41 and 10:39, and the three that disappeared, are listed in the main report's §4.8 and §8. The `UntilRestart` rules added during the investigation (`ui-179446*`) are gone from the 00:25 dump after the 23:45 restart. `ui-1794472527` and `ui-1794510938` are also gone; their stored duration was never captured.

### Rules per process (top 20)

| Process | Rules |
|---|---|
| kilo | 128 |
| betterbird-bin | 45 |
| codium | 40 |
| codex | 27 |
| synara | 24 |
| (none) | 22 |
| java | 21 |
| gvfsd-http | 21 |
| helm | 18 |
| t3code | 12 |
| opencode | 11 |
| ticktick | 9 |
| node | 9 |
| dockerd | 9 |
| chromium | 8 |
| curl | 8 |
| freebuff | 8 |
| mimo | 7 |
| bun | 7 |
| WebKitNetworkProcess | 7 |

### Domains with the most exact-match rules

| Domain | Rules | Processes | Process names |
|---|---|---|---|
| `models.dev` | 19 | 12 | codex, codium, gvfsd-http, kilo, llm-leaders, mimo, node, opencode, ssh, synara, t3code, xiaomi-mimo-desktop |
| `events.kiloapps.io` | 12 | 7 | (none), codex, gvfsd-http, kilo, opencode, synara, t3code |
| `sm.logicamp.dev` | 11 | 10 | (none), chromium, freelens-k8s-proxy, git-remote-http, gitea-mcp, helm, kilo, kubectl, kubefwd, ssh |
| `ingest.kilosessions.ai` | 11 | 5 | codex, codium, gvfsd-http, kilo, opencode |
| `registry.npmjs.org` | 10 | 7 | bun, freelens, mimo, node, `npm exec @drawi`, pnpm, synara |
| `github.com` | 10 | 9 | cargo, curl, freebuff, git-remote-http, helm, java, kilo, ssh, uv |
| `raw.githubusercontent.com` | 8 | 7 | claude, codex, codium, curl, java, kilo, t3code |
| `models.opencode.ai` | 8 | 6 | codex, codium, kilo, opencode, opencode-cli, synara |
| `clerk.sailresearch.com` | 7 | 7 | codex, codium, gvfsd-http, kilo, opencode, opencode-cli, python3.14 |
| `token-plan-sgp.xiaomimimo.com` | 6 | 4 | claude, kilo, mimo, trae |
| `stitch.googleapis.com` | 6 | 4 | claude, kilo, mimo, xiaomi-mimo-desktop |
| `redirector.gvt1.com` | 6 | 6 | chrome, freebuff, marktext, nimbalyst, t3code, xiaomi-mimo-desktop |

### Rules with zero `policy:` matches in 2.41 M journal lines (71)

| Rule | Action | Duration | Process | Exe | Destination |
|---|---|---|---|---|---|
| `ui-1790749399` | Allow | Permanent | node | /usr/bin/node | DomainWildcard(api.mega.co.nz) |
| `ui-1790754705` | Allow | Permanent | kilo | /home/mohamad/.vscode-oss/extensions/kilocode.kilo-code-7.8.1-linux-x64/bin/kilo | DomainWildcard(crates.io) |
| `ui-1791356674` | Allow | Permanent | cef_server | /opt/intellij-idea-ultimate-edition/plugins/jcef-plugin/jcef/cef_server | DomainWildcard(jetbrains.com) |
| `ui-1791742533` | Deny | Permanent | kilo | /home/mohamad/.vscode-oss/extensions/kilocode.kilo-code-7.8.8-linux-x64/bin/kilo | DomainExact(otel.gitkraken.com) |
| `ui-1792225203` | Route | Permanent | freelens-k8s-proxy | — | DomainExact(bnpl.dohd2z.kaariiz.com) |
| `ui-1792232817` | Allow | Permanent | betterbird-bin | /tmp/Downloads/betterbird-153.5.0esr-bb11.en-US.linux-x86_64/betterbird/betterbird-bin | DomainExact(smtp.gmail.com) |
| `ui-1792232823` | Allow | Permanent | betterbird-bin | /tmp/Downloads/betterbird-153.5.0esr-bb11.en-US.linux-x86_64/betterbird/betterbird-bin | DomainExact(pop.gmail.com) |
| `ui-1792233027` | Allow | Permanent | betterbird-bin | /tmp/Downloads/betterbird-153.5.0esr-bb11.en-US.linux-x86_64/betterbird/betterbird-bin | DomainExact(pop3.panahiran.com) |
| `ui-1792233099` | Allow | Permanent | betterbird-bin | /tmp/Downloads/betterbird-153.5.0esr-bb11.en-US.linux-x86_64/betterbird/betterbird-bin | DomainExact(imap.panahiran.com) |
| `ui-1792240728` | Route | Permanent | cortex-scout | /home/mohamad/.local/bin/cortex-scout | DomainWildcard(google.com) |
| `ui-1792240736` | Route | Permanent | cortex-scout | /home/mohamad/.local/bin/cortex-scout | DomainWildcard(bing.com) |
| `ui-1792240745` | Route | Permanent | cortex-scout | /home/mohamad/.local/bin/cortex-scout | DomainExact(duckduckgo.com) |
| `ui-1792243962` | Allow | Permanent | kilo | /home/mohamad/.vscode-oss/extensions/kilocode.kilo-code-7.8.8-linux-x64/bin/kilo | DomainExact(benchmarklist.com) |
| `ui-1792314422` | Allow | Permanent | betterbird-bin | /opt.old/betterbird/betterbird-bin | DomainExact(autoconfig.panahiran.com) |
| `ui-1792314432` | Allow | Permanent | betterbird-bin | /opt.old/betterbird/betterbird-bin | DomainExact(smtp.panahiran.com) |
| `ui-1792314437` | Allow | Permanent | betterbird-bin | /opt.old/betterbird/betterbird-bin | DomainExact(imap.panahiran.com) |
| `ui-1792314441` | Allow | Permanent | betterbird-bin | /opt.old/betterbird/betterbird-bin | DomainExact(pop3.panahiran.com) |
| `ui-1792317579` | Allow | Permanent | kilo | /usr/lib/kilo/kilo | DomainWildcard(bing.com) |
| `ui-1792329631` | Route | Permanent | chrome | /opt/google/chrome/chrome | DomainExact(clients2.google.com) |
| `ui-1792661956` | Allow | Permanent | — | — | DomainExact(devsie2r.kaariiz.com) |
| `ui-1792661976` | Allow | Permanent | chromium | — | DomainExact(devsie2r.kaariiz.com) |
| `ui-1792666760` | Allow | Permanent | chromium | — | DomainExact(searxng.kaariiz.com) |
| `ui-1792667283` | Route | Permanent | kilo | /usr/lib/kilo/kilo | DomainExact(chromewebstore.googleapis.com) |
| `ui-1792844515` | Deny | Permanent | rtk | /usr/bin/rtk | DomainExact(telemetry.rtk-ai.app) |
| `ui-1792914276` | Allow | Permanent | — | — | DomainExact(searxng.kaariiz.com) |
| `ui-1793013554` | Route | Permanent | codex | — | DomainExact(api.zed.dev) |
| `ui-1793014158` | Allow | Permanent | codium | /opt/vscodium-bin/codium | DomainExact(worker.clerkprod-cloudflare.net) |
| `ui-1793622338` | Allow | Permanent | kilo | /usr/lib/kilo/kilo | DomainExact(benchmarklist.com) |
| `ui-1793692950` | Route | Permanent | kilo | /home/mohamad/.vscode-oss/extensions/kilocode.kilo-code-7.8.18-linux-x64/bin/kilo | DomainExact(benchmarklist.com) |
| `ui-1793693058` | Route | Permanent | codium | /opt/vscodium-bin/codium | DomainExact(arena.ai) |
| `ui-1793694533` | Route | Permanent | bun | /tmp/.mount_FreebulQ8axM/resources/bun/bun | DomainWildcard(cloudflare.com) |
| `ui-1793694746` | Route | Permanent | codium | /opt/vscodium-bin/codium | DomainWildcard(r2.dev) |
| `ui-1793702508` | Route | Permanent | codex | /home/mohamad/.vscode-oss/extensions/openai.chatgpt-26.1021.22027-linux-x64/bin/linux-x86_64/codex | DomainExact(auth.tokenharbor.ai) |
| `ui-1793702653` | Route | Permanent | gvfsd-http | /usr/lib/gvfsd-http | DomainExact(auth.tokenharbor.ai) |
| `ui-1793778587` | Route | Permanent | kilo | /usr/lib/kilo/kilo | DomainWildcard(vercel-dns-013.com) |
| `ui-1793781403` | Route | Permanent | codium | — | DomainExact(apinex.bond) |
| `ui-1794055706` | Allow | Permanent | — | — | DomainExact(oevaite.kaariiz.com) |
| `ui-1794204616` | Route | Permanent | codex | /usr/lib/openai-codex/bin/codex | DomainExact(ingest.kilosessions.ai) |
| `ui-1794205260` | Route | Permanent | ssh | /usr/bin/ssh | DomainExact(models.dev) |
| `ui-1794206392` | Route | Permanent | trae | — | DomainExact(token-plan-sgp.xiaomimimo.com) |
| `ui-1794240746` | Route | Permanent | gvfsd-http | /usr/lib/gvfsd-http | DomainExact(cdn.tapsell.xyz) |
| `ui-1794261781` | Route | Permanent | codium | /opt/vscodium-bin/codium | DomainExact(api.ipify.org) |
| `ui-1794291506` | Route | Permanent | codium | /opt/vscodium-bin/codium | DomainExact(avro.apache.org) |
| `ui-1794292567` | Route | Permanent | curl | /usr/bin/curl | DomainExact(avatars.githubusercontent.com) |
| `ui-1794300843` | Route | Permanent | synara | /opt/synara/synara | DomainExact(workos.com) |
| `ui-1794301311` | Route | Permanent | kilo | /home/mohamad/.vscode-oss/extensions/kilocode.kilo-code-7.8.18-linux-x64/bin/kilo | DomainExact(opencode.ai) |
| `ui-1794304606` | Route | Permanent | opencode | /usr/bin/opencode | DomainExact(ingest.kilosessions.ai) |
| `ui-1794317019` | Route | Permanent | — | — | IpExact(34.107.238.235) |
| `ui-1794317770` | Route | Permanent | codium | /opt/vscodium-bin/codium | DomainExact(krabka.io) |
| `ui-1794317857` | Route | Permanent | codium | /opt/vscodium-bin/codium | DomainExact(nightlies.apache.org) |
| `ui-1794317868` | Route | Permanent | codium | /opt/vscodium-bin/codium | DomainExact(docs.starrocks.io) |
| `ui-1794319687` | Route | Permanent | codium | /opt/vscodium-bin/codium | IpExact(23.216.77.39) |
| `ui-1794345856` | Route | Permanent | kilo | /home/mohamad/.vscode-oss/extensions/kilocode.kilo-code-7.8.27-linux-x64/bin/kilo | DomainExact(images.openai.com) |
| `ui-1794346110` | Route | Permanent | synara | /opt/synara/synara | DomainExact(images.openai.com) |
| `ui-1794346286` | Route | Permanent | kilo | /home/mohamad/.vscode-oss/extensions/kilocode.kilo-code-7.8.27-linux-x64/bin/kilo | DomainExact(llm-stats.com) |
| `ui-1794376143` | Route | Permanent | opencode | /usr/bin/opencode | DomainExact(api.ipify.org) |
| `ui-1794379183` | Route | Permanent | t3code | /opt/t3code-bin/t3code | DomainExact(avatars.githubusercontent.com) |
| `ui-1794380877` | Route | Permanent | nimbalyst | /tmp/.mount_NimbalQkWITA/nimbalyst | DomainExact(extensions.nimbalyst.com) |
| `ui-1794384763` | Deny | Permanent | freelens | /usr/share/freelens/freelens | DomainExact(hub.helm.sh) |
| `ui-1794393759` | Route | Permanent | codium | /opt/vscodium-bin/codium | DomainExact(bun.sh) |
| `ui-1794394456` | Route | Permanent | kilo | /home/mohamad/.vscode-oss/extensions/kilocode.kilo-code-7.8.27-linux-x64/bin/kilo | DomainExact(worker.clerkprod-cloudflare.net) |
| `ui-1794395287` | Route | Permanent | npm exec @drawi | — | DomainExact(registry.npmjs.org) |
| `ui-1794395506` | Route | Permanent | synara | /tmp/synara-patch/appimage/squashfs-root/synara | DomainExact(fonts.googleapis.com) |
| `ui-1794395521` | Route | Permanent | synara | /tmp/synara-patch/appimage/squashfs-root/synara | DomainExact(registry.npmjs.org) |
| `ui-1794396131` | Route | Permanent | synara | /home/mohamad/Projects/synara-build/pkgbuild/pkg/synara/opt/synara/synara | DomainExact(fonts.googleapis.com) |
| `ui-1794408017` | Route | Permanent | opencode | — | DomainExact(clerk.sailresearch.com) |
| `ui-1794408306` | Route | Permanent | opencode-cli | — | DomainExact(clerk.sailresearch.com) |
| `diag-curl-apinex-direct` | Route | Permanent | curl | — | DomainExact(api.apinex.bond) |
| `record-vpn-mitmdump` | Route | Permanent | mitmdump | — | Any |
| `trae-mimo-vpn` | Route | Permanent | trae | — | DomainExact(xiaomimimo.com) |
| `(empty)` | Allow | Permanent | — | — | DomainExact(www.google.comm) |

The `(empty)` row is a rule whose stored id is the empty string and whose domain contains the `www.google.comm` typo. It is listed for completeness; check it before deleting anything by id.

---

## C. Policy verdict corpus

| Artifact | Value |
|---|---|
| `policy:` lines parsed | 199,073 |
| With a domain | 161,479 |
| Without a domain | 37,594 |
| Distinct rule ids seen | 1,724 |
| Rules in the 09:41 snapshot never seen | 71 |
| Actions | Route 102,233; Allow 85,748; Deny 11,090; Ask 2 |

Note: 1,724 distinct rule ids appear in the journal but only 599 rules exist in the 09:41 snapshot. Rules are deleted or expire (`UntilRestart`) while their historical verdicts remain. This is why a rule id is the stable join key and a rule name is not.

### Destination port of domain-bearing verdicts (top 20)

| Port | Verdicts |
|---|---|
| 443 | 149,571 |
| 80 | 5,324 |
| 22 | 2,046 |
| 123 | 1,026 |
| 53782 | 919 |
| 5228 | 691 |
| 993 | 407 |
| 6464 | 335 |
| 8080 | 272 |
| 43963 | 233 |
| 19302 | 149 |
| 2096 | 132 |
| 3478 | 94 |
| 6443 | 73 |
| 4318 | 71 |
| 1080 | 70 |
| 5222 | 64 |
| 465 | 63 |
| 25 | 58 |
| 2053 | 54 |

Non-443 domain-bearing verdicts: **11,908**.

### Rules applied most often

| Rule | Matches | Action | Process | Destination |
|---|---|---|---|---|
| `ui-1790749270` | 28,906 | Route | chromium | Any |
| `ui-1793008069` | 25,566 | Route | brave | Any |
| `ui-1794062480` | 15,055 | Route | trae | Any |
| `ui-1790770051` | 11,843 | Route | Telegram | Any |
| `ui-1791022908` | 11,082 | Allow | — | DomainWildcard(chatgpt.com) |
| `ui-1793897682` | 7,877 | — | — | not in the 09:41 snapshot |
| `ui-1790749282` | 7,761 | Allow | Windscribe | Any |
| `ui-1790749341` | 4,905 | Allow | megasync | DomainWildcard(api.mega.co.nz) |
| `ui-1790839511` | 3,505 | Allow | firefox | Any |
| `ui-1790749472` | 2,969 | — | — | not in the 09:41 snapshot |
| `ui-1792666817` | 2,834 | Allow | — | IpExact(5.202.198.83) |
| `ui-1790749326` | 2,699 | — | — | not in the 09:41 snapshot |
| `ui-1790749318` | 2,682 | — | — | not in the 09:41 snapshot |
| `ui-1793514994` | 2,616 | Deny | kilo | DomainExact(events.kiloapps.io) |
| `ui-1790749393` | 2,340 | Allow | node | DomainExact(registry.npmjs.org) |
| `ui-1791022832` | 2,336 | Allow | gvfsd-http | DomainExact(api.ipify.org) |
| `ui-1793955219` | 2,298 | — | — | not in the 09:41 snapshot |
| `ui-1790750180` | 2,289 | Allow | NetworkManager | Any |
| `ui-1790844327` | 1,725 | — | — | not in the 09:41 snapshot |
| `ui-1793949783` | 1,680 | Route | codex | Any |

### Policy verdicts per process (top 15)

| Process | Verdicts | Domain-bearing |
|---|---|---|
| chromium | 31,339 | 28,041 |
| brave | 30,866 | 25,680 |
| trae | 25,375 | 19,977 |
| kilo | 23,617 | 23,105 |
| Telegram | 11,843 | 4,248 |
| codium | 8,654 | 8,624 |
| codex | 8,049 | 7,864 |
| Windscribe | 7,761 | 2,715 |
| megasync | 6,185 | 5,171 |
| python3.14 | 5,417 | 4,915 |
| NetworkManager | 5,258 | 4,673 |
| gvfsd-http | 4,010 | 3,647 |
| firefox | 3,999 | 3,389 |
| node | 3,621 | 3,070 |
| synara | 2,483 | 2,482 |
| ssh | 2,190 | 2,051 |

### Destination IPs carrying the most distinct domains

| Destination IP | Distinct domains |
|---|---|
| `10.10.34.35` | 258 |
| `188.114.99.0` | 147 |
| `188.114.98.0` | 137 |
| `10.10.34.36` | 119 |
| `104.18.12.205` | 90 |
| `2001:4188:2:600:10:10:34:36` | 87 |
| `2a06:98c1:3122::` | 82 |
| `2a06:98c1:3123::` | 79 |
| `104.18.13.205` | 72 |
| `2001:4188:2:600:10:10:34:35` | 52 |

The private `10.10.34.x` entries are the tunnel interface addresses; they aggregate every proxied name and are not meaningful identities. The `188.114.9x.0` and `2a06:98c1:312x::` entries are Cloudflare anycast.

IPs with more than one domain: **2,070 of 7,070**. Restricting to port 443: **1,876 of 6,546**.

#### `5.202.198.83` — 22 domains observed in `policy:` lines

- `auth.dohd2z.kaariiz.com`
- `bnpl.dohd2z.kaariiz.com`
- `claw.kaariiz.com`
- `claw.logicamp.dev`
- `crew.logicamp.dev`
- `devsie2r.kaariiz.com`
- `docskl3w.kaariiz.com`
- `git.logicamp.dev`
- `kaneo.logicamp.dev`
- `koquaec.kaariiz.com`
- `lcr.logicamp.dev`
- `litellm.kaariiz.com`
- `m.tameshk-company.ir`
- `ms-3.preview.kaariiz.com`
- `n8nmeixeec.kaariiz.com`
- `oevaite.kaariiz.com`
- `sm.logicamp.dev`
- `sub2api.kaariiz.com`
- `ugapoan.kaariiz.com`
- `vk.logicamp.dev`
- `waexuhu.kaariiz.com`
- `zentao.logicamp.dev`

#### `188.114.98.0` — 137 domains observed in `policy:` lines

- `0fa9010fca70.w.hcaptcha.com`
- `32c6a2fed52b.w.hcaptcha.com`
- `471e5c6c0c21.w.hcaptcha.com`
- `a.inference.net`
- `a.pub.network`
- `ab.chatgpt.com`
- `acrop.net`
- `addoncrop.com`
- `analytics-api.zintrack.com`
- `api-player.globalsun.io`
- `api.64e23e873ff04bfa2bbc2ae45430381281e7f360.com`
- `api.6f0088725badd19291a5fa178ba5d2933f4aa537.com`
- `api.90341b4610d2ad771c3d7cef15e3e700b647dd3a.com`
- `api.9d992bc3669c19219bd556efc6b9569b2d09ff60.com`
- `api.bff0cfdfc3d893fc4c14affb538d23544b90541d.com`
- `api.dnschecker.org`
- `api.gitkraken.dev`
- `api.iconify.design`
- `api.ipify.org`
- `api.jetpusher.com`
- `api.oaistatsig.com`
- `api.simplesvg.com`
- `api.zed.dev`
- `api.zeroeval.com`
- `apinex.bond`
- `app.fusebox.fm`
- `app.mpay.cards`
- `app.wafer.ai`
- `arena.ai`
- `audinifer.com`
- `backlog.so`
- `basescan.org`
- `beeg.com`
- `benchlm.ai`
- `benchmarklist.com`
- `btloader.com`
- `bun.sh`
- `bzr.openai.com`
- `cdn.agentclientprotocol.com`
- `cdn.api.btloader.com`
- `cdn.datatables.net`
- `cdn.id5-sync.com`
- `cdn.tapsell.xyz`
- `chatgpt.com`
- `clerk.openrouter.ai`
- `clerk.relace.ai`
- `clerk.sailresearch.com`
- `clerk.t3.codes`
- `codex-cloud-backend.chatgpt.com`
- `collector.onedollarstats.com`
- `connector-id-dfbccc248e43b6fe7d187129e21b5ec8.web-sandbox.oaiusercontent.com`
- `connector_68de829bf7648191acd70a907364c67c.web-sandbox.oaiusercontent.com`
- `csp-reporting.cloudflare.com`
- `d3a6ceb6aef0.w.hcaptcha.com`
- `deaf32d0d357.w.hcaptcha.com`
- `debezium.io`
- `dl.gitea.com`
- `dnschecker.org`
- `docs.gitea.com`
- `docs.mitmproxy.org`
- `e561e7fb621e.w.hcaptcha.com`
- `easypoller.com`
- `edge.cdn-vitals.com`
- `embed.tawk.to`
- `events.kiloapps.io`
- `example.com`
- `file.pushe.co`
- `files.downloadhelper.net`
- `flagcdn.com`
- `flags.inference.net`
- `hagen.challenges.cloudflare.com`
- `i.doodcdn.io`
- `i.mscdn.ai`
- `images.openai.com`
- `images.versus.io`
- `img.lulucdn.com`
- `ingest.kilosessions.ai`
- `ingest.t3.codes`
- `ipapi.co`
- `ipwho.is`
- `js.globalsun.io`
- `json-update-button.eytvd.workers.dev`
- `kitploit.com`
- `lebrel.ai`
- `live.thunderbird.net`
- `llm-stats.com`
- `logs.mosevura.com`
- `lulustream.com`
- `luluvido.com`
- `mcp.openrouter.ai`
- `mcpservers.org`
- `media.nano-gpt.cloud`
- `mintcdn.com`
- `models.dev`
- `models.opencode.ai`
- `moviejavan.com`
- `node.somenano.com`
- `opencode.ai`
- `openrouter.ai`
- `otel.gitkraken.com`
- `persistent.oaistatic.com`
- `ping.wappalyzer.com`
- `pixibay.cc`
- `playmogo.com`
- `ponytail.dev`
- `pornhoarder.pics`
- `proxyapi.io`
- `pub-0cfed6727a1844b7b9405419b66ad607.r2.dev`
- `rapi.acrop.net`
- `relay.inference.net`
- `resim.epey.com`
- `rum-static.pingdom.net`
- `sa.searchatlas.com`
- `sdmntprsouthcentralus.oaiusercontent.com`
- `sdmntprwestus3.oaiusercontent.com`
- `static-assets.searchatlas.com`
- `static-lib.com`
- `static.doodcdn.io`
- `static.pushe.co`
- `static2.doodcdn.io`
- `store.externulls.com`
- `synara-account-api-trial.synara-orgs.workers.dev`
- `theme.blogfa.com`
- `thunderbird-settings.thunderbird.net`
- `tokenharbor.ai`
- `unpkg.com`
- `us-assets.i.posthog.com`
- `vibuxer.com`
- `worker.clerkprod-cloudflare.net`
- `ws.chatgpt.com`
- `www.accountingcoach.com`
- `www.epey.com`
- `www.fakexy.com`
- `www.mpay.cards`
- `www.tgju.org`
- `www.tokenrouter.com`
- `www.whatismyip.com`

#### `188.114.99.0` — 147 domains observed in `policy:` lines

- `0fa9010fca70.w.hcaptcha.com`
- `471e5c6c0c21.w.hcaptcha.com`
- `6e5f456a0533.w.hcaptcha.com`
- `7odcs2a8nxtfyxndn.ay.delivery`
- `a.apkpures.xyz`
- `a.inference.net`
- `ab.chatgpt.com`
- `acrop.net`
- `addoncrop.com`
- `analytics-api.zintrack.com`
- `api.37348c5b946467daf024dd617616d6ed968023b3.com`
- `api.64e23e873ff04bfa2bbc2ae45430381281e7f360.com`
- `api.90341b4610d2ad771c3d7cef15e3e700b647dd3a.com`
- `api.9d992bc3669c19219bd556efc6b9569b2d09ff60.com`
- `api.adoptium.net`
- `api.bff0cfdfc3d893fc4c14affb538d23544b90541d.com`
- `api.dnschecker.org`
- `api.gitkraken.dev`
- `api.iconify.design`
- `api.ipify.org`
- `api.jetpusher.com`
- `api.oaistatsig.com`
- `api.windscribe.net`
- `api.zed.dev`
- `api.zeroeval.com`
- `apinex.bond`
- `app.fusebox.fm`
- `app.mpay.cards`
- `app.wafer.ai`
- `arena.ai`
- `audinifer.com`
- `autoconfig.thunderbird.net`
- `backlog.so`
- `basescan.org`
- `beeg.com`
- `benchlm.ai`
- `btloader.com`
- `bun.sh`
- `bzr.openai.com`
- `callistanise.com`
- `cdn.agentclientprotocol.com`
- `cdn.api.btloader.com`
- `cdn.datatables.net`
- `cdn.id5-sync.com`
- `cdn.tapsell.xyz`
- `chatgpt.com`
- `clerk.openrouter.ai`
- `clerk.relace.ai`
- `clerk.sailresearch.com`
- `clerk.t3.codes`
- `client.crisp.chat`
- `cloud-platform.near.ai`
- `codex-cloud-backend.chatgpt.com`
- `configs.gitkraken.dev`
- `connector-id-dfbccc248e43b6fe7d187129e21b5ec8.web-sandbox.oaiusercontent.com`
- `csp-reporting.cloudflare.com`
- `dashboard.searchatlas.com`
- `dd2stliwt0bc.digitalworkflow.sbs`
- `deaf32d0d357.w.hcaptcha.com`
- `debezium.io`
- `dl.gitea.com`
- `docs.gitea.com`
- `docs.mitmproxy.org`
- `download.ticktick.app`
- `e561e7fb621e.w.hcaptcha.com`
- `easypoller.com`
- `edge.cdn-vitals.com`
- `events.kiloapps.io`
- `example.com`
- `example.org`
- `expapi.pureapk.com`
- `file.pushe.co`
- `files.downloadhelper.net`
- `flagcdn.com`
- `flags.inference.net`
- `free.rpc.fastnear.com`
- `hagen.challenges.cloudflare.com`
- `hgcloud.to`
- `i.doodcdn.io`
- `i.mscdn.ai`
- `images.openai.com`
- `images.versus.io`
- `ingest.kilosessions.ai`
- `ingest.t3.codes`
- `ipapi.co`
- `js.globalsun.io`
- `json-update-button.eytvd.workers.dev`
- `kitploit.com`
- `lebrel.ai`
- `live.thunderbird.net`
- `llm-stats.com`
- `logs.mosevura.com`
- `lulustream.com`
- `mcp.openrouter.ai`
- `mcpservers.org`
- `media.nano-gpt.cloud`
- `minochinos.com`
- `mintcdn.com`
- `models.dev`
- `models.opencode.ai`
- `moviejavan.com`
- `opencode.ai`
- `openrouter.ai`
- `otel.gitkraken.com`
- `persistent.oaistatic.com`
- `ping.wappalyzer.com`
- `pixibay.cc`
- `ponytail.dev`
- `pornhoarder.net`
- `pornhoarder.pics`
- `proxyapi.io`
- `pub-0cfed6727a1844b7b9405419b66ad607.r2.dev`
- `r.jina.ai`
- `rapi.acrop.net`
- `relay.inference.net`
- `resim.epey.com`
- `rum-static.pingdom.net`
- `sa.searchatlas.com`
- `sdmntprsouthcentralus.oaiusercontent.com`
- `sdmntprwestus3.oaiusercontent.com`
- `sparrow.cloudflare.com`
- `stackpath.bootstrapcdn.com`
- `static-assets.searchatlas.com`
- `static-lib.com`
- `static.doodcdn.io`
- `static.pushe.co`
- `static2.doodcdn.io`
- `store.externulls.com`
- `streamtape.to`
- `synara-account-api-trial.synara-orgs.workers.dev`
- `techlore.tv`
- `theme.blogfa.com`
- `thunderbird-settings.thunderbird.net`
- `tokenharbor.ai`
- `unpkg.com`
- `us-assets.i.posthog.com`
- `v.ipinfo.io`
- `worker.clerkprod-cloudflare.net`
- `ws.chatgpt.com`
- `www.epey.com`
- `www.fakexy.com`
- `www.jsdelivr.com`
- `www.mpay.cards`
- `www.tgju.org`
- `www.tokenrouter.com`
- `xerj.org`
- `zeroeval.com`

---

## D. `ssh` verdicts and `known_hosts`

- `ssh` policy lines: **2,190**; with a domain: **2,051**; without: **139**.
- Destinations: port 22 (2,174), port 52176 (16). IPs: `5.202.198.83` (1,770), `140.82.121.4` (167), `140.82.121.3` (162), `192.168.100.122` (59), `20.250.119.67` (11), `198.18.0.15` (6), `140.82.114.3` (4), `198.18.0.12` (3), `192.168.80.116` (1), `140.82.116.4` / `.3` (1 each), `20.26.156.215` (1), `192.168.7.3` (1), `140.82.113.4` / `114.4` / `113.3` (1 each).
- Distinct `(ip, port, domain)` triples: **30**.
- Domain-bearing verdicts whose name appears literally in `known_hosts` (name-only match, port ignored): **1,445 / 2,051 (70.4%)**, but 1,431 of those are `sm.logicamp.dev` (1,126) and `github.com` (305); `git.logicamp.dev` accounts for the remaining 14.

| Destination | Port | Domain in verdict | Verdicts | Literal name in `known_hosts`? |
|---|---|---|---|---|
| `5.202.198.83` | 22 | `sm.logicamp.dev` | 1105 | yes |
| `5.202.198.83` | 22 | `oevaite.kaariiz.com` | 342 | no |
| `140.82.121.3` | 22 | `github.com` | 150 | yes |
| `140.82.121.4` | 22 | `github.com` | 134 | yes |
| `5.202.198.83` | 22 | `litellm.kaariiz.com` | 129 | no |
| `5.202.198.83` | 22 | `sub2api.kaariiz.com` | 62 | no |
| `5.202.198.83` | 22 | `devsie2r.kaariiz.com` | 23 | no |
| `5.202.198.83` | 22 | `lcr.logicamp.dev` | 20 | no |
| `5.202.198.83` | 52176 | `sm.logicamp.dev` | 13 | yes |
| `5.202.198.83` | 22 | `git.logicamp.dev` | 12 | yes |
| `5.202.198.83` | 22 | `docskl3w.kaariiz.com` | 12 | no |
| `20.250.119.67` | 22 | `github.com` | 11 | yes |
| `140.82.121.4` | 22 | `patch-diff.githubusercontent.com` | 6 | no |
| `198.18.0.15` | 22 | `sm.logicamp.dev` | 5 | yes |
| `140.82.114.3` | 22 | `github.com` | 4 | yes |
| `5.202.198.83` | 22 | `ms-3.preview.kaariiz.com` | 4 | no |
| `198.18.0.12` | 22 | `sm.logicamp.dev` | 3 | yes |
| `192.168.100.122` | 22 | `192.168.100.122` | 3 | no |
| `5.202.198.83` | 52176 | `git.logicamp.dev` | 2 | yes |
| `140.82.116.4` | 22 | `github.com` | 1 | yes |
| `140.82.116.3` | 22 | `github.com` | 1 | yes |
| `20.26.156.215` | 22 | `github.com` | 1 | yes |
| `5.202.198.83` | 22 | `auth.dohd2z.kaariiz.com` | 1 | no |
| `5.202.198.83` | 22 | `bnpl.dohd2z.kaariiz.com` | 1 | no |
| `5.202.198.83` | 22 | `m.tameshk-company.ir` | 1 | no |
| `5.202.198.83` | 22 | `claw.logicamp.dev` | 1 | no |
| `5.202.198.83` | 22 | `waexuhu.kaariiz.com` | 1 | no |
| `140.82.113.4` | 22 | `github.com` | 1 | yes |
| `140.82.114.4` | 22 | `github.com` | 1 | yes |
| `140.82.113.3` | 22 | `github.com` | 1 | yes |

`known_hosts` parse: 32 host entries; 3 hashed (`|1|`); 5 plaintext names (`git.logicamp.dev`, `git.logicamp.tech`, `github.com`, `localhost`, `sm.logicamp.dev`); 7 IPs. Entries for `5.202.198.83` are all `[5.202.198.83]:52176` (sm/git on a non-standard SSH port).

`dig +short -x 5.202.198.83` returns `files.logicamp.dev.`, `searxng.kaariiz.com.`, `m.tameshk-company.ir.`. `/etc/hosts` maps the same IP to `files.logicamp.dev`, `searxng.kaariiz.com`, `m.tameshk-company.ir`.

Other facts used in §6 of the report:

- `~/.ssh/config` does not exist.
- `dns-forwarder: … process=ssh …` lines: **0**.
- `dns-forwarder:` lines containing `oevaite`: **0**.
- `ssh` policy verdicts on 443: **0**.

---

## E. Same-4-tuple domain flips within 15 s where the action also changed

There are **57** flips total (same destination IP, destination port, and source port; different domain within 15 s). **17** also changed the action; those are listed below.

| Time | Destination IP | Port | Src port | Process | From | To | Δt |
|---|---|---|---|---|---|---|---|
| 2026-11-03 20:06:45 | `188.114.99.0` | 443 | 51252 | kilo | models.dev/Route | chatgpt.com/Allow | 1s |
| 2026-11-03 20:06:45 | `2a06:98c1:3123::` | 443 | 32988 | kilo | models.dev/Route | chatgpt.com/Allow | 1s |
| 2026-11-03 20:06:45 | `188.114.98.0` | 443 | 56020 | kilo | models.dev/Route | chatgpt.com/Allow | 1s |
| 2026-11-03 20:06:45 | `2a06:98c1:3122::` | 443 | 55438 | kilo | models.dev/Route | chatgpt.com/Allow | 1s |
| 2026-11-07 00:54:17 | `2a06:98c1:3122::` | 443 | 46702 | kilo | models.dev/Route | events.kiloapps.io/Deny | 1s |
| 2026-11-07 00:54:17 | `2a06:98c1:3123::` | 443 | 37896 | kilo | models.dev/Route | events.kiloapps.io/Deny | 1s |
| 2026-11-08 14:41:40 | `188.114.99.0` | 443 | 54920 | kilo | ab.chatgpt.com/Allow | events.kiloapps.io/Deny | 1s |
| 2026-11-09 11:03:15 | `188.114.99.0` | 443 | 42000 | kilo | models.dev/Route | events.kiloapps.io/Deny | 8s |
| 2026-11-09 11:03:15 | `188.114.98.0` | 443 | 49526 | kilo | models.dev/Route | events.kiloapps.io/Deny | 8s |
| 2026-11-10 09:42:46 | `188.114.98.0` | 443 | 37874 | kilo | models.dev/Route | chatgpt.com/Allow | 7s |
| 2026-11-10 09:42:46 | `188.114.99.0` | 443 | 43912 | kilo | models.dev/Route | chatgpt.com/Allow | 7s |
| 2026-11-10 11:51:40 | `188.114.98.0` | 443 | 45836 | kilo | models.dev/Route | chatgpt.com/Allow | 7s |
| 2026-11-10 11:51:40 | `188.114.99.0` | 443 | 50560 | kilo | models.dev/Route | chatgpt.com/Allow | 7s |
| 2026-11-10 12:51:24 | `188.114.98.0` | 443 | 48278 | kilo | models.dev/Route | clerk.sailresearch.com/Allow | 1s |
| 2026-11-10 12:51:24 | `188.114.99.0` | 443 | 51582 | kilo | models.dev/Route | clerk.sailresearch.com/Allow | 1s |
| 2026-11-11 06:00:13 | `188.114.98.0` | 443 | 45918 | kilo | models.dev/Route | chatgpt.com/Allow | 5s |
| 2026-11-11 06:00:13 | `188.114.99.0` | 443 | 45944 | kilo | models.dev/Route | chatgpt.com/Allow | 5s |

The pattern is dominated by `kilo` and `models.dev`, i.e. the same app moving between names that share the Cloudflare anycast addresses. A `Route` for `models.dev` and an `Allow` for `chatgpt.com` on the same four addresses means the egress changes while the socket stays the same.

---

## F. `sweep_pending` bursts

- Total auto-resolutions: **3,674**; Allow 2,497, Route 910, Deny 267.
- Per process (top 12): `kilo` 779, `curl` 386, `codium` 375, none 209, `synara` 184, `gvfsd-http` 122, `trae` 122, `betterbird-bin` 116, `codex` 103, `keepassxc` 100, `helm` 78, `python3.14` 70.

| Second | Resolutions |
|---|---|
| 2026-10-04 12:30:13 | 100 |
| 2026-11-07 18:11:20 | 29 |
| 2026-10-05 12:23:40 | 24 |
| 2026-10-05 14:42:35 | 23 |
| 2026-11-08 02:48:49 | 22 |
| 2026-11-05 20:24:42 | 19 |
| 2026-10-05 16:27:02 | 16 |
| 2026-11-06 12:19:13 | 16 |
| 2026-11-11 01:03:36 | 16 |
| 2026-10-05 14:42:31 | 14 |

The 100-resolution burst on 2026-10-04 12:30:13 is all `keepassxc`, all `Allow`. The 29-resolution burst on 2026-11-07 18:11:20 is all `trae`, all **`Deny`**, while the only rule created in that second is `ui-1794062480` (`trae → Any`, **Route**): the Deny was produced by a different rule already in the store, which is the point of §4.10. Neither log line names the domain or the rule, which is the logging gap described in §7 of the report.

---

## G. Policy ↔ transparent-proxy join

### G.1 Method

Key: `(destination_port, source_port)`, timestamps within 1 s, proxy target is a hostname (IP targets skipped). For every policy line with a domain, compare the policy domain with the proxy target.

This yields:

- 844,413 matched proxy lines;
- 7,649 pairs where the policy domain differs from the proxy target;
- 1,362 distinct `(process, policy_domain, proxy_host)` triples;
- 6,041 pairs / 1,009 triples that differ at the registrable-domain level.

### G.2 Why this is an upper bound

The count is **not** a count of bugs:

1. **CNAME aliasing.** A policy domain can be the canonical name of the proxy's target (`trae` → `*.akamai.net` vs `*.trae.ai` accounts for most of the top rows).
2. **Proxy fallback hints.** The proxy logs fallback CONNECT attempts, so one connection can produce several target hostnames; a policy line can match a fallback, not the final dial.
3. **Rule snapshots drift.** The policy domain is what the classifier produced at the time; the rules used to judge it are from a later snapshot.

Only same-second, same-port pairs whose two names do not alias, or flips inside one connection, are conclusive.

### G.3 Top cross-registrant triples

| Process | Policy domain | Proxy target | Pairs |
|---|---|---|---|
| trae | `direct.quic-mix-proxy-gcpsg-v3.gcpsg.byteglb.com` | `core22-normal-sg.trae.ai` | 375 |
| trae | `a10022687.t.akamai.net` | `icube-normal.trae.ai` | 254 |
| trae | `a632.t.akamai.net` | `api.marscode.com` | 226 |
| trae | `a611.t.akamai.net` | `bytegate-sg.byteintlapi.com` | 145 |
| trae | `a10025005.t.akamai.net` | `mcs16-normal-sg.trae.ai` | 126 |
| trae | `api22-normal-alisg.mchost.guru` | `core22-normal-sg.trae.ai` | 125 |
| brave | `go-updater-1830831421.us-west-2.elb.amazonaws.com` | `go-updater.brave.com` | 104 |
| trae | `a10034077.t.akamai.net` | `growsg-normal.trae.ai` | 103 |
| trae | `a10019766.dsct.akamai.net` | `core-normal.traeapi.us` | 80 |
| python3.14 | `direct.quic-mix-proxy-gcpsg-v3.gcpsg.byteglb.com` | `core22-normal-sg.trae.ai` | 75 |
| trae | `a10027630.t.akamai.net` | `mon16-normal-sg.trae.ai` | 73 |
| trae | `a613.t.akamai.net` | `api16-normal-alisg.mchost.guru` | 72 |

The `trae` rows are the CNAME caveat in its purest form. The `synara`/`gvfsd-http` cases in the report are not aliases: the policy domain and the proxy host are unrelated registrants, and the rule actions differ (Deny vs Route, Allow vs Route).

---

## H. Verbatim timelines

### H.1 `oevaite.kaariiz.com`: brave on 443 → ssh on 22

```
2026-11-01T10:53:23  policy: id=ui-1792666817 action=Allow process=Some("brave") (brave-bin) domain=Some("oevaite.kaariiz.com") dst=5.202.198.83:443 src=:32906
2026-11-01T10:53:42  policy: id=ui-1792666817 action=Allow process=Some("ssh") (openssh) domain=Some("oevaite.kaariiz.com") dst=5.202.198.83:22 src=:59808
```

The first line is `brave`; the second is `ssh`. The same name crossed protocols, ports, and processes. `ssh` made no DNS query.

### H.2 One connection, two names, three seconds

```
2026-11-09T09:39:04  policy: id=ui-1792666817 action=Allow process=Some("ssh") (openssh) domain=Some("oevaite.kaariiz.com") dst=5.202.198.83:22 src=:59056
2026-11-09T09:39:07  policy: id=ui-1792827494 action=Allow process=Some("ssh") (openssh) domain=Some("sm.logicamp.dev") dst=5.202.198.83:22 src=:59056
```

### H.3 `ui-1794205260` and its sweep second

```
2026-11-09T09:51:00  sweep_pending: auto-resolving pending-16 (Some("ssh") → Route)
```

Rule id `ui-1794205260` decodes to `2026-11-09 09:51:00`. The rule is `Route`, `/usr/bin/ssh`, `DomainExact models.dev`, egress `eg-1790749737`, priority 11.394. Its policy id appears 0 times in the journal.

### H.4 Case A: gvfsd-http

```
2026-11-10T11:49:19  policy: id=ui-1793912852 action=Route process=Some("gvfsd-http") (gvfs) domain=Some("api.zeroeval.com") dst=188.114.98.0:443 src=:40758
2026-11-10T11:49:19  transparent proxy: 192.168.1.101:40758 -> api.ipify.org:443 via 127.0.0.1:2080
```

The real host already has an Allow (`ui-1791022832`, 2,336 matches); the wrong host has a Route.

### H.5 Case B: synara and the denied `workers.dev`

```
2026-11-12T01:14:38  policy: id=ui-1794344181 action=Route process=Some("synara") domain=Some("events.kiloapps.io") dst=188.114.99.0:443 src=:50700
2026-11-12T01:14:38  transparent proxy: 192.168.100.120:50700 -> synara-account-api-trial.synara-orgs.workers.dev:443 via 192.168.100.121:1082
```

`ui-1794398999` (`synara → …workers.dev`, Deny, first match 2026-11-11 15:40:00, 277 matches) did not apply. `ui-1794344181` is a pre-existing Route created 2026-11-11 00:26:21 (26 matches).

### H.6 The 12:05 inversion

```
2026-11-12T12:05:13  policy: id=ui-1793008069 action=Route process=Some("brave") (brave-bin) domain=Some("clerk.sailresearch.com") dst=188.114.98.0:443 src=:36094
2026-11-12T12:05:13  transparent proxy: 192.168.1.101:36094 -> clerk.sailresearch.com:443 via 192.168.1.108:1082
2026-11-12T12:05:27  sweep_pending: auto-resolving pending-30 (Some("synara") → Route)
2026-11-12T12:05:27  sweep_pending: auto-resolving pending-31 (Some("synara") → Route)
2026-11-12T12:05:48  policy: id=ui-1794472527 action=Route process=Some("synara") domain=Some("clerk.sailresearch.com") dst=188.114.99.0:443 src=:50140
2026-11-12T12:05:48  transparent proxy: 192.168.1.101:50140 -> synara-account-api-trial.synara-orgs.workers.dev:443 via 192.168.1.108:1082
```

The `synara` process is correct; the destination is borrowed. `ui-1794472527` is absent from the 00:25 dump; its duration was not captured.

### H.7 The 22:44–22:51 process borrow

```
2026-11-12T22:44:23  policy: id=ui-1794398999 action=Deny process=Some("synara") domain=Some("synara-account-api-trial.synara-orgs.workers.dev") dst=188.114.99.0:443 src=:46922
2026-11-12T22:44:24  policy: id=ui-1794398999 action=Deny process=Some("synara") domain=Some("synara-account-api-trial.synara-orgs.workers.dev") dst=2a06:98c1:3122::443 src=:38994
2026-11-12T22:44:24  policy: id=ui-1794398999 action=Deny process=Some("synara") domain=Some("synara-account-api-trial.synara-orgs.workers.dev") dst=188.114.98.0:443 src=:47870
2026-11-12T22:44:24  policy: id=ui-1794398999 action=Deny process=Some("synara") domain=Some("synara-account-api-trial.synara-orgs.workers.dev") dst=2a06:98c1:3123::443 src=:41994
2026-11-12T22:45:38  sweep_pending: auto-resolving pending-10 (Some("kilo") → Deny)
2026-11-12T22:45:38  sweep_pending: auto-resolving pending-11 (Some("kilo") → Deny)
2026-11-12T22:45:38  sweep_pending: auto-resolving pending-12 (Some("kilo") → Deny)
2026-11-12T22:45:38  sweep_pending: auto-resolving pending-13 (Some("kilo") → Deny)
2026-11-12T22:45:38  policy: id=ui-1794344181 action=Route process=Some("synara") domain=Some("events.kiloapps.io") dst=188.114.98.0:443 src=:59396
2026-11-12T22:51:13  policy: id=ui-1793009835 action=Deny process=Some("kilo") domain=Some("events.kiloapps.io") dst=188.114.98.0:443 src=:53088
2026-11-12T22:51:13  policy: id=ui-1793009835 action=Deny process=Some("kilo") domain=Some("events.kiloapps.io") dst=2a06:98c1:3123::443 src=:55362
2026-11-12T22:51:13  policy: id=ui-1793009835 action=Deny process=Some("kilo") domain=Some("events.kiloapps.io") dst=188.114.99.0:443 src=:51716
2026-11-12T22:51:13  policy: id=ui-1793009835 action=Deny process=Some("kilo") domain=Some("events.kiloapps.io") dst=2a06:98c1:3122::443 src=:37872
2026-11-12T22:51:24  policy: id=ui-1794510938 action=Deny process=Some("kilo") domain=Some("synara-account-api-trial.synara-orgs.workers.dev") dst=188.114.98.0:443 src=:53796
2026-11-12T22:51:24  policy: id=ui-1794510938 action=Deny process=Some("kilo") domain=Some("synara-account-api-trial.synara-orgs.workers.dev") dst=2a06:98c1:3123::443 src=:37270
2026-11-12T22:51:24  policy: id=ui-1794510938 action=Deny process=Some("kilo") domain=Some("synara-account-api-trial.synara-orgs.workers.dev") dst=188.114.99.0:443 src=:33986
2026-11-12T22:51:24  policy: id=ui-1794510938 action=Deny process=Some("kilo") domain=Some("synara-account-api-trial.synara-orgs.workers.dev") dst=2a06:98c1:3122::443 src=:53812
2026-11-12T23:45:58  policy: id=ui-1794398999 action=Deny process=Some("synara") domain=Some("synara-account-api-trial.synara-orgs.workers.dev") dst=188.114.98.0:443 src=:54418
2026-11-12T23:45:58  policy: id=ui-1794398999 action=Deny process=Some("synara") domain=Some("synara-account-api-trial.synara-orgs.workers.dev") dst=2a06:98c1:3122::443 src=:36578
```

`ui-1794510938` decodes to 2026-11-12 22:45:38, exactly the sweep second. It is absent at 00:25 (duration not captured; disappearance at the restart is the `UntilRestart` signature). `kilo` has no DNS observation of `workers.dev` anywhere; the only `kilo → workers.dev` association is the 22:51:24 block.

### H.8 `synara → api.zed.dev` and the `zed-editor` Deny

```
2026-11-12T01:13:45  policy: id=ui-1792233615 action=Deny process=Some("zed-editor") (zed) domain=Some("api.zed.dev") dst=188.114.99.0:443 src=:42068
2026-11-12T01:13:50  policy: id=ui-1792233615 action=Deny process=Some("zed-editor") (zed) domain=Some("api.zed.dev") dst=188.114.98.0:443 src=:39938
2026-11-12T01:13:53  policy: id=ui-1794344794 action=Route process=Some("synara") domain=Some("models.opencode.ai") dst=2a06:98c1:3122::443 src=:57060
2026-11-12T01:13:54  policy: id=ui-1794344794 action=Route process=Some("synara") domain=Some("models.opencode.ai") dst=2a06:98c1:3123::443 src=:55338
2026-11-12T01:13:58  sweep_pending: auto-resolving pending-106 (Some("synara") → Allow)
2026-11-12T01:13:58  sweep_pending: auto-resolving pending-107 (Some("synara") → Allow)
2026-11-12T01:14:08  policy: id=ui-1794433438 action=Allow process=Some("synara") domain=Some("api.zed.dev") dst=188.114.98.0:443 src=:48268
```

`ui-1794433438` decoded to 01:13:58. The rule has exactly one match, ten seconds after creation.

---

## I. Key rules referenced in the report

| Rule | Created | Action | Duration | Process | Destination / egress | Journal matches |
|---|---|---|---|---|---|---|
| `ui-1794205260` | 2026-11-09 09:51:00 | Route | Permanent | ssh | models.dev / `eg-1790749737` | 0 |
| `ui-1793013554` | 2026-10-26 14:49:14 | Route | Permanent | codex | api.zed.dev | 0 |
| `ui-1794433438` | 2026-11-12 01:13:58 | Allow | Permanent | synara | api.zed.dev | 1 |
| `ui-1794344181` | 2026-11-11 00:26:21 | Route | Permanent | synara | events.kiloapps.io / `eg-1790749737` | 26 |
| `ui-1794398999` | 2026-11-11 15:39:59 | Deny | Permanent | synara | `synara-account-api-trial.synara-orgs.workers.dev` | 277 |
| `ui-1794472527` | 2026-11-12 12:05:27 | Route | not captured | synara | clerk.sailresearch.com | absent after 23:45 |
| `ui-1794510938` | 2026-11-12 22:45:38 | Deny | not captured | kilo | `…workers.dev` | absent after 23:45 |
| `ui-1793008069` | 2026-10-26 13:17:49 | Route | Permanent | brave | Any | 25,566 |
| `ui-1792666817` | 2026-10-22 14:30:17 | Allow | Permanent | — | IpExact 5.202.198.83 | 2,834 |
| `ui-1791022832` | 2026-10-03 13:50:32 | Allow | Permanent | gvfsd-http | api.ipify.org | 2,336 |

The "Created" column is the rule-id epoch, not the first match. `UntilRestart` rules are removed when the daemon restarts; their historical verdicts remain in the journal.

---

## J. Reproducing the tables

The analysis was done with Python over the captured files. The essential steps, in order:

1. Parse `policy:` lines into `(timestamp, rule_id, action, process, domain, dst_ip, dst_port, src_port)`.
2. Parse `sweep_pending: auto-resolving` lines into `(timestamp, pending_id, process, action)`.
3. Parse `transparent proxy: <src>:<port> -> <host>:<port>` and join to policy lines on `(dst_port, src_port)` with `|Δt| ≤ 1 s`.
4. Group policy lines by `(dst_ip, dst_port, src_port)` and sort by time; a "flip" is a domain change within 15 s.
5. Group by `dst_ip` to count distinct domains; group by `dst_port` for non-443 verdicts.
6. Decode `ui-<epoch>` with `date -d @<epoch>` to get rule creation time.
7. Parse `known_hosts`: strip `[host]:port`, skip `|1|` hashed entries, split comma-separated names.

All counts in this file come from that pipeline over the 2026-11-12 capture. A re-run against a later journal will produce different numbers; compare rates and shapes, not exact counts.
