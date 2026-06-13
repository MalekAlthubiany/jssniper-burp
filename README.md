# JSsniper for Burp Suite

A JavaScript & JSON security analyzer for Burp Suite, in the spirit of JS-Miner.
It passively scans static files (JS / JSON / inline `<script>`) as you browse and
adds right-click actions to **scan a whole host**, **scan a specific response**,
and **dump static files**. Findings are raised as native Burp issues with Title,
Description, Impact, Remediation and highlighted matches.

Detection seeds are from the original CLI tool,
[JSsniper](https://github.com/MalekAlthubiany/JSsniper.py), heavily expanded.

> For authorized security testing only.

## A note on accuracy
This is a recon helper built on regular expressions and heuristics. Like every
tool of this kind , **it produces false
positives and does not replace manual review.** It does not — and cannot — achieve
"99% / zero false positives." What it does to keep precision high: Shannon-entropy
filtering on generic secrets, Luhn validation on card numbers, placeholder
stop-lists, version comparison for libraries, and **live NPM verification** for
dependency confusion (only unclaimed packages are flagged). Treat every result as
a lead to verify.

## Features

Passive (automatic + on right-click):
- **Secrets / credentials** — AWS, Google, Stripe, GitHub, GitLab, Slack, Twilio,
  SendGrid, NPM, OpenAI, JWTs, generic keys (entropy-gated), DB strings, private keys
- **PII** — emails, Saudi (+966) & US phone numbers, payment cards (Luhn-checked)
- **Crypto** — MD5/SHA-1/SHA-256/bcrypt hashes, crypto libraries, weak algorithms
- **API endpoints** — GET/POST/PUT/DELETE/PATCH via fetch/axios/XHR/jQuery + paths
- **Hosts & IPs** — IPv4/IPv6, private ranges, internal hostnames
- **Subdomains (passive)** — subdomains of the target's registrable domain
- **Cloud URLs (passive)** — AWS (S3/API GW/ELB), Azure, Google/Firebase, CloudFront,
  DigitalOcean, Oracle, Alibaba, Rackspace, DreamHost
- **Vulnerable JS libraries** — version-based (jQuery, AngularJS, Bootstrap, Lodash,
  Moment, Handlebars, Axios, …)
- **Source maps (passive)** — detects inline base64 maps and external `.map` references
- **Developer comments & dangerous sinks** — TODO/SECURITY, eval/innerHTML (off by default)

Active (right-click only — sends HTTP requests through Burp):
- **JS Source Mapper** — fetches/guesses `.map` files and reports how many original
  sources are recoverable
- **Dependency confusion** — extracts referenced NPM packages and queries the public
  NPM registry; an **unclaimed** package/scope is flagged High (404 = takeable name)
- **Static files dumper** — one click to save all static files for a host to disk


## Where results appear (important for Community Edition)

JSsniper shows findings in its **own colour-coded Results tab** — it does **not**
rely on Burp's scanner or the Target > Issues panel, so it works in **Burp Suite
Community Edition** (which has no scanner UI).

1. Browse/crawl your target so its static files are in the site map.
2. Open the **JSsniper** tab > **Results** and click **Scan entire site map**
   (or right-click a host in the site map > **JSsniper: Scan the host**).
3. Findings appear in the table, colour-coded by severity (red = High, orange =
   Medium, yellow = Low, blue = Information). Click a row to see the full
   Description / Impact / Remediation below.

In Burp **Professional**, findings additionally appear under **Target > Issues**
and passive scanning runs automatically as you browse.

## Usage

Right-click a host (or any of its requests) in Target / Proxy history:
- **JSsniper: Scan the host** — runs the full passive engine over every static
  response for that host **plus** the active checks (source maps + dependency
  confusion). Issues appear under **Target → Issues**; progress logs in the
  extension Output.
- **JSsniper: Scan specific response** — same analysis on just the selected items.
- **JSsniper: Dump static files** — writes the host's static files to a temp folder
  (path is logged) so you can run your own tooling over them.

Passive scanning also runs automatically as you browse. The **JSsniper** suite tab
toggles categories and the inline-HTML / in-scope options.

> Tip: browse/crawl the target first so its static files are in Burp's site map —
> the host scan and dumper read from the site map.


### Viewing a finding (request, response & highlight)
Click a row in the Results table to open the detail pane below, which has three tabs:
- **Advisory** — issue name, severity, description, impact and remediation.
- **Request** — the originating HTTP request (Burp's native editor).
- **Response** — the HTTP response, with the matched/vulnerable bytes highlighted
  via Burp's search highlighter.
The header shows live severity counts (High / Medium / Low / Info) and a text
filter, so the view stays readable on large targets.

## Build & load

JDK 21. `gradle build` → `build/libs/jssniper-1.0.0.jar` (Montoya is `compileOnly`,
no bundled deps). Load via Extensions → Installed → Add → type **Java**.

## Submitting to the BApp Store

Push to a public GitHub repo, then on
[`PortSwigger/extension-portal`](https://github.com/PortSwigger/extension-portal)
open Issues → **New extension submission**. It meets the structural criteria
(Montoya via Gradle, no bundled deps, passive check makes no requests, active work
+ NPM/dump on background threads via Burp's HTTP stack, clean unload handler, GUI
tab parented to Burp). Before submitting: confirm it isn't a duplicate of an
existing BApp (notably **JS-Miner**, whose feature set this overlaps), credit
original author **Malek Althubiany**, and agree licensing before publishing.

## Credits
- Original tool & seed patterns: **Malek Althubiany** — https://github.com/MalekAlthubiany/JSsniper.py
- Feature set inspired by JS-Miner. Burp/Montoya implementation: this project.

## Precision notes (IP addresses)
IPv4 detection is heavily filtered to avoid the usual false positives:
- word/dot boundaries so version strings like `v1.2.3.4` and longer dotted numbers are skipped;
- version context before (`version: 1.2.3.4`) and version suffixes after (`1.2.3.4-beta`) are dropped;
- strictly-sequential quads (`2.3.4.5`), `0.x`, multicast/reserved (>=224), loopback, netmasks, broadcast and RFC-5737 documentation ranges are discarded;
- surviving IPs are labelled **public / private / CGNAT / link-local** so results are immediately useful.
