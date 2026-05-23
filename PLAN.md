# Project Plan — PGP-First E2E Email Server

> Project name: **`rookery`**. In *A Song of Ice and Fire*, a rookery is the room at every castle where the maester keeps the ravens that carry sealed messages between holdfasts. Each instance of this project is one operator's rookery; instances exchange mail over plain SMTP the way ravens fly between castles. The name is settled; this note exists for the record.

## 1. Vision

Email is an open protocol. Anyone can run a server; it has worked that way for
forty years. In practice, almost nobody runs their own, because doing it well —
encryption, spam filtering, deliverability, abuse handling, a usable client — is
brutally hard. The realistic options for end users who want encrypted, low-friction
email are a handful of single-company services (Proton, Tutanota, Mailbox.org), and
trust collapses back to one provider.

**What we are building:** an opinionated, self-hostable mail-server-in-a-box that
speaks standard SMTP to the rest of the world, makes PGP end-to-end encryption the
default path between consenting parties, and is engineered so that one competent
person can run an instance for themselves, their family, or a small group without
becoming a full-time email sysadmin.

**Accounts are pseudonymous by default.** Signup asks for a local-part. Nothing
else. No name, no phone, no recovery email, and the server does not log connecting
IPs. The account/key pair is the only identity rookery knows about a user, and
that is the property we want to preserve. The recipient and the network path still
see standard SMTP metadata — that is a consequence of speaking email to the rest
of the world, not a property rookery can hide; see §4.

**The user owns their key. The server never holds it, not even encrypted.** The
PGP private key is generated in the browser during signup. Immediately after
registration the user is taken to settings, where they set a passphrase and
export the recovery file — the only durable copy of their key, kept off-device
and exportable on demand from settings at any time. Nothing is persisted in the
browser once logged out — every login on every device requires the recovery file
and the passphrase. The server holds the public key (it has to — outbound signing
auto-attaches it and WKD publishes it). The server never holds the private side,
and critically **the server never holds the passphrase or any hash of it** —
authentication is a challenge/response signed by the private key, so a server
breach leaks no authentication material whatsoever. Neither the passphrase alone
nor the recovery file alone is sufficient to log in; an attacker needs both. This
is a stronger property than the common "encrypted blob on the server" model and
matches the principle that the user — not the instance — owns the identity; the
operational consequences are spelled out in §5 and §11.1.

rookery is a complete email stack — server + web client — in one container. Postfix
+ Dovecot + Roundcube, opinionated and PGP-first, deployable in one command. That's
the entire scope. We are not building a network, a movement, or a federation
protocol. We are building a piece of software that runs email well.

If many people run good instances, the consolidation problem solves itself as a
side effect — but that outcome is not the goal of the design. The goal is for the
software to be correct, small, honest, and pleasant to operate.

## 2. Guiding principles

1. **The instance is the product.** The hard work is operational: deliverability, spam filtering, setup, migration, day-2 ops. Not crypto, not protocols. Optimize for "this is easy to run well," not "this has clever new technology."
2. **Standards only, no novel crypto or protocols.** SMTP, MIME, OpenPGP (RFC 9580), PGP/MIME (RFC 3156), WKD, Autocrypt, DKIM/SPF/DMARC, MTA-STS, TLS-RPT. We are consumers of standards via `ProtonMail/go-crypto` and `OpenPGP.js`. No new wire protocols, no new key-exchange schemes, no roll-our-own anything. SMTP is how rookery instances talk to other mail servers; that is not a feature we invented, it is the existing internet.
3. **Aggressively standards-compatible, deliberately replaceable.** A user's PGP key generated in our client is a normal OpenPGP key — exportable to and importable from `gpg`. Our messages are byte-compatible with what `gpg --encrypt --sign` produces; any conforming PGP implementation can decrypt them. Our WKD records are consumable by any WKD client. The user is never locked in. We are the convenient default; the standards are the escape hatch.
4. **Zero-trust server for content.** A compromised server must not be able to read PGP-encrypted message bodies or forge user signatures. Metadata leakage to the server is accepted and documented.
5. **PGP-first, not PGP-only.** Outgoing messages are encrypted whenever the recipient's key is discoverable. Plaintext fallback exists but always requires explicit confirmation.
6. **The web UI is the client.** Server-rendered HTML, small amount of JS for PGP operations only. No SPA, no IMAP/POP. There is no separate public API contract and no plan for third-party clients. The HTTP routes the web UI calls are not versioned for external consumers; they are implementation details of the web UI.
7. **Utilitarian UI in v1.** Inbox list, read, compose. Nothing else. The UI should look like a competent admin panel or a well-made distribution homepage (think `archlinux.org`, `voidlinux.org`, `man.archlinux.org`) — information-forward, no marketing prose, no decoration that doesn't carry information — not Superhuman. The visual direction is spelled out in §11.14. Polish in the "Superhuman-y" sense is Phase 8+ or never; the disciplined-utility look of §11.14 is shipped from v1.
8. **Techies as the user target.** Hard rules instead of compromised UX: one device per key, lose-your-passphrase-lose-your-mail, manual key import/export supported.
9. **Desktop-first, mobile-tolerated.** The target user lives on a desktop or laptop: a real keyboard, a file system, `gpg`, an `$EDITOR`, the ability to keep a passphrase-protected key on durable local storage they control. We design the web UI to be *usable* in a mobile browser (it should not break), but we do not optimize for mobile, we do not ship a native mobile app in v1, and we do not pretend a smartphone is a good place to hold a long-lived PGP private key. Push notifications, mobile-share targets, and similar mobile-native affordances are explicit non-goals for v1.
10. **Operators are a target audience too, but they operate from the shell, and the system is small enough to fit in one head.** The cost of running a mail server has never been the initial setup; it is the indefinite tax of staying competent at seven moving parts (Postfix, Dovecot, Roundcube, rspamd, certbot, opendkim, a PGP plugin), each with its own config language, upgrade cycle, and CVE feed. rookery's primary operator-facing claim is that there is **one process to know, one config file to edit, and one upgrade command to run**; DKIM, ACME, WKD, MTA-STS, DMARC reporting, Autocrypt and PGP/MIME are features of the binary, not separate packages. The operator's interface is **the shell on the box** — editing `rookery.toml`, running `rookery up`, occasionally running a documented `psql` snippet via `rookery psql`. There is no admin web UI, no in-app admin role, no setup wizard. The operator already has root on the VPS; reinventing access controls in a browser would be busywork. Anything that requires a separate admin app is either a sign we got the data model wrong, or a sign it doesn't belong in v1. The **30-minute active-configuration-time NFR** (§10) is the testable proxy for this: if a competent Linux user with a domain cannot get TLS, verified DNS, and one user inside that budget, the README or the dispatcher is the bug, not the budget. The number matters because it is falsifiable; the *reason* it is achievable is the one-binary architecture, not a clever installer.
11. **Boring server, small browser.** Server-side: Postgres, Go stdlib, `html/template`. No frameworks, no clever runtimes. Browser-side: we are honest that the stack (OpenPGP.js handling key generation, decryption, and private-key protection per RFC 9580; a `localStorage` session-key cache cleared on logout; future SSE) is *not* boring — it is the most security-sensitive code we ship. We keep it small, auditable, pinned, and SRI-protected, and we treat its review burden accordingly.
12. **Aggressive dependency minimalism.** Every dependency is a supply-chain attack surface. The current state of npm, PyPI, and (increasingly) Go module ecosystems makes this a live concern, not a theoretical one — typosquats, account takeovers, and malicious updates land monthly. **For us this is amplified twice over:** (a) the browser handles ciphertext and a decrypted private key, so a compromised dependency on a compose or read page is game over; (b) the server handles inbound SMTP, signing keys, and ACME credentials, so a compromised server dependency is also game over. Therefore: prefer stdlib over libraries. Prefer hand-written code over libraries when the alternative is under a few hundred lines. Pin and hash-verify everything we do depend on (`go.sum`, SRI for browser assets, `--frozen-lockfile`-equivalents). No transitive `postinstall` scripts. No dependency added without justification in a PR. The dependency list is reviewed periodically; bloat is removed. "We don't need it" is always a valid reason to remove a library.
13. **Useful at every milestone.** Each phase ships something a real person could use end-to-end.

## 3. What we are and are not

**We are:**
- A mail server (inbound + outbound SMTP) that speaks standard email to the rest of the world.
- A server-rendered web UI that performs PGP operations in the browser via a small JS module.
- A WKD publisher and an auto-attacher of public keys on outbound mail, so anyone can discover our users' keys.
- An opinionated, self-hostable instance — running one is the *intended* deployment, not an escape hatch.
- An operator product: deliverability, spam filtering, setup, observability, and migration are first-class concerns.
- Deliberately replaceable: the user's key, messages, and access to their mailbox all work without us. The web client is one of potentially many clients; the standards underneath are the real substrate.

**We are not (in v1):**
- A single-page app. No React/Vue/Svelte/etc., and no HTMX-style attribute frameworks either. Server-rendered HTML, plain hand-written JS only where required (crypto, partial updates).
- A polished webmail client. v1 UI is utilitarian: inbox, read, compose. No keyboard shortcuts, threaded conversation views, contact manager, calendar, etc.
- A mobile product. No native iOS/Android apps, no PWA-installability story, no push notifications, no mobile-optimized layouts beyond "the desktop UI doesn't break on a phone." Mobile users are second-class on purpose, and we say so. The target user is on a desktop or laptop.
- An IMAP/POP server. Any RFC-conforming MUA can send to and receive from a rookery instance over SMTP; what is absent is IMAP/POP access for reading the stored mailbox through a third-party mail client.
- A network with a novel inter-instance protocol. rookery instances communicate with other mail servers via plain SMTP — the same protocol every mail server uses. There is no rookery-specific coordination layer, no shared directory, no DHT, no custom protocol. Two rookery instances federate the same way Gmail and Fastmail federate: MX lookup and SMTP.
- A messaging app reinventing email. We use real RFC 5322 messages.
- A consumer product. UX targets people who know what a keypair is.
- An inventor of cryptographic protocols. We use OpenPGP via established libraries; no novel cryptography.
- A Unix shell in the browser. We don't run `gpg` in WASM, we don't pretend the browser is your local environment. The browser is a sandbox; we are honest about that. The `pass`-philosophy property is achieved through standards-compatibility — exportable OpenPGP keys, standard RFC 5322 messages, SMTP submission, WKD — not by faking a Unix toolchain in the page.

## 4. Threat model (initial sketch)

| Actor | Can do | Cannot do |
|---|---|---|
| Home server (honest-but-curious) | See envelope (From/To/Subject/timestamp/size), see plaintext for non-PGP mail, see ciphertext for PGP mail | Read PGP-encrypted bodies, forge user signatures, derive private key |
| Home server (malicious) | Drop/delay mail, serve wrong public keys to *new* contacts (key-discovery MITM), DoS the user, log everything, serve tampered JavaScript to extract passphrases on next login | Decrypt past PGP traffic, retroactively forge signed history, offline-brute-force user private keys (none are stored server-side, §11.1), authenticate as a user (challenge/response requires the private key, which the server never holds — a server breach leaks no login credentials) |
| Remote mail server | Same as home server for its own users; sees plaintext if no E2E | Read PGP-encrypted bodies in transit |
| Network attacker | See SMTP traffic patterns; without STARTTLS, see plaintext | Read PGP-encrypted bodies; forge signed mail |
| Other internet users | Send us mail, look up our published public key | Read mail addressed to others |

**Out of scope (permanently, not just v1):** metadata/traffic-analysis resistance, hiding the fact-of-sending from network observers, post-quantum crypto, repudiable messaging, **hiding Subject lines from SMTP**. The PGP ecosystem leaks subjects as a fact of life; encrypted-Subject extensions (Memory Hole / RFC 9152) have poor interop. Users who want subject privacy use a generic placeholder and put the real topic in the encrypted body, like everyone else does.

**Pseudonymity is *in* scope and is the default.** We collect nothing identifying at signup, we do not log connecting IPs on the web UI or on submission ports, and the account/key combination is the only identity rookery knows about its users. The instance is reachable over Tor without special treatment; the operator may publish a v3 onion address for the web UI alongside the clearnet hostname (§11.4). What the *recipient* and the *network path* see is standard SMTP metadata — From, To, Subject, timestamps, sizes, the `Received:` chain, and the originating instance's hostname. That metadata is a property of speaking email to the rest of the world, not something rookery can hide, and we say so plainly rather than hand-wave at it. Operators of public instances who combine pseudonymity with open registration take on real abuse risk; the per-user and per-instance outbound rate limits in §11.4 are the primary defense and invite-only registration (the default per §11.8) is the second. See §9 for the abuse-signal trade-off.

The **key-discovery TOFU problem** is the hardest unsolved issue. See §9.

## 5. User journeys

The product is intelligible only in terms of three concrete journeys: the **operator** standing up an instance, the **new user** signing up on a public instance, and the **everyday user** living in their mailbox. The self-hoster does the first two in sequence; everyone else does the second one only.

### 5.1 Operator journey — "I want to run an instance"

The operator is a competent Linux user with a domain and a VPS. They might be running the instance for themselves only, or for a small group of friends/family/colleagues, or as a more-or-less public instance accepting invited members. v1 doesn't distinguish: it's the same software, the same flow. **The operator does everything from the shell.** There is no setup wizard, no admin web UI, no in-app role for them — see P10.

1. **Provision.** A $5/month VPS, public IPv4 (and ideally IPv6), a domain like `rookery.example`. Reverse DNS (PTR) set to that hostname — many providers require a support ticket; doc this.
2. **Clone the repo into `/opt/rookery`.** The systemd unit assumes this path (`WorkingDirectory=/opt/rookery`), so taking the standard location avoids editing the unit. `sudo mkdir -p /opt/rookery && sudo chown "$USER" /opt/rookery && git clone <url> /opt/rookery && cd /opt/rookery`. The repo ships a known-good `compose.yaml` (Docker with the Compose v2 plugin; that is the only supported runtime — see §7) and the `rookery` dispatcher script (ADR-0033). No separate "copy these files" step.
3. **`rookery init --domain rookery.example --email you@example.com --name "My Rookery"`.** Idempotent, user-local bootstrap. Generates `rookery.toml` if missing (the flags pre-fill `domain`, `contact_email`, and `instance_name`; any not given are prompted interactively unless `--no-prompt`), generates `.env` with random secrets (DB password, server master key, session-signing key), generates `Caddyfile` from the config, and stages `./rookery.service` with `User=` filled in from `--user` (default: `whoami`). No `sudo`; no `--dev` / `--prod` flag — `init` always generates the full set, because the prod-only files (`Caddyfile`, `rookery.service`) are inert until something uses them. The server master key (§11.6) is the one secret the operator needs to back up themselves; `init` prints a one-time reminder.
4. **`sudo rookery install`.** Copies the staged `./rookery.service` into `/etc/systemd/system/rookery.service` and runs `systemctl daemon-reload`. This is the only command in the operator flow that needs `sudo`. It does **not** enable or start the unit — that is the operator's deliberate next step.
5. **`systemctl enable --now rookery`.** Standard systemd. The unit's `ExecStart` is `rookery start --prod`, so the stack comes up with Caddy on 80/443, plain HTTP on 8080 behind it, and SMTP on 25. The server generates DKIM keys on first run and logs the required DNS records as structured log lines.
6. **Add the DNS records.** Operator either reads them from the log (`rookery logs | grep DNS`) or runs the bundled subcommand `rookery dns print` (Phase 5; until then, `rookery logs`). They paste records into their DNS provider, wait for propagation. The server periodically rechecks DNS and logs the status; once DNS propagates, Caddy provisions Let's Encrypt certs automatically and the web UI becomes available over HTTPS.
7. **Create the first invite.** `rookery invite create` prints an invite URL to stdout. Under the hood the dispatcher runs `psql -c "INSERT INTO invites ..."` inside the postgres container and `printf`s the resulting URL; the operator does not need to know that. Operator visits the URL in their browser and goes through the user flow in §5.2a — picks a local-part, generates a PGP key in the browser, etc. They are now a regular user of the instance; that's the only role they need.
8. **(Optional) Users add their own custom domains.** Custom domains are always self-serve via the web UI flow in §5.2b. The user visits the custom-domain settings page, enters their domain, and follows the DNS-record wizard. The server generates per-domain DKIM keys, provisions ACME for `mta-sts.alice.com` and `openpgpkey.alice.com`, and guides the user through verification. There is no `rookery domain add` subcommand; operators who want to pre-register a domain for a user can do so via `rookery psql` and a direct `INSERT` into the `domains` table.

**Time budget:** under 30 minutes of *active configuration time* (DNS propagation and provider PTR turnaround excluded — see §10). Active steps are: `rookery init` with values inline or prompts (~3 min), `sudo rookery install` and `systemctl enable --now rookery` (~1 min), paste DNS records into registrar (~5 min), `rookery invite create` and complete user signup (~5 min). The rest is waiting on DNS, which is not us.

**Upgrade path:** `cd /opt/rookery && rookery update && sudo systemctl restart rookery`. The `update` subcommand runs `git fetch && git pull --ff-only && docker compose build`; restart is the operator's call.

**What's deliberately missing:**
- No setup wizard. Configuration is a file. Operators with file editors are the audience.
- No hosted control panel we provide. No phone-home. No telemetry.
- No admin web UI. Operations on the instance are shell operations.
- No green-tick DNS-propagation page. The server logs what it sees; the operator reads the log.
- No deliverability dashboard. Operators wire Prometheus or Grafana against the metrics endpoint if they want one; we ship the metrics, not the dashboard.

### 5.2 New-user journey — "Someone invited me to their instance"

The user receives an invite link from the instance operator (`https://rookery.example/invite/<token>`). They click. There are two sub-journeys depending on what address they want.

#### 5.2a Use the instance's domain (5-minute path)

This is the common case. Alice will have `alice@rookery.example`.

1. **Invite landing page.** Plain explanation of what they're about to do: "You're joining `rookery.example`, an encrypted email instance run by `<operator-display-name>`. A PGP key will be generated in your browser. After your account is created you will be taken to settings where you set a passphrase and export your recovery file. **If you lose the recovery file, your
mail is unrecoverable. There is no reset.** We do not ask for your name, phone, or any other identifying information; the account is pseudonymous. The recipients of your mail and the network in between will still see standard email metadata (your address, theirs, subject lines, timestamps) — that is how email works, and it is not something we can change." One-click to proceed; one-click to abandon.
2. **Pick a local part.** Alice picks `alice`. Server confirms it's available on `rookery.example`.
3. **Keypair generation, in browser.** Curve25519 by default. An unencrypted keypair is generated; the fingerprint is shown. Alice sees `alice@rookery.example` and a fingerprint like `A1B2 C3D4 ... 9F0E`.
4. **Public key uploaded to the server.** The server needs the public key to publish via WKD and to attach to Alice's outbound mail. *Only the public key.* The private key has not left the browser at any point and never will.
5. **Recovery file — export from settings.** Alice lands on the settings page immediately after registration. The page prompts for a passphrase and lets her export the private key encrypted as a `.asc` recovery file. The wording is unambiguous: "This file plus your passphrase *is* your account. If you lose either, your mail is gone — there is no reset, no server-side rescue, no recovery flow. Treat this file the way you would treat the only key to a safe." The server never has a copy; the unlocked session key is cached in `localStorage` (AES-GCM wrapped, cleared on logout) and the settings page encrypts it with the passphrase on demand to produce the file.
6. **Done.** Alice navigates to her inbox. WKD is now publishing her public key under `rookery.example`.

**Total time:** ~5 minutes, dominated by reading the warnings.

#### 5.2b Bring your own domain to a public instance (15–30-minute path)

Alice wants `alice@alice.com` but doesn't want to run her own server. The instance operator has enabled custom domains for users (or Alice asked the operator to add it for her — depending on instance policy).

1. **Invite landing page.** Same as above.
2. **Choose: instance domain or your own.** Alice picks "my own domain." Enters `alice.com`.
3. **DNS records.** Page shows the full set Alice needs to publish in her registrar's DNS:
   - `MX alice.com → mail.rookery.example`
   - `TXT alice.com → "v=spf1 include:_spf.rookery.example ~all"`
   - `CNAME rookery._domainkey.alice.com → rookery._domainkey.rookery.example`
   - `TXT _dmarc.alice.com → "v=DMARC1; p=quarantine; rua=mailto:dmarc@alice.com"`
   - `CNAME openpgpkey.alice.com → openpgpkey.rookery.example`
   - `CNAME mta-sts.alice.com → mta-sts.rookery.example`
   - `TXT _mta-sts.alice.com → "v=STSv1; id=<server-generated>"`
   - `TXT _smtp._tls.alice.com → "v=TLSRPTv1; rua=mailto:tls-reports@alice.com"`
   - `TXT _rookery-challenge.alice.com → "<verification-token>"`
4. **Verification.** Alice publishes the records and clicks "verify." Server polls DNS; shows per-record green/red status. Allows partial progress — Alice can leave and come back, the page remembers.
5. **Once verified.** Per-domain DKIM keypair is generated server-side, MTA-STS cert is provisioned via ACME, WKD endpoint is activated for `alice.com`. Server confirms inbound mail to `alice@alice.com` is being accepted. Alice gets a test message sent to her own address to verify end-to-end.
6. **Then: same flow as 5.2a from step 3 onward.** Key generation, public-key upload, then settings page where the passphrase is set and the recovery file is exported.

**Total time:** dominated by DNS propagation, ~15 minutes if Alice's registrar is fast (Cloudflare, Namecheap), up to a couple of hours if it's slow. Active configuration time: maybe 10 minutes of copy-paste.

**Why this is the killer feature:** Alice's identity is `alice@alice.com`, owned by Alice, not by the instance. If she ever leaves this instance — operator quits, instance goes down, Alice gets unhappy with policies — she changes her MX and DKIM CNAMEs to point at a new instance, exports her mailbox from instance A and imports it into instance B (her key never left her browser to begin with, so there is nothing key-shaped to "move"), and her *email address is unchanged*. This is what "deliberately replaceable" means at the user level. Without custom domains, leaving an instance is a forced address change. With them, it's a DNS update.

### 5.3 Daily-use journey — "I have an account, what's it like?"

Most of the product surface lives here, and most of the time it looks unremarkable, which is the point.

**Login (every device, every time).** Alice visits `https://rookery.example` (or her own bookmark), enters her passphrase, and selects her recovery `.asc` file. The login JS unlocks the private key locally with the passphrase, then performs a challenge/response: the server issues a nonce, the client signs it with the unlocked key, and the server verifies the signature against the stored public key. On success the server issues a session cookie. The unlocked key is then cached in `localStorage` (AES-256-GCM wrapped), shared across all tabs and browser restarts, and cleared on logout. The server never sees the passphrase or any hash of it — the only authentication material it holds is the public key it already publishes via WKD. Within a single login session, opening new tabs auto-decrypts encrypted messages without further prompts. The recovery file can be re-exported at any time from settings. Re-exporting it with a new passphrase **is** a passphrase change — the server authenticates by signature, not by a stored hash, so there is nothing server-side to update. The new file replaces the old one; the new passphrase is required for all subsequent logins.

**Session key in localStorage — the plaintext window.** The AES-GCM wrapping of the session key in `localStorage` is an ergonomic measure, not a cryptographic barrier: the wrapping key and the wrapped blob both live in the same storage at the same origin, so a same-origin attacker (malicious JS, browser extension, or anyone with read access to the browser profile on disk) can recover the private key while the session is active. The server never holds the private key; the risk is local to the device and exists only during the session. **Users who cannot trust physical or remote access to their machine while logged in should log out when done.** The UI recommends this explicitly. Logout removes all three localStorage keys; the private key is gone from the browser until the next login with the recovery file and passphrase.

**Reading an encrypted message.** Server renders inbox row → Alice clicks → read page renders headers, structural metadata, attachment list. Body area initially shows "decrypting..." JS module fetches the ciphertext, decrypts in memory, renders. Signed-by status is shown plainly: "Signed by Bob (fingerprint match)" / "Signed but key unknown" / "Unsigned." Plaintext-received messages render normally with an obvious "this message was received in plaintext" banner.

**Composing to someone with a known key.** Alice clicks "Compose." As she types `bob@…`, a small in-house JS helper (see §7 and ADR-0012) debounces and hits the server's discovery endpoint. Server checks: known-keys cache → WKD → keyserver. Result shows next to the recipient: green padlock with fingerprint preview, or yellow "first seen" badge, or red "no key found." Multi-recipient: each gets its own indicator. On submit, the JS module fetches the recipient public keys + Alice's decrypted private key, builds a PGP/MIME message, attaches Alice's own public key, POSTs ciphertext. Server queues.

**Composing to someone with no discoverable key.** Same flow, but the recipient row shows red "no key — this will be plaintext." The send button is disabled until Alice explicitly toggles "Send in plaintext anyway" per-recipient. Mixed recipients (some known-key, some not) show a banner: "This message will be sent encrypted to 2 recipients and in plaintext to 1." Alice must acknowledge before sending.

**Receiving a reply from someone new.** Bob (using Thunderbird+OpenPGP, or another `rookery` instance, or Proton, or `gpg` directly) replies. His message includes his public key as an auto-attached PGP key, or our server discovered it via WKD on the next send. Either way, Alice's known-keys cache now contains Bob's key with a "first seen on `<date>`" annotation. Subsequent threads with Bob are seamlessly encrypted.

**Losing the device.** Alice's laptop dies. The login flow is identical to any other login — passphrase plus recovery file. Nothing device-specific was stored. The recovery file is the only off-device copy of her key; the server has nothing to "return." **If she has no recovery file, her mail is unrecoverable, regardless of whether the server is up.** Hard rule, said plainly at onboarding (§5.2a step 7). She can register a new keypair on a new account, but past mail decrypted under the old key is gone. This is the inverse of the common webmail model and it is deliberate: the server has no power to lock Alice out of her mail, and equally no power to rescue her from a lost recovery file. She holds both halves.

**Migration to another instance.** (Phase 7.) Alice on `alice@alice.com` decides to move from instance A to instance B. From instance A she exports her mailbox archive (server-side data: messages, addresses, aliases, known-keys cache, metadata). She joins instance B via the custom-domain flow, imports the mailbox archive there, and uploads her existing public key so instance B can publish it via WKD and attach it to outbound. Her private key was never on instance A in the first place — it lives only in the recovery file she controls. The first login on instance B is the standard login flow: passphrase plus recovery file, same as every other login. She points her DNS records at instance B's hostnames, waits for propagation. Her address, her key, her thread history — all preserved. Correspondents notice nothing.

### 5.4 What these journeys explicitly rule out

Naming the absences is as important as naming the features:

- **No "forgot my passphrase" link, anywhere, ever.** Not on login, not in settings, not as a recovery flow with security questions. Hard rule, surfaced honestly at onboarding. The server holds no passphrase hash and no encrypted private key — there is literally nothing server-side to reset or recover from.
- **Passphrase change is self-service, server-free.** Because authentication is a signature and not a password check, changing the passphrase requires no server interaction at all. The user re-exports the recovery file from settings with a new passphrase; the new file replaces the old one; the new passphrase is in effect immediately. No confirmation email, no current-password verification endpoint, no server-side state to update.
- **No server-side private-key storage.** The server holds public keys (it has to, for WKD and outbound auto-attach) and nothing else key-shaped. The encrypted private key is never held by the server; it lives in the recovery file the user keeps off-device, exportable on demand from settings. The unlocked key is cached in `localStorage` and cleared on logout; the server never holds it. The server cannot rescue a user who lost the recovery file, and cannot be compelled, subpoena'd, or breached into surrendering private keys it does not possess. §11.1 / ADR-0010 spells out the model and the trade-off against the "encrypted blob on the server" alternative we considered and rejected.
- **No multi-device sync, and no device-specific state.** Every login on any device requires the recovery file alongside the passphrase. There is nothing device-specific to sync — the session key in `localStorage` is cleared on logout and the recovery file is device-independent.
- **No mobile app, and no mobile-optimized experience, in v1.** Mobile browsers will *load* the same UI and basic flows will work, but we do not optimize layouts, gestures, or input for phones, and we do not ship a native iOS/Android app. This is a deliberate match to the audience: the target user is desktop-heavy, has a keyboard and a real file system, and is unlikely to want a long-lived PGP private key sitting on a phone they lose, lend, or replace every two years. A future PWA or native client is a Phase 8+ conversation, not a v1 gap.
- **No SMS, no phone number, no recovery email.** Identity is the keypair, period.
- **No IP logging by default.** The web UI and the SMTP submission ports do not persist connecting IP addresses, on signup or on subsequent logins. Operators who want IP logging for their own debugging or abuse-investigation purposes can flip it on per-instance, with the consequences for pseudonymity made explicit in the config-file comment. The default is off.
- **No push notifications.** SSE for in-page updates while a tab is open; that's it. No mobile push, no email-to-SMS bridges, no desktop OS notifications in v1.
- **No address book service.** Known-keys cache is the only contact concept. No fields for phone, birthday, company, photo.
- **No social graph, no presence, no read receipts.** Email semantics only.
- **No moderators in v1, and no in-app admin.** One role: user. The operator (whoever has shell access) handles abuse via shell scripts (§11.8). If a public instance grows large enough to need in-app moderation, that's a v2 conversation or — more likely — a signal that the instance should split.

These omissions are the product, not gaps in the product.

## 6. High-level architecture

```
                       ┌─────────────────────────────┐
   Other mail servers  │      rookery instance       │   Browser
   ── SMTP (25/465/587) ──▶│                         │◀── HTTPS ──┐
   ◀── SMTP ───────────────│  ┌───────────────────┐  │            │
                           │  │ inbound SMTP      │  │   ┌────────┴───────────┐
                           │  │ outbound SMTP     │  │   │ Server-rendered    │
                           │  │ MIME + PGP/MIME   │  │   │ HTML + plain JS:   │
                           │  │ WKD server        │  │   │  - OpenPGP.js      │
                           │  │ public-key        │  │   │    (OpenPGP s2k,   │
                           │  │   auto-attach     │  │   │     RFC 9580)      │
                           │  │ key discovery     │◀─┼───┤  - in-house        │
                           │  │ html/template UI  │  │   │    partials.js     │
                           │  │ message store     │  │   │    (fetch + swap)  │
                           │  └───────────────────┘  │   │  - session key in  │
                           │   Postgres + blobs      │   │    localStorage    │
                           └─────────────────────────┘   └────────────────────┘
```

Key ideas:
- **The browser is the trust anchor for content.** Private keys are generated in the browser, encrypted with a passphrase-derived key (OpenPGP.js s2k per RFC 9580), and held only in a recovery file the user controls. The server never holds the private key — not in plaintext, not encrypted. See §11.1 for the model and the trade-off.
- **The server renders the chrome.** Inbox lists, threads, settings, navigation — all server-rendered HTML. No client-side router. Rationale in P6 and §9 risk 6.
- **JS does crypto.** A small, auditable JS module on the compose and read pages handles encrypt/decrypt against locally-held keys. Form submit is intercepted, ciphertext is posted to the server. Without JS, compose and read show a "JS required for PGP" notice; the rest of the UI works fine.
- **JS also does partial updates, in-house.** A second small module — `partials.js`, hand-written, no third-party library — provides `fetch + swap` helpers for the handful of places we want partial-page updates (recipient key-status hints, DNS verification polling, mark-as-read, inbox refresh). It exposes a few primitives (`swap`, `poll`, `debounce`, `onSubmit`) and operates on `data-*` attributes. Endpoints called by this module return **HTML fragments**; JSON is reserved for the crypto module's raw-data needs (ciphertext, key material). The reasoning and the contract live in ADR-0012.

### Message lifecycles

**Outgoing (Alice → external `bob@gmail.com`):**
1. Alice opens the server-rendered compose page.
2. As she enters recipients, the page (via the in-house `partials.js` helper) asks the server: "do you know a key for `bob@gmail.com`?"
3. Server tries: local directory → WKD (`https://gmail.com/.well-known/openpgpkey/...`) → optional keyserver (e.g. `keys.openpgp.org`) → cached result. Result is shown next to each recipient.
4. On submit, the JS module fetches recipient keys + Alice's private key (decrypted in-browser with her passphrase), produces a PGP/MIME encrypted+signed message, and POSTs the resulting `.eml` to the server. Alice's public key is auto-attached.
5. If no key for a recipient, the form shows a clear "this recipient will receive plaintext" warning and requires explicit confirmation.
6. Server's outbound SMTP queue delivers the message.

**Outgoing (Alice → `bob@another-rookery.example`):**
- Identical to above. Discovery succeeds via WKD because the other `rookery` instance also publishes WKD, or via Bob's previously-received auto-attached key. No special protocol.

**Incoming (`carol@gmail.com` → Alice):**
1. Server receives over SMTP, stores the raw RFC 5322 message in the blob store.
2. If PGP-encrypted: server can't read it. Stores ciphertext as-is.
3. If plaintext: server stores plaintext and flags it as non-E2E for the UI.
4. If an auto-attached public key is present, server harvests it into a "known keys" cache for that sender address (with a clear "first seen" indicator).
5. The read page server-renders headers + structural metadata; the JS module fetches the raw body and decrypts in the browser if needed.

**Key publishing (Alice's public key):**
- Published at `https://<instance>/.well-known/openpgpkey/...` per the WKD spec — discoverable by Thunderbird, GPG, Proton, other `rookery` instances, anyone.
- Also auto-attached to every outbound message Alice sends, so recipients have her key for replies without needing to perform a lookup.
- Later (Phase 8): also exposed via Autocrypt headers on outbound mail for clients that prefer that mechanism.

## 7. Tech stack

| Layer | Choice | Rationale |
|---|---|---|
| Server language | **Go** | Mature SMTP libs (`emersion/go-smtp`, `emersion/go-message`), strong stdlib, single-binary deploys. |
| HTTP framework | `net/http` + `chi` | Boring, fast, no magic. |
| SMTP (inbound + outbound) | `emersion/go-smtp` + `emersion/go-message` | De facto standard Go SMTP/MIME stack. |
| OpenPGP on server (for discovery, signing of WKD records) | `ProtonMail/go-crypto` (OpenPGP fork) | Actively maintained, used in production by Proton. |
| Database | **PostgreSQL** | Boring, reliable. One backend, not two — see §11.6. |
| Migrations | `golang-migrate` | Decided in §11.6. |
| Blob storage (raw `.eml` files) | Filesystem, content-addressed paths (`/blobs/sha256/ab/cd/...`) | §11.6. S3-compatible is a Phase 8+ option if it's ever wanted. |
| Frontend rendering | **Go `html/template`** (stdlib) | No framework, no build step for HTML. |
| Frontend interactivity | **In-house `partials.js`** — hand-written, no third-party library | `fetch + swap` helpers for partial updates (key-status hints, DNS polling, mark-as-read). Replaces HTMX. Per P12, every avoided dependency is a removed supply-chain attack surface; this one we can replace with ~150–250 lines of code we own and audit. Endpoints return HTML fragments. Reasoned out in ADR-0012. |
| Frontend styling | Hand-written CSS, single stylesheet. Visual direction: techie-utility, in the lineage of `archlinux.org` and `voidlinux.org` — see §11.14 for the full spec. | Techie audience, no design system needed. We deliberately **avoid** even classless frameworks like `pico.css` — same supply-chain reasoning (P12). Hand-written CSS in a single file is fine for the v1 UI's scope, and the visual target is information-forward enough that no framework would help anyway. |
| Client crypto module | **OpenPGP.js**, loaded as a single pinned + SRI'd script on compose/read pages only | The standard. Tiny isolated surface. *This is one of the few third-party browser deps we accept; we are not going to write OpenPGP ourselves.* Pinned to a specific commit, SRI-locked, no transitive deps at runtime. |
| Passphrase KDF (client side) | OpenPGP.js's built-in s2k (RFC 9580 §3.7.1.4) | OpenPGP.js encrypts the private key with the passphrase when producing the recovery file (via `openpgp.encryptKey`); no separate KDF library is needed. The keypair is generated unencrypted at signup and the passphrase is set by the user on the settings page immediately afterwards. A previously-planned `argon2-browser` WASM dependency was removed — it was redundant with OpenPGP.js's own KDF. There is no server-side passphrase hashing — authentication is PGP challenge/response (§11.2). |
| Client storage | `localStorage` for the within-session unlocked key cache (AES-GCM wrapped, cleared on logout). Recovery `.asc` file held off-device by the user, exportable on demand from settings and required on every login. | Passphrase never leaves the device. Private key never leaves the user's control — server holds nothing key-shaped on the private side, see §11.1. Nothing persists between sessions; IndexedDB is not used. **The AES-GCM wrapping is not a cryptographic barrier against a same-origin or local attacker** — the wrapping key and blob coexist in `localStorage` at the same origin, so the plaintext private key is recoverable by anything that can read browser storage while the session is active. The risk is local and session-scoped; logout eliminates it. Users are warned at login and in settings; see §5.3 for the full discussion. |
| Server-push (later) | Server-Sent Events via browser-native `EventSource` for new-mail notifications | Long-poll first. No WebSockets. No library — `EventSource` is stdlib in the browser. |
| Build | **The Containerfile is the build.** `docker build` on a clean checkout produces the deployable image, with no other host-side toolchain required. Inside the multi-stage build: Go toolchain compiles the server; a single `esbuild` invocation bundles the JS crypto module (and only that — `partials.js` ships hand-written, no bundler). No `npm run dev`, no Vite. No transitive `postinstall` scripts permitted at any build stage. **No hosted CI provider is assumed.** The project is forge-agnostic — GitHub, Codeberg, sourcehut, a self-hosted Gitea, or a tarball on someone's web server are all equally valid hosting choices. If a hosted CI is in use for a particular fork or mirror, it runs the same `docker build` and the same in-repo test scripts that any developer or self-hoster runs locally; the project does not ship forge-specific workflow files in v1. Lint and test entrypoints (`go test`, `go vet`, optionally `golangci-lint`) are invoked inside the container build or via the `rookery` shell-script dispatcher (`rookery test`, `rookery vet`; ADR-0033), runnable by anyone with `docker` installed and nothing else. | Minimal toolchain, minimal supply-chain exposure, no vendor lock-in for the build pipeline. |
| Container | Multi-stage `Dockerfile` (also valid `Containerfile`), distroless final image. **The Containerfile is the only supported build path** — not just for deployment but for development too, where JS bundling is involved (Go code can be iterated with native `go run` / `go test` on the host, which is normal and fast; the JS crypto module goes through the container build so developers don't have to install Node or esbuild on their host). **Runtime: Docker only, with the Compose v2 plugin.** Rootless Podman was evaluated during Phase 0 and rejected — privileged-port binding, OCI vs Docker image format, short-name resolution, and `podman-compose` bookkeeping noise added up to too much friction for too little gain, and supporting both runtimes doubled the surface area we'd have to test and document. The compose-spec file is what it is; operators on Podman hosts can run the Docker CLI against the Podman socket if they really want to, but that path is not tested or supported. | Easy self-host. One runtime to document, one runtime to test against; we explicitly trade a small piece of audience preference for a much simpler operator experience. |
| License | **AGPLv3** | Closes the SaaS loophole. Anyone running rookery as a service has to ship their changes back. |

### Explicitly deferred / rejected

- **No frontend framework.** No React/Vue/Svelte/Solid/etc. Server-rendered HTML + a tiny hand-written `partials.js`; JS for crypto and a handful of partial updates, nothing else. See P6 and §11.14.
- **No HTMX or HTMX-equivalent.** We considered HTMX and rejected it on supply-chain and minimalism grounds. Our partial-update needs (recipient key hints, custom-domain DNS verification polling for user self-serve, mark-as-read) are small enough to handle in ~200 lines of hand-written JS. See ADR-0012.
- **No CSS framework**, not even classless ones like `pico.css`. Hand-written CSS only.
- **No IMAP/POP** server. Hard rule for v1.
- **No mobile apps**, no PWA, no mobile-optimized layout in v1. See P9 and §5.4.
- **No custom inter-instance protocol, no DHT, no libp2p, no blockchain.** Two rookery servers communicate the same way Postfix and Exchange do: SMTP over the internet. There is nothing else.
- **No multi-device key sync.** One device per account by default.
- **No account recovery.** Lose passphrase → lose mailbox. Documented.
- **No encrypted Subject lines.** Standard PGP/MIME leaks them; ecosystem norm; not solvable interoperably.
- **No `npm`-style dependency cascades anywhere.** OpenPGP.js is the single browser dependency, pinned-with-SRI; `npm ci --ignore-scripts` runs only inside the Containerfile build stage, and transitive `postinstall` scripts are forbidden (P12). There is no separate KDF dependency — OpenPGP.js's built-in s2k covers private-key encryption.

## 8. Roadmap

This is a side project. The roadmap is a dependency graph and a rough sizing signal, not a deadline.

**Phase budgets** below are given in *engineer-weeks of focused full-time work* — useful for chunking and for knowing which phases are big vs small relative to each other. Real calendar time on a side-project cadence is whatever it is; multiply by your own pace factor. The sizing exists to communicate "this phase is twice as big as that one," not "you'll be done by month four."

**Phase ordering** is not strict. The phases overlap freely — Phase 3 (TLS) establishes the ACME infrastructure that Phase 4 (custom-domain infrastructure) and Phase 5 (operator setup) build on; Phases 4 and 5 also share DNS-verification and key-lifecycle code. Treat phases as cohesive workstreams, not as a Gantt chart.

**ADR prerequisites** are called out inline where a phase depends on a design decision not yet made (see §11).

### Phase 0 — Foundations (≈1 week)
- Repo scaffolding, Go module, Containerfile (multi-stage: Go build + JS bundle + distroless final image). No Makefile — the `rookery` shell-script dispatcher (ADR-0033) is the single operator and developer interface; it wraps `docker compose` underneath. See §7.
- ADRs for the major decisions in this doc (at minimum: ADR-0001 through ADR-0008 from §13).
- README + this plan.
- `compose.yaml` with Postgres + a minimal SMTP test harness (e.g. `mailpit`) for local dev.
**Deliverable:** `rookery init && rookery start` boots an empty server with `/healthz` (and mailpit for SMTP testing). The project builds from a clean checkout on any host with only `docker` installed. ADRs committed.

### Phase 1 — Receive mail, decrypt in the browser (≈4–6 weeks)
- Inbound SMTP listener (port 25, STARTTLS-preferred, see §11.4) that accepts mail for the instance's primary domain.
- User accounts (challenge/response authentication signed by the private key — no passphrase hash stored server-side, see §11.2). Cookie-based sessions with sliding expiry.
- In-browser keypair generation (Curve25519, §11.1); **public key uploaded; private key stays in the browser** — generated without a passphrase at signup, then immediately cached in `localStorage` (cleared on logout); user is redirected to settings to set a passphrase and export the recovery `.asc` file. The server never receives the private side.
- **Plus-addressing** from day one: `alice+anything@<primary>` routes to `alice`. Free with proper local-part parsing; cheap to do now, painful to retrofit.
- **Reserved local-parts** (`postmaster@`, `abuse@`, `hostmaster@`, `webmaster@`) auto-created on the primary domain and routed to the operator's user account (or to a configured fallback address).
- WKD endpoint serving local users' public keys, advanced method (§11.7). Z-base-32 SHA-1 hashing of local-parts is non-trivial; budget for interop testing.
- Mailbox model from §11.5: inbox, read/unread state, soft-delete to trash, virtual sent/drafts/bounced views (sent/bounced are empty in Phase 1; the structure is in place).
- Server-rendered inbox + read pages. Small JS module on the read page decrypts PGP/MIME bodies locally.
- Mail can be sent **into** the system from any external mailer (e.g. `gpg` + `swaks`, Thunderbird) and read in the browser.

**Deliverable:** External user PGP-encrypts a message to `alice@yourdomain` via WKD lookup, sends it from their normal mailer; Alice reads it decrypted in her browser.

> **Phase 1 is not yet a "useful product" in isolation** — you can receive PGP mail but not send it. Phases 1 and 2 should be viewed as a unit; we ship to friends-testing only at the end of Phase 2. This is a deliberate softening of P13 ("useful at every milestone") for the first two phases; we are honest about it.

### Phase 2 — Send mail outbound, key discovery, primary-domain delivery (≈4–6 weeks)
- Submission listeners on 465 (implicit TLS) and 587 (STARTTLS), auth required (§11.4). *These ports are started in Phase 2 but require TLS certificates to be fully operational; Phase 3 provisions them.*
- Server-rendered compose page.
- Server-side key discovery: local directory → WKD → optional keyserver. Cached with TTL. Recipient key-status hints (rendered as HTML fragments by the server, swapped into the compose page by `partials.js`) update next to each address as Alice types, with debounce + in-flight cancellation.
- Client-side PGP/MIME encryption + signing on form submit.
- **Auto-attach Alice's public key** to every outbound message.
- **Harvest auto-attached keys** from inbound messages into the per-user known-keys cache (with "first seen" indicators).
- Outbound SMTP queue with retries, DSN handling, and the bounce policy in §11.4.
- Per-user and per-instance outbound rate limits (§11.4).
- Plaintext fallback with explicit confirmation when no key is found for a recipient.
- Basic threading (group by `In-Reply-To` / `References`).
- **DKIM signing** (ed25519 + RSA-2048 fallback per §11.7), SPF and DMARC alignment on outbound, **for the instance's primary domain only.** (Per-user custom-domain DKIM lands in Phase 4.)
- Sent and Drafts virtual views become populated.
- HTTP API extended to cover send, draft, discovery, and queue-status endpoints.

**Deliverable:** Two-way email with the rest of the world, on the *instance's primary domain*. PGP-to-PGP works automatically when a key is discoverable via WKD or has been auto-attached on a prior message. Plain SMTP delivery on the open internet works with proper DKIM/SPF/DMARC alignment for the primary domain. (Submission on 465/587 is wired up but not yet usable without TLS; Phase 3 makes those ports operational.)

### Phase 3 — TLS and HTTPS for the primary domain ✓ complete

This is the "make it safely deployable on the public internet" phase. Phases 1 and 2 deliver working receive and send; this phase puts TLS under everything. Without it, the PGP challenge/response login (ADR-0015) travels in plaintext, session cookies are insecure, and the primary-domain WKD endpoint is not spec-compliant (WKD requires HTTPS). This work was previously spread across Phases 4 and 5 of the earlier plan; it is moved forward because any operator who has finished Phase 2 can and should put their instance on the internet at this point.

- **TLS termination via Caddy reverse proxy.** Rather than embedding an ACME client in the Go binary, TLS is handled by a Caddy sidecar in the compose stack (`rookery start --prod`, or the systemd-managed equivalent). Caddy provisions and auto-renews Let's Encrypt certificates via HTTP-01, handles the HTTPS→HTTP proxy to rookery on port 8080, and manages HSTS. `rookery init` generates the `Caddyfile` from the domain (and optional contact email) in `rookery.toml`. ADR-0024 records the full rationale for choosing Caddy over `certmagic`-in-Go.
- **rookery HTTP server on port 8080.** The Go binary serves plain HTTP only; Caddy is the TLS boundary. In dev (`--profile dev`) operators hit port 8080 directly with no Caddy and no certificates. In production Caddy forwards HTTPS traffic to port 8080 on the Docker-internal network.
- **Session cookies gain their `Secure` flag automatically.** The existing `auth.SetCookie` already checks `X-Forwarded-Proto` (set by Caddy) and marks cookies Secure when the request arrived over HTTPS.
- **`openpgpkey.<domain>` HTTPS.** The WKD advanced method endpoint (live since Phase 1) requires HTTPS per spec. The `Caddyfile` includes an `openpgpkey.<domain>` block that Caddy provisions a cert for; once Phase 3 ships, WKD is spec-compliant for the primary domain.
- **SMTP STARTTLS deferred.** Caddy handles HTTP/HTTPS but cannot terminate SMTP. STARTTLS on port 25 and submission on 465/587 require a separate cert-management solution and are deferred to a later phase.
- **No new Go dependency.** Caddy is an independent process; the Go binary is unchanged. The `certmagic` package was evaluated and not added (see ADR-0024).

**Deliverable:** The web UI is reachable at `https://<domain>` with a valid Let's Encrypt certificate. Session cookies are Secure when served over HTTPS. The primary-domain WKD endpoint is spec-compliant HTTPS. Certificate renewal is automatic via Caddy. Dev workflow (`--profile dev`, port 8080) is unaffected.

### Phase 4 — Custom domains and per-domain infrastructure (≈6–8 weeks)
**This phase is the killer-feature work.** It was previously bundled into Phase 2 as a bullet point; it is in fact the largest single workstream in the project, because it is the thing that makes §5.2b — `alice@alice.com` on a self-hosted instance — actually work. Without this phase delivered well, the project is "Proton but you host it," which is a worse Proton, not a real alternative.

- **User journey for adding a domain.** UI generates the full set of DNS records (MX, SPF, DKIM CNAME/TXT — both ed25519 and RSA selectors, WKD CNAME, MTA-STS CNAME + TXT, TLS-RPT, DMARC) with copy-paste values. TXT-challenge verification (`_rookery-challenge.<domain>`) before the domain is activated.
- **Per-domain DKIM lifecycle.** Two DKIM keypairs (ed25519 + RSA-2048, §11.7) are generated when a domain is verified; private keys encrypted at rest with the server master key (§11.6); public keys published via the user's DNS as CNAMEs to our selectors. Outbound mail from `@<domain>` is signed with that domain's keys. Rotation tooling stub (full dual-selector rotation lands in Phase 8).
- **Per-domain WKD serving.** `openpgpkey.<domain>` serves the published keys of users on that domain. Per-domain TLS via ACME HTTP-01 (§11.7).
- **Per-domain MTA-STS and TLS-RPT.** Automatic ACME provisions certs for `mta-sts.<domain>`. Policy mode `testing` for the first 48 hours, then `enforce` (§11.7). TXT record published, kill switch available per-domain (default off, can be flipped on for incident response). **Cert renewal failure raises an unmissable operator alert ≥14 days before expiry**, because expiry here breaks inbound mail.
- **Multiple addresses per user, across multiple domains.** Once domains are a thing, the multi-address model from §11.3 becomes real: a user can hold `alice@personal.example`, `alice@work.example`, and `a@a.li` on one account/key, with a default From and per-message override.
- **Per-user address aliases** (e.g. `support@alice.com` → `alice`), set up in account settings.
- **Catch-all on custom domains**, opt-in per domain, default off (§11.3).
- **Reserved local-parts** (`postmaster@`, `abuse@`, etc.) auto-created on every newly verified custom domain.
- **DNS preflight and drift detection.** Continuously re-checks records and surfaces drift in the UI. A user whose registrar quietly drops a CNAME finds out from us, not from a confused correspondent.
- **Custom domains are always user self-serve.** There is no per-instance policy toggle and no `add-domain.sh` script. Users add domains via the web UI flow (§5.2b); the operator can pre-register domains via `psql` for advanced cases.
- HTTP API extended to cover domain registration, verification status, DNS-record reads, address & alias management, catch-all toggling.

**Deliverable:** A user on a public instance can bring `alice@alice.com`, complete the full DNS setup with our guidance in well under an hour of active configuration time, and have working two-way encrypted mail on their own domain with strict transport security. Migrating that domain to a different `rookery` instance later requires only changing CNAMEs — that promise is now real, because the records exist as a set.

### Phase 5 — Operator runbook and deliverability foundations (≈4–6 weeks)
The "make it actually-runnable for the operator" phase. Reuses ACME infrastructure from Phase 3 and DNS-verification and key-lifecycle code from Phase 4. **No setup wizard, no admin web UI** — per P10 the operator works from the shell.

- **`compose.yaml` and `rookery.toml` examples** in the README, with sensible defaults. Operator copies, edits two or three values, brings up the stack. The config schema is documented inline in the example file.
- **Server-side bootstrapping on first run.** First-run server generates the DB schema, the per-instance signing keys, the primary-domain DKIM keys, the ACME account; logs the DNS records the operator needs to publish. No interactive flow.
- **Server master key generation and rotation.** First run generates the server master key and writes a one-time setup note to the log telling the operator to back it up. Rotation is a documented `psql` + `./scripts/rotate-master-key.sh` procedure.
- **Operator subcommands** added to the `rookery` dispatcher (ADR-0033). v1 set: `rookery user suspend`, `rookery user unsuspend`, `rookery user delete`, `rookery dns print`, `rookery stats print`, `rookery master-key rotate` (or the flat equivalents — `suspend-user`, `print-dns` — chosen per case at coding time; ADR-0033 documents the noun-verb preference). Each is a few dozen lines of shell in the dispatcher source, typically a small `psql -c "..."` plus a `printf`. Custom-domain management remains user self-serve (no `rookery domain add` subcommand; operators can use `rookery psql` for pre-registration).
- **Bundled, pre-configured spam filtering** per §11.13 (ADR-0032): rspamd with stock defaults, Redis sidecar, ClamAV opt-in. No Bayesian training UI in v1 — that's a coherent Phase 8+ piece of work touching the inbox UI, storage model, and spam pipeline together. *We acknowledge per §9.2 that "works out of the box" here means "reasonable defaults, not Gmail-quality"; ongoing tuning is expected work.*

- **Observability**: structured logs, Prometheus metrics endpoint. Cert renewal status, queued mail, recent bounces, per-user outbound volume, anomaly signals — all exposed as metrics. Operators wire their own Grafana or Alertmanager if they want graphs and alerts; we don't ship a UI for these.
- **Docs**: deployment guide, DNS reference, troubleshooting, "your mail is going to spam" runbook (which honestly explains the IP-reputation problem; see §10 and the README), custom-domain onboarding guide, **operator runbook** documenting every shipped script and the common `psql` queries (`SELECT * FROM users`, `UPDATE users SET quota = ... WHERE address = ...`, etc.).

**Deliverable:** A competent operator with a domain and a $5/month VPS goes from "fresh box" to "first invite URL generated" in under 30 minutes of *active configuration time* (DNS propagation and reverse-DNS turnaround excluded — see §10). The flow is: clone the repo, `rookery init --domain <yours> --email <yours> --name <yours>`, `sudo rookery install`, `systemctl enable --now rookery`, paste DNS records, wait for propagation, `rookery invite create`. If any of those steps drift past the time budget, fix the dispatcher or the example config, not the operator's expectations.

### Phase 6 — Productionize the user experience (≈4–6 weeks)

> **Prerequisite spike:** before Phase 6 planning locks, run a one-day perf investigation of OpenPGP.js with a 25 MB attachment (encrypt + decrypt round-trip, in a real browser, on a representative laptop). The output is a number, not a design — we need to know whether chunked encryption is "a week" or "a month" of work before committing to the Phase 6 budget. Per §9.7 the problem is known; the spike is what turns the known unknown into a sized known.

- Attachments (PGP/MIME parts; **chunked encryption** in the client for large files — this is a real piece of OpenPGP.js work, budget for it; the prerequisite spike above sizes it).
- Client-side full-text search index (decrypted in the browser, never sent to server, §11.5).
- **Account deletion flow** with the design from §11.9 (user-initiated web flow with 7-day grace period and double-passphrase confirmation; operator-initiated variant via `./scripts/delete-user.sh` for abuse cases).
- **Backup tooling.** Single-command encrypted backup per §11.10 (ADR-0029): `tar.zst` of `pg_dump` + blob tree, encrypted with age to an operator-provided recipient, bundled `backup.sh` and `restore.sh` scripts. Automated restore-from-backup test in the in-repo test suite per the NFR (runnable by anyone with `docker`; no hosted-CI dependency, §7).
- Per-user export of full mailbox (server-side data only — the user's private key has never been on the server, see §11.1; the recovery file the user already holds is the key half of the migration), in the format the migration story uses (Phase 7 will consume this).
- Documented interop recipes: "decrypt your stored mail with `gpg` directly," "import your `rookery` key into Thunderbird," "export and re-import into another instance."
- Threat model written up in `SECURITY.md`.

**Deliverable:** A version trusted to run on a real domain for real correspondence, with a documented escape hatch.

### Phase 7 — Portability & migration (≈4–6 weeks)
This is what makes "trust no single instance" real. If migration between instances is trivial, no operator becomes load-bearing.

> **Design prerequisite:** the key-rotation attestation protocol is shape-committed in §11.10 (ADR-0028) but the wire format and exact header layout still need a written ADR before code lands. The identity model and address model are already resolved (§11.1, §11.3); the attestation protocol is the last design document to draft.

- **Key-as-identity in practice:** a user's identity is their long-lived PGP key fingerprint (§11.1). Their bundle of addresses is portable along with the key. On a destination instance the user imports the export, then re-registers each address (instance-domain addresses become new addresses; custom-domain addresses come with the user by repointing DNS).
- **Full mailbox export from the server**: complete mailbox + addresses + aliases + known-keys cache + metadata + the user's public key, in the format established in Phase 6. **The export does not contain the private key** — it has never been on the server (§11.1); the user already holds the only copy in their recovery file. Migration is therefore *two* artifacts that the user owns: the mailbox archive (from instance A's export) and the recovery file (which they already have).
- **Import** on a fresh instance from the mailbox archive. The new instance's web UI prompts for the recovery file on first login, exactly as in the new-device flow (§5.3); the user enters their passphrase and is back in business. There is no special "key import" step in the migration UI — re-using the existing recovery-file affordance keeps the migration flow small and the audit surface tiny.
- **Address forwarding** during migration windows so contacts using the old address still reach the user. (Applies primarily to users leaving an instance's primary domain; custom-domain users repoint DNS instead.)
- **Key rotation** with audit trail visible to user and (signalled to) past correspondents via signed key-change attestations included with future messages, per the shape committed in §11.10 (ADR-0028): attestations are message headers, signed by the outgoing key, covering `(old fp, new fp, counter, timestamp)`, attached to outbound for 90 days post-rotation. Wire format and exact header layout are specified in the ADR.

**Deliverable:** A user on a custom domain can move from instance A to instance B in under 15 minutes of active work (DNS propagation excluded), without losing mail or breaking encrypted threads. Users on the instance's domain get a forwarding window but accept an address change — that's the cost of not owning a domain, and we say so.

### Phase 8 — Hardening & ecosystem (open-ended)
- Autocrypt support (header-based key exchange) — sibling of our auto-attach.
- Instance-level abuse controls: rate limits, optional peer allowlists.
- Interop conformance tests against major providers (Gmail, Fastmail, Posteo, Proton).
- Optional smarthost integration for instances that don't want to fight IP reputation directly, per the shape committed in §11.10 (ADR-0030): opt-in (off by default), per-instance scope, rookery signs DKIM before handoff. The same `[smtp.smarthost]` block accepts either a **commercial relay** (AWS SES, Postmark, Mailgun) or a **relay rookery** (another rookery instance acting as upstream) — the wire shape is identical SMTP submission and the smarthost-is-opaque-transport property is what makes the inter-instance variant safe. The relay-rookery arrangement is bilateral and operator-configured out of band (no directory, no auto-discovery); abuse exposure for the relay-rookery operator is real and documented. *This is the realistic deliverability fix for new operators; see §9.1.*
- DMARC aggregate report ingestion + per-domain dashboard surfacing alignment failures.
- DKIM key rotation tooling (dual-selector transitions, automated DNS-update prompts).
- Hardware key (YubiKey) support for unlocking the encrypted private key in the browser, replacing or supplementing the passphrase-derived key.

**Deliverable:** A version that survives the open internet at small-instance scale.

### Phase 9+ — Possibly later
- Optional minimal IMAP read-only export (controversial — discuss before building).
- Key transparency log integration.
- Group conversations / mailing list assistant.
- UI polish, keyboard shortcuts, threaded views, the Superhuman-y stuff. Only if it earns its place.

### What's load-bearing vs nice-to-have

If energy or time runs thin and the project needs to be pruned to its essential shape, this is the map.

**Load-bearing — these phases *are* the thesis. Without any one of them the project is not what §1 claims:**
- **Phase 1 + 2** (receive and send PGP mail in the browser). Obvious.
- **Phase 3** (TLS). Without it, the login challenge/response travels in plaintext, session cookies are insecure, and the server cannot be safely exposed to the internet. Not optional.
- **Phase 4** (custom domains). Without it, leaving an instance forces an address change, and "deliberately replaceable" collapses into marketing.
- **Phase 5** (operator UX). Without it, "one competent person can run an instance" is false in practice.
- **Phase 7** (migration). Without it, custom domains are just custom domains, not a portable identity story.
- **Standards discipline running through all phases.** SMTP-compatible delivery, exportable OpenPGP keys, WKD-published public keys, standard RFC 5322 messages. Without these, "you can leave and take your identity with you" is a slogan.

**Nice-to-have — defer freely:**
- Phase 6 polish items (client-side search index, chunked attachments). The product works without these.
- Phase 5 niceties beyond the example compose file, the bundled scripts, and the metrics endpoint. Nice-to-haves like Grafana dashboard JSON, fancier scripts, or pretty-printed CLI output are all defer-able.
- All of Phase 8 (Autocrypt, smarthost, hardware keys, DMARC reports, key rotation tooling).
- All of Phase 9+.

**Phases 0–7 total roughly 28–41 engineer-weeks of focused work.** On a side-project cadence that's whatever it is. The thing that matters is the order of the dependencies, not the calendar.

## 9. Hard problems we will hit (be aware now)

The hard work in this project is operational, not cryptographic. The crypto is solved (we use OpenPGP via mature libraries). These are the actual challenges:

1. **Deliverability.** This is *the* problem that kills self-hosted email today. Even with perfect DKIM/SPF/DMARC, a fresh IP gets junked by Gmail for weeks or months. We can mitigate (good DNS defaults, IP warming guidance, optional smarthost integration in Phase 7 — either a commercial relay like AWS SES/Postmark, or another rookery instance acting as a *relay rookery*; both are the same `[smtp.smarthost]` config block per §11.10), but we cannot fully solve it. **The honesty pointer:** this caveat must be in the README, not just in §9 of this plan. The first thing a prospective operator reads should be "your outbound mail to Gmail will be unreliable for weeks; here's why; here's what you can do (warm the IP slowly, pay a commercial relay, or arrange to send through a relay rookery in Phase 7)." Hiding it inside a 400-line plan is a trap.
2. **Spam filtering that works out of the box.** Bundling rspamd is the easy part; tuning it so it doesn't reject legitimate mail or accept obvious spam, without per-operator tweaking, is hard. Plan for this to be ongoing work.
3. **Outbound spam abuse.** If anyone can register on your instance, you become a spam source. Default to invite-only (§11.8); per-user and per-instance outbound rate limits (§11.4) land in Phase 2; abuse-relevant metrics (per-user volume, bounce rate, recent rejection codes) land in Phase 5 as Prometheus metrics that operators can alert on or graph in Grafana — we don't ship a dashboard ourselves (§11.8).
4. **Key discovery & TOFU.** WKD relies on the recipient's domain serving the right key. Domain operator (or anyone with TLS for that domain) can MITM first-contact. Auto-attached keys on inbound mail have the same trust property. Long-term mitigations: fingerprint verification UX, key transparency logs (out of scope for us), Autocrypt history.
5. **Migration without breakage.** "Easy migration" is the load-bearing feature for the trust-distribution claim. Getting it right (mailbox + key + identity + forwarding + correspondents updated) is finicky and easy to half-ass.
6. **Browser as a secure environment.** XSS = total compromise — the JS in the page holds the decrypted private key in memory. Every byte of JS we ship is part of the TCB. Strict CSP, no third-party scripts ever, SRI on every asset. The server-rendered + hand-written-JS architecture (P6, ADR-0002) is load-bearing here: an SPA framework would drag thousands of lines of vendor code, a build pipeline, and an XSS sink into every render path. This is *the* reason that decision is not negotiable.
7. **OpenPGP.js attachment performance.** Fine for messages, painful for big files. Chunked encryption is part of Phase 6; if it turns out attachments are needed earlier (e.g. for a real-user trial after Phase 3), we can pull it forward and accept the rework cost.
8. **No account recovery.** Hard rule, but we still need a *very* clear onboarding flow so users understand it. Otherwise it's just data loss with extra steps.
9. **Replying to plaintext threads.** If half a thread is plaintext on the server and half is E2E ciphertext, the UI must make the security state of every message obvious.
10. **Pseudonymity vs abuse signals.** Not logging connecting IPs (§5.4, §11.2) and accepting Tor without penalty (§11.4) is a deliberate property of the system, and it costs us something concrete: we lose the IP-based heuristics that conventional mail systems use to detect compromised accounts and brute-force login attempts. The defenses we keep are (a) invite-only registration by default (§11.8), (b) per-user and per-instance outbound rate limits (§11.4), (c) per-user bounce-rate and rejection-code metrics (Phase 5) that an operator can alert on. Public instances combining open registration, no IP logging, and Tor-tolerance take on real abuse risk; the README and the config-file comments must say so out loud. We are not going to recover the IP signal by giving up the pseudonymity property — that trade was the point.

## 10. Non-functional requirements

These are measurable targets. Each is paired with the honesty caveat that makes it actually achievable, because an NFR you can't hit is just a lie with a number on it.

- **Time-to-instance:** under **30 minutes of active configuration time** for a competent Linux user with a domain, on a properly-provisioned VPS. The flow being measured is the one in §5.1: clone the repo, `rookery init --domain <yours> --email <yours> --name <yours>` (or interactive equivalent), `sudo rookery install`, `systemctl enable --now rookery`, paste DNS records, `rookery invite create`, complete the user-signup flow. *Excluded from this budget, because they are outside our control:* DNS propagation, reverse-DNS (PTR) turnaround at the VPS provider (often a support-ticket process — documented in §5.1), Let's Encrypt rate-limit cooldowns if the operator has previously burned attempts on the same hostname. Honestly measured by running through the README on a clean VPS and recording the steps; if the steps take longer than budget, the README or the dispatcher is the bug, not the budget.
- **Resource footprint:** a working single-user instance fits comfortably on a **2 GB RAM** VPS (1 vCPU, 25 GB disk) with rspamd + Redis enabled and ClamAV disabled by default. The popular "$5 VPS" target hits this on most providers (Hetzner CX22, OVH, etc.); the older 1 GB tier is *technically* runnable but leaves no headroom and will OOM under sustained spam load. We document the realistic minimum rather than the marketing minimum. ClamAV is opt-in; enabling it adds ~1 GB RAM.
- **Deliverability — configuration score:** an instance brought up with the example `compose.yaml` and `rookery.toml` passes **all DNS/auth configuration checks** (SPF, DKIM, DMARC, MTA-STS, TLS-RPT, PTR, valid TLS chains) on first try, once the operator has published the DNS records the server logs at startup. The server's own preflight checker is the source of truth for this NFR; the project ships a scripted, repo-local test that runs the preflight against a controlled environment. Anyone with `docker` installed can run it; whoever maintains a fork or tags a release is responsible for running it before releasing. The project does not depend on a hosted CI provider to enforce this — see §7's Build row. This is the part of "deliverability" that is actually under our control.
- **Deliverability — reputation score:** **not an NFR, on purpose.** Per §9.1, the headline `mail-tester.com` score and inbox-placement at Gmail/Outlook depend on the *IP reputation of the VPS provider's range*, which we do not control. A fresh budget-VPS IP frequently starts in the 6–8 range on mail-tester regardless of configuration, and can land mail in spam at Gmail for weeks or months. The operator can run `mail-tester` themselves; we don't paper over the result with a gate. The docs explain why operators who need guaranteed deliverability use a smarthost (Phase 8) — either a commercial relay or a relay rookery, per §11.10 — or a clean dedicated IP.
- **Backup:** a single command produces a complete, encrypted, restorable backup. The project ships an automated restore-from-backup test as part of its in-repo test suite, runnable by anyone with `docker` installed (one command). Whoever tags a release runs it before tagging; whoever maintains a fork runs it on their own cadence. No hosted-CI dependency — see §7.
- **Migration:** a user **on a custom domain** can move between instances in under 15 minutes of active work, with their address unchanged (Phase 7 deliverable). A user on the instance's own domain cannot meet this NFR — they accept an address change, get a forwarding window, and we say so plainly in onboarding (§5.2a explicitly).
- **Browser-stack auditability:** the bundled JS that touches keys or plaintext is **under 200 KB unminified** and built reproducibly from a single `esbuild` invocation inside the Containerfile build, with no transitive npm postinstall scripts. SRI hashes are committed. Anyone can reproduce the exact bundle byte-for-byte from a clean checkout with only `docker` installed. This is the operational form of P11's "small browser" promise — it is reviewable in an afternoon.

## 11. Architectural decisions

This section captures every architectural choice that affects the shape of the product. Each decision is committed and gets its own ADR for the long-form rationale; the entries here are the summary plus enough detail to build against. Decisions are grouped by topic.

### 11.1 Cryptography and key handling

- **Private key handling: client-only custody.** The user's PGP private key is generated in the browser during signup without a passphrase. The server never holds the private key in any form, and — crucially — **never holds the passphrase or any derivative of it**. Authentication is a challenge/response signed by the private key (§11.2); the only authentication material on the server is the public key it already publishes via WKD. After registration the unlocked key is cached in `localStorage` (AES-GCM wrapped, cleared on logout, persists across page navigations and browser restarts within the login session); the user is immediately redirected to settings where they set a passphrase and export the recovery `.asc` file. From settings the user can re-export the recovery file with a new passphrase at any time (OpenPGP.js's built-in s2k, RFC 9580). Every subsequent login on any device requires importing the recovery file alongside the passphrase — there is no IndexedDB cache between sessions. Only the public key is uploaded — the server needs it for WKD publishing and for auto-attaching to outbound mail. *Why this over a server-side encrypted blob:* (a) the server is not a centralised brute-force target — an attacker who compromises the server walks away with public keys, mail content, and metadata, but not private-key material or password hashes that could be cracked offline; (b) the tampered-blob attack (server hands the client a substituted encrypted private key on login) is removed from the threat model entirely; (c) it aligns the storage model with what "the user owns their key" actually means — the user holds their key the way they hold their `gpg` private key on their own machine; (d) neither the passphrase alone nor the recovery file alone is sufficient to log in — an attacker needs both, which is a strictly stronger property than a password-only or file-only credential. The previously-considered "encrypted blob on the server" alternative is documented in ADR-0010 with the reasons it was rejected; the JavaScript-tampering vector remains the dominant residual risk and is mitigated by SRI, strict CSP, the no-third-party-scripts rule, and the small auditable browser-stack footprint (§10, P11). ADR-0010.
- **OpenPGP key defaults.** Curve25519 — ed25519 for signing, cv25519 for encryption. RSA-4096 supported only as legacy import; we do not generate RSA keys. ADR-0011.
- **Key-rotation attestation protocol.** Shape committed (§11.10, ADR-0028): when the user rotates their key, attestations signed by the *outgoing* key — covering `(old fp, new fp, monotonic counter, timestamp)` — travel as headers on outbound mail for a 90-day window. Receiving clients verify against the cached old key and silently update; lost-key rotations fall back to TOFU. Wire format and exact header layout still need a written ADR before Phase 7 code lands.
- **Identity model: key-as-identity, address-as-attribute.** The user's identity is their long-lived OpenPGP key fingerprint. Addresses are mutable attributes of an identity — a user can hold one or many addresses, and addresses can be added, removed, or migrated without breaking the identity. The export format and migration flow are designed around this. ADR-0014.

### 11.2 Authentication and session model

- **Authentication: challenge/response with the private key.** The server holds no passphrase hash and no encrypted private key — the only credential on the server is the user's public key (already published via WKD). Login works as follows: the JS prompts for the passphrase and the recovery `.asc` file, unlocks the private key locally, then performs a challenge/response — the server issues a nonce, the client signs it with the unlocked key, and the server verifies the signature against the stored public key. On success the server issues a session cookie. The unlocked key is cached in `localStorage` (AES-256-GCM wrapped, cleared on logout, shared across all tabs and browser restarts). Encrypted messages auto-decrypt across all tabs with no additional prompts. If the session key disappears from `localStorage` while the session cookie is still valid (e.g. `localStorage` cleared manually), the read page redirects to `/logout`. The passphrase encrypts the PGP key locally (OpenPGP.js s2k, RFC 9580) and never leaves the browser. The recovery file can be re-exported at any time from settings. Re-exporting it with a new passphrase is a passphrase change — there is no server-side state to update. **Security properties:** (1) neither the passphrase alone nor the recovery file alone is sufficient to authenticate — both are required; (2) a full server breach leaks no material that would allow an attacker to log in as any user; (3) passphrase rotation requires no server interaction and leaves no audit trail on the server, consistent with the pseudonymity property. ADR-0015.
- **Sessions.** Cookie-based, server-side session store (Postgres). HttpOnly, Secure, SameSite=Lax. Sliding expiry only: a session expires after `session_expiry_days` days of inactivity (default 7); there is no hard expiry ceiling. "Remember me" is implicit (sliding window) — there is no separate long-lived-token flow. Logout invalidates the session row server-side; concurrent sessions are allowed and listed in account settings **by last-seen timestamp only** — neither the IP nor the user agent is recorded, in line with the pseudonymity-by-default property in §1 and §4. Operators who explicitly enable IP logging at the instance level (a config-file flag, off by default, §5.4) get IP/UA columns surfaced in the same settings page; users on such an instance see exactly what is being stored about them. ADR-0015.
- **2FA by design, not by bolt-on.** The login flow is inherently two-factor: something you know (the passphrase) and something you have (the recovery file). A stolen passphrase alone cannot authenticate — there is no signed challenge without the file. A stolen file alone cannot authenticate — the key stays locked without the passphrase. This is a strictly stronger property than TOTP, which protects only the account shell while doing nothing for message confidentiality; here both factors gate the private key itself. TOTP is therefore not implemented and not planned — it would add complexity for no security gain. WebAuthn / hardware-key unlock is a Phase 8 candidate and would be a natural fit, replacing the passphrase factor with a hardware-bound one. SMS 2FA is ruled out, consistent with §5.4's "no phone number." ADR-0015.
- **CSRF.** Standard double-submit cookie or per-request token; not deciding the exact mechanism here, but every state-changing endpoint requires it. The HTTP API consumed by `partials.js` follows the same rule. ADR-0015.
- **Content Security Policy.** Strict, by default: no inline scripts, no inline styles, no third-party origins, `frame-ancestors 'none'`. The crypto pages additionally serve a stricter policy that allows only the pinned OpenPGP.js bundle (via SRI) and any WASM blobs OpenPGP.js loads internally — nothing else. Exact directives live in the implementation, not this plan. ADR-0016.

### 11.3 Addresses, aliases, multiple identities

- **Multiple addresses per user account.** A single user account / single PGP key can be associated with one or many addresses. Example: Alice has `alice@personal.example`, `alice@work.example`, and `a@a.li` — all bound to the same account, the same inbox, the same PGP key. Each address can be on the instance's primary domain or on any verified custom domain the user (or operator) controls. The user picks a default From address; other addresses are selectable per-message in the compose page. ADR-0017.
- **Plus-addressing.** `alice+anything@domain` routes to `alice@domain`. Standard RFC 5233 sub-addressing. No configuration needed; works for every address by default. Users can filter on the tag in the local part for their own organization (filtering itself is Phase 8+). ADR-0017.
- **Address aliases (non-plus).** Independent aliases like `support@domain` → `alice@domain` are supported. Per-user, configurable by the user in account settings; operator-configurable at the domain level via `psql` for things like `postmaster@` and `abuse@`. Aliases share the inbox, the key, and the identity of their target user. ADR-0017.
- **Catch-all on custom domains.** `*@alice.com → alice` is supported as an opt-in per-domain setting. Off by default (catch-alls attract spam); when enabled, a per-domain rate-limit and an obvious indicator in the inbox row ("via catch-all: `random-thing@alice.com`") let the user manage the noise. The catch-all routes to one user — there is no "round-robin to admins" feature in v1. ADR-0017.
- **Reserved local-parts.** Every domain managed by an instance reserves `postmaster@`, `abuse@`, `hostmaster@`, and `webmaster@` as required/conventional addresses. These are auto-created and route to the operator's user account (or to a configured fallback address) on instance setup and on every custom-domain verification. The operator cannot disable them; they're RFC-required and DMARC-aggregate-report-required. ADR-0018.

### 11.4 SMTP listener and transport policy

- **Ports.** 25 (inbound MX), 465 (submission, implicit TLS), 587 (submission, STARTTLS). Plain port 25 submission is not offered — the instance does not relay for arbitrary clients. ADR-0019.
- **Authentication on submission ports.** Required, always. **Open design question:** the web-UI authentication model (PGP challenge/response, no passphrase hash on the server) does not map directly onto SMTP SASL, which expects a stored verifier or a shared secret. Options are: (a) a separate app-password per user stored as a hash specifically for SMTP, (b) deferring SMTP submission entirely until a defined third-party client story exists, or (c) restricting SMTP submission to web-UI-initiated sends only (no external MUA support). This must be resolved before Phase 2 ships the submission ports; it is an explicit open item, not a decided question. The "server holds no passphrase hash" security property applies to web-UI login; SMTP SASL is a separate credential path that needs its own ADR.
- **Inbound STARTTLS.** Advertised and preferred; we accept unencrypted SMTP on port 25 because the rest of the internet still sends some of it, but MTA-STS is published for all our domains so well-behaved senders use TLS. TLS-RPT collects reports.
- **Outbound TLS.** Opportunistic by default (try STARTTLS, fall back); strict for destinations with valid MTA-STS policies (refuse to deliver if TLS fails). Configurable per-instance.
- **Mail size limit.** 25 MB default for both inbound and outbound, configurable per-instance up to 50 MB. Larger gets a `552` rejection. We document that PGP overhead inflates messages by ~33% (base64) and to size accordingly. ADR-0019.
- **Outbound bounce policy.** Standard SMTP retry schedule: deferred messages retried with exponential backoff for 5 days, then bounced to the sender with a delivery-status notification. Hard failures (5xx) bounce immediately. The user sees bounced messages in a "Bounced" view (a virtual folder, see §11.5).
- **Inbound bounce / DSN handling.** Bounces to our users land in their inbox like any other mail, with an obvious "delivery failure" badge so the UI can render the original recipient and reason clearly.
- **IPv6.** Listen on both v4 and v6 if available. Send from v6 if the destination has AAAA records and rDNS for our v6 IP is set; otherwise fall back to v4. The README documents v6 rDNS as part of the operator checklist (and many providers' v6 rDNS UX is worse than v4's, which we say).
- **Rate limits on outbound.** Per-user: 200 messages per hour, 1,000 per day (default; configurable per-instance). Per-instance: 5,000 messages per hour against any single destination domain. These exist to limit damage from a compromised account; legitimate use never approaches them. ADR-0020.
- **Tor and onion reachability.** Connections to the web UI and to submission ports (465, 587) from Tor exit nodes are accepted without special treatment — no CAPTCHA, no rate-limit penalty, no exit-list blocking. The instance can optionally be reached via a v3 onion address for the web UI; the operator publishes the onion alongside the clearnet hostname and users can bookmark either. Documented in the operator runbook. **Outbound SMTP delivery is clearnet only.** There is no anonymity benefit to relaying outbound SMTP over Tor — the recipient and their mail server are on the clearnet, the `Received:` chain still names the originating instance, and the destination MX will frequently reject Tor-exit traffic anyway. We do not pretend otherwise. ADR-0019.

### 11.5 Mailbox model

- **Inbox-only in v1, with virtual views.** The mailbox is a flat list of messages with attributes (read/unread, starred, in-reply-to chain, has-attachment, security-state). The UI surfaces a small number of *virtual views* over that list: **Inbox** (everything), **Sent** (messages this user sent), **Drafts** (composed but not sent), **Bounced** (delivery failures), **Trash** (soft-deleted, see deletion below). There are no user-created folders or labels in v1. Threads are derived from `In-Reply-To`/`References` on the fly. ADR-0021.
- **Read state.** Per-message boolean, server-side. We deliberately do not send read receipts to senders — §5.4's "no read receipts."
- **Soft delete.** Deleting a message moves it to Trash. Trash is auto-purged after 30 days (configurable per-user, 0 = immediate hard delete). Hard delete from Trash is irreversible.
- **Per-user storage quota.** Default 5 GB, instance-wide default set in `rookery.toml`, per-user overrides set by the operator via `psql` (`UPDATE users SET quota_bytes = ... WHERE primary_address = ...`). When 90% full the user gets a banner; at 100%, inbound mail to that user is rejected at SMTP time with a `452 Mailbox full` and the sender gets a normal bounce. We never silently drop mail. ADR-0021.
- **Search.** Phase 6: client-side full-text index, decrypted in the browser, never sent to the server. The server provides only the message ciphertexts and metadata.

### 11.6 Storage

- **Database.** PostgreSQL. SQLite was previously listed as "optional for single-user installs"; we drop that. Postgres on a single machine is operationally simple enough that maintaining two storage backends is not worth it. Single-user instances get the same Postgres container; resource footprint (§10) is still met. ADR-0022.
- **Migrations.** `golang-migrate`. Both `golang-migrate` and `goose` are fine; we pick `golang-migrate` and stop debating. ADR-0022.
- **Blob storage.** Raw RFC 5322 messages (encrypted or not, as received) are stored on the filesystem with content-addressed paths (`/blobs/sha256/ab/cd/abcdef...eml`). Postgres holds metadata and references to the blob. v1 is filesystem-only; an S3-compatible interface is a Phase 8+ option if anyone wants it. ADR-0022.
- **Server-side encryption at rest.** Out of scope for the message store — PGP-encrypted messages are already encrypted; plaintext messages received from the outside world are stored as received (this matches every other mail server). DKIM private keys, session secrets, and ACME account keys *are* encrypted at rest with a server master key, which lives in an env var / Docker secret loaded at startup and never persisted to disk by the server itself. **User PGP private keys are not in this list because they are not on the server at all** (§11.1). Losing the master key bricks the instance for the server-side secrets it protects (DKIM, sessions, ACME) but does not put user mailboxes at risk in the way a traditional webmail compromise would. Operators back the master key up. ADR-0023.

### 11.7 DNS, TLS, and WKD

- **WKD method.** **Advanced method only** (`openpgpkey.<domain>/.well-known/openpgpkey/<domain>/...`). The direct method on the apex makes operating a separate web service on the apex domain harder for users with their own websites. The advanced method's CNAME-to-our-host approach is what makes per-user custom domains tractable. ADR-0024.
- **ACME challenge type.** HTTP-01 for the instance's primary domain; HTTP-01 for `mta-sts.<custom-domain>` and `openpgpkey.<custom-domain>` (both reached via CNAME to our infrastructure, so HTTP-01 works without registrar API access). We do not require DNS-01, which would force operators to integrate with registrar APIs. ADR-0024.
- **MTA-STS policy mode.** `enforce` once a domain is fully verified. `testing` mode is available as a per-domain override for the first 48 hours after activation; the UI explains the trade-off (strict = inbound mail fails if our TLS breaks; testing = TLS failures only get reported). ADR-0024.
- **DKIM key strength and rotation.** Ed25519 DKIM signatures (RFC 8463) primary, RSA-2048 fallback for receivers that don't grok ed25519 (still common). Each domain has both, published under distinct selectors. Manual rotation tooling in Phase 8. ADR-0024.

### 11.8 Registration, abuse, and the operator model

- **One role: user. There is no in-app admin.** The system has a single application-level role — *user*. The **operator** is whoever has shell access to the VPS; they have root and they have `psql`, and that is enough. There is no admin web UI, no in-app admin login, no admin role flag in the database. Anything an admin "would have done" is either (a) a user-facing action the user does themselves in the web UI, or (b) something the operator does on the box via documented commands. This is a hard simplification and a real principle (P10). ADR-0008.
- **Registration.** Invite-only, always. There is no open-registration mode and no config knob to enable one — the abuse risk on a pseudonymous, IP-log-free instance is not a trade-off worth offering. Invite tokens are rows in an `invites` table; the operator creates them via `rookery invite create` (a thin `psql INSERT` wrapper, ADR-0033). User-issued invites are a Phase 8+ option; not in v1. ADR-0008.
- **Custom-domain registration.** Users add their own custom domains via the web UI (§5.2b), always. There is no operator-managed-only mode and no per-instance policy toggle. The server generates DKIM keypairs, provisions ACME, and logs DNS records when the user completes DNS verification through the UI. Operators can also insert domain rows directly via `psql` for advanced cases (e.g. pre-registering a domain before inviting the user), but the web UI flow is the supported path.
- **Outbound spam abuse.** Per-user and per-instance rate limits (§11.4) are enforced unconditionally. Beyond that, anomaly detection lives in **Prometheus metrics** (outbound volume per user, bounce rate, recent rejection codes) and **structured logs** — the operator can `grep`, alert via their existing Alertmanager rules, or write small queries against the metrics. There is no "anomaly dashboard" page we ship; if the operator wants one, they wire up Grafana against the metrics endpoint. The point is: the operator already has these tools; we don't reinvent them.
- **Account suspension.** Suspending a user is a flag on the user row (`suspended_at`). Set the column via `psql` (or `./scripts/suspend-user.sh`); the server checks the flag on every inbound and outbound operation. Suspended accounts cannot send or receive (inbound rejected at SMTP time with `550 5.7.1 Account suspended`, producing a normal bounce; outbound attempts fail with a clear error in the user's web UI). Suspension is reversible by clearing the flag. ADR-0025.
- **First-user bootstrapping.** On a fresh instance, the first user account must come from somewhere. The operator creates it with `rookery invite create` (which writes an invite row to the DB and prints the invite URL to stdout), then visits that URL in their browser like any other invited user. No special bootstrap dance, no `is_admin` column to set. This is the same flow every subsequent user takes; the first user just happens to also be the operator. ADR-0008.

### 11.9 Account deletion and data retention

- **User-initiated account deletion.** A user can delete their own account from settings. The flow requires the passphrase **and a proof-of-key-control** (the client signs a server-issued nonce with the user's private key, which requires unlocking it with the passphrase — it works under the client-only-key model since the server has no encrypted blob to test the passphrase against), plus a typed-out confirmation, plus a 7-day grace period during which the account is suspended but not yet purged. During grace the user can cancel; the account also goes "hold" if there are unread messages from the past 24 hours (a soft tripwire to avoid impulsive deletion). ADR-0026.
- **What deletion removes.** All messages (encrypted blobs and metadata), the user's stored **public** key, all addresses and aliases owned by the user, the user's known-keys cache, all DKIM keys for domains exclusively owned by this user (if no other user uses the domain), all session rows, and the user record itself. There is no encrypted private-key blob to remove — the server never had one (§11.1). Backups created before deletion will still contain the user's server-side data until they age out; we document this. The user's *own* recovery file is theirs to deal with; deleting the account does not reach into their devices. ADR-0026.
- **What deletion does not remove.** Bounced/DSN copies of mail this user sent that ended up in *other users'* inboxes are not chased down — they are the recipients' mail. Public-key copies that have been auto-attached to past outbound messages are obviously in the wild forever; that is the nature of having published a key, and we say so.
- **Operator-initiated deletion.** The operator can delete a user (e.g. for abuse) via `./scripts/delete-user.sh <address>`, which writes a tombstone row and starts the same purge sequence as user-initiated deletion (minus the grace period — the operator made an explicit choice). A `DELETED` tombstone with the timestamp, the operator's hostname/user, and a reason string is retained for audit. ADR-0026.
- **Domain deletion.** Removing a custom domain from the instance requires no users to be using it for any address. If users are using it, they must remove or migrate those addresses first. We do not orphan-delete addresses behind a user's back. ADR-0026.
- **Data retention defaults.** No automatic purge of any mail beyond Trash (§11.5). Sent mail, received mail, drafts: all retained until the user deletes them or the account is deleted. This is policy, not technical limit — operators with regulatory needs can change it. We document it explicitly. ADR-0026.
- **GDPR / data-subject requests.** Out of scope to provide a tooling answer for every regulation, but the architecture supports the basics: export (Phase 6 mailbox-export covers right-to-data-portability), deletion (above covers right-to-erasure). Operators in regulated jurisdictions are responsible for their own compliance; we document what the software does and doesn't do. ADR-0026.

### 11.10 Key rotation, backup, smarthost — architectural commitments

Three items were "genuinely open" earlier in the planning process. The *shapes* are now committed; the wire formats and exact specifications still need their own ADRs before the relevant phases.

**Key-rotation attestation protocol** [ADR-0028, needed before Phase 7]

When a user rotates their PGP key (planned rotation, or because the old one was compromised), their past correspondents need to learn the new key automatically — without falling back to "manually call your friend and read fingerprints" and without silently accepting an attacker's swap. The committed shape:

- Attestations are **message headers**, signed by the *outgoing* (old) key, attached to outbound mail for a configurable window after rotation (default 90 days).
- An attestation covers `(old fingerprint, new fingerprint, monotonic counter, timestamp)`. The counter increments per rotation and prevents replay of older attestations.
- Receiving clients verify the attestation against the cached old key, update their known-keys cache to the new key, and surface a small unobtrusive notice ("This contact rotated their key on date X, verified by their previous key"). No yes/no prompt — verified means trusted.
- **Lost-key fallback.** If the user has lost the old key entirely (no signature possible), the rotation falls back to TOFU: correspondents see the same "first seen" yellow badge as for a brand-new contact. We do not try to invent a recovery path; §11.1 already commits to single-device, no-recovery, and key rotation inherits that property.
- **Out of scope for the shape (handled in the ADR):** wire format and exact header name; behaviour under concurrent rotations on different devices (mostly prevented by single-device design, but the ADR should specify); whether attestations are also published via WKD (probable answer: no — WKD serves the *current* key only, attestations belong in-band with messages).

The ADR will be drafted and reviewed before Phase 7 code lands. This is real cryptographic protocol design and the shape commits us to "in-band, signed by old key, monotonic" but the wire-level details deserve their own document.

**Backup format and encryption** [ADR-0029, needed before Phase 6]

The "single command produces an encrypted, restorable backup" NFR (§10) is now spec'd at the shape level:

- **Format:** a single `.tar.zst` archive containing (a) `pg_dump --format=custom` of the `rookery` database, (b) the content-addressed blob storage tree, (c) a small `manifest.json` with schema version, rookery version, and a list of included paths. **The backup does not — and cannot — contain user PGP private keys**: those live in users' browsers and recovery files (§11.1), not on the server. Restoring from a backup gives users back their mailboxes, addresses, and metadata; users still need their recovery files to actually decrypt past mail. We document this clearly so operators do not develop a false sense of having a complete user-data backup. A "complete" backup from any user's perspective is *the server backup plus that user's own recovery file* — and the recovery file is their responsibility, by design.
- **Encryption:** the archive is encrypted with **age** (https://age-encryption.org/) to an operator-provided age recipient public key. The recipient public key is configured in `rookery.toml`; the corresponding age identity (private key) is held *by the operator*, off the server. This survives loss of the server master key — and the server master key being lost is precisely when a backup matters.
- **Why age over GPG:** smaller dependency surface, simpler key format, modern crypto defaults, and the backup recipient is unambiguously distinct from a PGP user-identity key (which would invite confusion). The rest of the project uses OpenPGP because that is what email and PGP/MIME require for interop; backups are a local disaster-recovery artifact and have no such constraint.
- **Why not encrypt with the server master key:** because the master key is on the server, and losing the server is the disaster the backup must survive.
- **Bundled scripts:** `./scripts/backup.sh` produces a timestamped archive on stdout (or to a path); `./scripts/restore.sh` consumes it on a fresh instance. Both are thin wrappers (`pg_dump | age -r ... | zstd > backup.tar.zst.age`).
- **Automated verification:** the test harness generates a throwaway age keypair, runs a backup against a seeded instance, spins up a fresh instance, restores, and asserts that key invariants hold (users, messages, addresses, blobs all present and decryptable). This is the "automated restore-from-backup test" the NFR commits to. It lives in the repo as a scripted, container-driven test that anyone with `docker` installed can run; release tagging requires running it. No dependence on a hosted CI provider, in keeping with §7.
- **Out of scope for the shape (handled in the ADR):** archive layout details, exact pg_dump options, blob deduplication strategy for incremental backups (v1 is full-backup only; incremental is Phase 8 if anyone wants it).

**Smarthost integration shape** [ADR-0030, Phase 8]

Smarthosts are an optional outbound relay that operators can opt into when their VPS's IP reputation makes direct delivery unreliable (§9.1). Two flavours of smarthost are supported under the same configuration block and the same wire shape, because to rookery they are both "a remote SMTP submission endpoint we trust to relay our signed mail":

1. **Commercial relay** — AWS SES, Postmark, Mailgun, etc. The expected configuration for operators who need guaranteed inbox placement at Gmail/Outlook from day one and are happy to pay a vendor for it.
2. **Relay rookery** — another rookery instance, with a delivery history on its IP, acting as the smarthost for an instance whose IP does not have one yet. The mechanism is the same SMTP submission session; the smarthost just happens to be running rookery itself. **This is not a federation protocol.** No directory, no auto-discovery, no DHT, no new wire protocol — the downstream operator knows about the relay rookery because its operator told them, the same way an operator gets a Postmark API key. Two rookery instances relay between each other exactly the way any two mail systems do: SMTP submission on 465/587, with credentials provisioned out of band.

The committed shape, identical for both flavours:

- **Opt-in, off by default.** A `rookery.toml` block (`[smtp.smarthost]`) is absent by default and the server delivers mail directly. Setting `enabled = true` plus host/port/username — and providing `ROOKERY_SMTP_RELAY_PASSWORD` as an env var — switches the server to relay mode. The same block configures a commercial relay or a relay rookery; the only thing that varies is the hostname and the credential.
- **Per-instance scope.** One smarthost configuration applies to all outbound from the instance. Not per-domain, not per-user. If an operator needs different smarthosts for different domains, they can run multiple instances, or — more realistically — wait until v1+ proves the demand. Per-instance keeps the config small and the DKIM story consistent.
- **DKIM signs first, then handoff.** rookery signs every outbound message with the user's domain DKIM key *before* handing it to the smarthost. The smarthost is opaque transport. This means: (a) the From-domain DKIM signature is what receivers verify, so DMARC alignment works without published smarthost keys; (b) operators can swap smarthost providers — *including swapping a commercial relay for a relay rookery, or the reverse* — without anything about message authentication changing; (c) the smarthost cannot impersonate the user cryptographically, only relay what we've already signed. This last property is what makes the relay-rookery variant a viable trust escalation in the first place: a relay rookery sees the same thing any SMTP hop sees, no more.
- **What the smarthost sees:** the message envelope (From, To, Subject, Date, all standard headers) and the message body. For PGP-encrypted mail, the body is the encrypted blob — useful privacy property whether the smarthost is Postmark or a relay rookery. For non-PGP outbound (which exists: replies to plaintext senders, mail to addresses without published keys), the smarthost sees plaintext, same as any other SMTP hop. We document this clearly so operators choosing a smarthost choose one they trust.
- **Mutual opt-in for the relay-rookery case.** An instance does not become a relay rookery for another instance implicitly. The relay-rookery operator configures their instance to accept submissions from a specific authenticated remote operator (a row in a `relay_clients` table, provisioned by `psql` or a future `./scripts/new-relay-client.sh`), and the downstream operator configures their instance to relay through that hostname with the issued credential. There is no rookery-side endpoint that auto-vends relay credentials, and there is no rendezvous service we run. The trust is one bilateral agreement at a time, the same way every other inter-administrator relay trust on the open internet works.
- **Abuse exposure is real, named honestly.** A relay rookery inherits its downstream's outbound reputation: if the downstream instance's users send spam, the relay rookery's IP gets dirty. This is identical to the risk a commercial smarthost runs, except commercial smarthosts have abuse teams, KYC, and lawyers, and a small rookery operator does not. Operators considering acting as a relay rookery should (a) only do so for instances whose operators they know, (b) apply the same per-user and per-instance outbound rate limits (§11.4) to relayed traffic that they apply to local traffic, and (c) expect that revoking a downstream's credential is the only abuse remediation we ship in v1. The README and operator runbook say so out loud.
- **What this does *not* claim.** It does not claim that "the deliverability problem gets distributed across many shoulders as the network grows" — that framing is aspirational. In practice there will be one or a small handful of relay rookeries at any time, those operators will absorb most of the load and most of the risk, and that is fine because the alternative (every new operator buying SES credits) is worse only marginally. The mechanism creates an option, not an automatic equilibrium.
- **Out of scope for the shape (handled in the ADR):** retry behaviour when the smarthost itself is down (probably: queue locally and retry, same as direct delivery, but with different timeouts); whether to support multiple smarthost providers as failover (probable answer: no in v1, yes in Phase 8+ if anyone asks); exact `rookery.toml` schema for the smarthost block; the shape of the `relay_clients` table and how a relay rookery enforces per-downstream rate limits.

**Still genuinely deferred:**

- *(none at present — the project name was the last remaining identity-level deferral and is settled, see the note at the top of this document.)*

### 11.11 Configuration model

The instance is configured via a **mix of environment variables (for secrets) and a config file (for everything else)**, mounted into the container.

- **Config file:** `rookery.toml`, mounted at `/etc/rookery/rookery.toml`. Contains the primary domain, Let's Encrypt contact email, the per-instance policy toggles (open registration, custom-domain self-service), quota defaults, rate-limit overrides, paths to data directories, log verbosity. The file is short and heavily commented. Example file lives in the repo and is the canonical schema reference. Changes to the file require a server restart in v1; hot-reload is not in scope. ADR-0027.
- **Environment variables (secrets only):**
  - `ROOKERY_DB_PASSWORD` — Postgres password. The connection URL is not configurable — rookery always connects to `postgres://rookery:<password>@postgres:5432/rookery`. Only the password varies, and it is always generated automatically by `secrets-init` on first `compose up`.
  - `ROOKERY_MASTER_KEY` — server master key (§11.6). Generated on first run if absent and printed to the log with a one-time "back this up" notice; on subsequent runs the operator provides it.
  - `ROOKERY_SESSION_KEY` — HMAC key for session cookies. Same generate-on-first-run pattern.
  - `ROOKERY_SMTP_RELAY_PASSWORD` — optional, only if a Phase 8 smarthost is configured.
- **Why this split:** secrets stay out of the config file so it's safe to commit a sanitized example, version-control the config alongside the compose file, etc. Everything that isn't a secret is in the config file because env vars don't scale well past about a dozen settings.
- **What's deliberately not configurable in v1:** the SMTP port set (always 25/465/587), the WKD method (always advanced), the database engine (always Postgres). Locking these down keeps the config schema small.

### 11.12 Operator runbook

The shape of "the operator does ops from the shell" is concrete: a single executable, `rookery`, at the repo root, that dispatches to subcommands. The dispatcher is a POSIX shell script (no Go binary, no build step); it wraps `docker compose`, `psql`, and a small amount of `curl` / `openssl`. Operators inspect it with `cat rookery` before running anything novel. ADR-0033 is the long-form rationale; the v1 subcommand surface is committed below.

**v1 subcommands (Phases 0–3, shipped now):**

| Subcommand | What it does | Implementation shape |
|---|---|---|
| `rookery init [--domain X] [--email Y] [--name N] [--user U]` | User-local bootstrap from a clone. Generates `rookery.toml` if missing (flags or interactive prompts fill `domain`, `contact_email`, `instance_name`); generates `.env` (random secrets) if missing; generates `Caddyfile` if missing; stages `./rookery.service` with `User=` from `--user` (default: `whoami`) if missing. Never overwrites; safe to re-run. No `sudo`. | `openssl rand`, a few `sed`s, a `printf` |
| `sudo rookery install` | Promote a checkout into a system service: `install -m644 ./rookery.service /etc/systemd/system/` + `systemctl daemon-reload`. Does **not** enable or start. The only sudo command in the dispatcher. | `install`, `systemctl daemon-reload` |
| `rookery start [--prod]` | Bring the stack up. Defaults to **dev** (no Caddy, mailpit on 1025/8025, port 8080); `--prod` enables Caddy on 80/443. Errors with a hint if `rookery init` has not been run. | `docker compose [--profile prod] up --build` |
| `rookery stop` | Stop the stack. | `docker compose down` |
| `rookery restart [--prod]` | `stop` then `start`. | — |
| `rookery update` | Upgrade in place. Does **not** restart. `--ff-only` fails loudly on a divergent local branch. | `git fetch && git pull --ff-only && docker compose build` |
| `rookery logs [service]` | Tail logs (default: rookery). | `docker compose logs -f <svc>` |
| `rookery ps` | Show running services. | `docker compose ps` |
| `rookery invite create [validity_days]` | Generate a new invite URL. Noun-verb form leaves room for `invite list` / `invite revoke` later. | `docker compose exec postgres psql -c "INSERT INTO invites ..."` + `printf` |
| `rookery send-mail [flags] <to> [from] [subject] [body]` | Inject a message into the dev stack (plaintext or PGP-encrypted via `--pubkey` / `--fetch-key`). Useful for smoke checks and manual reproduction, not just tests. | `curl` to port 25 (+ `gpg` in encrypted mode) |
| `rookery psql` | Drop into a `psql` shell. | `docker compose exec postgres psql -U rookery -d rookery` |
| `rookery test` | Run the Go test suite. | `docker compose --profile test run --rm test` |
| `rookery vet` | Run `go vet`. | `docker compose --profile lint run --rm lint` |
| `rookery exec <service> <cmd...>` | Escape hatch: `docker compose exec` against any service. | `docker compose exec ...` |
| `rookery compose <args...>` | Escape hatch: arbitrary `docker compose` invocation, skipping `init`-style side effects. | `exec docker compose "$@"` |
| `rookery help [subcommand]` | Usage. | — |

**v1 subcommands (Phase 5, planned):**

| Subcommand | What it does | Implementation shape |
|---|---|---|
| `rookery user suspend <address>` | Mark a user suspended | `psql -c "UPDATE users SET suspended_at = now() WHERE primary_address = ..."` |
| `rookery user unsuspend <address>` | Reverse the above | `psql -c "UPDATE users SET suspended_at = NULL WHERE ..."` |
| `rookery user delete <address> [reason]` | Operator-initiated deletion (§11.9) | calls a small server endpoint at `localhost:internal-port` that runs the same deletion logic the user flow would, or directly writes tombstone + triggers purge |
| `rookery dns print [domain]` | Print the DNS records required for a domain (defaults to primary) | reads from `domains` table, formats output |
| `rookery stats print` | Quick summary of recent outbound stats | a couple of `SELECT count(*) FROM messages WHERE ...` queries |
| `rookery master-key rotate` | Rotate the server master key | documented procedure: re-encrypt DKIM private keys, session secrets, and ACME account keys under the new master; replace env var; restart. (No user PGP private keys to re-encrypt — they are not on the server, §11.1.) |

Subcommand names in the Phase 5 row are illustrative — flat verbs (`suspend-user`, `print-dns`) are accepted where they read better. The noun-verb preference is documented in ADR-0033, not a hard rule. Phase 6 adds `rookery backup` / `rookery restore <path>` (ADR-0029). Phase 8 may add `rookery relay-client create` if the relay-rookery shape (ADR-0030) is built.

**Documented `psql` queries** (issued via `rookery psql`) for everything not covered by a subcommand. The deployment guide includes a "common operator tasks" section with copy-pasteable queries: list users, change a user's quota, find a message by ID, view the outbound queue, expire old sessions, etc. The point is *the data model is meant to be readable and writable by hand*; queries are not workarounds, they're the supported interface.

**Constraint this places on the data model:** every operator-meaningful state change must be expressible as a small set of row updates that preserve invariants. Adding a user requires inserting into one table; suspending requires updating one column; deleting requires marking a tombstone and letting the server's purge worker handle the rest. If we ever find ourselves writing "the operator should run these seven `INSERT`s in this order," that's a design smell and the schema needs flattening.

**Constraint this places on the dispatcher:** the same. Any subcommand whose body grows beyond ~30 lines of shell is a signal that the work either belongs in the Go server (so it has tests and a typed schema) or that the data model needs flattening. The dispatcher does not become a framework, does not grow plugins, and does not maintain its own state. It is a `case "$1"` plus a handful of small functions. Anyone reading the source should be able to understand any single subcommand in 30 seconds. ADR-0027, ADR-0033.

### 11.13 Spam filtering

Spam filtering in v1 is **rspamd with stock defaults**. The goal is "reasonable out-of-the-box behaviour for a small instance," not "Gmail-quality classification." Per §9.2 we are honest that good spam filtering is ongoing operational work, not a problem we solve in v1.

- **Spam filter:** rspamd, bundled in the deployment. ADR-0032.
- **Backing store:** Redis, bundled as a sidecar container (rspamd requires it for bayes, fuzzy, ratelimits, and several other modules). The compose file ships Redis alongside rookery and rspamd; operators don't see Redis as a separate operational concern.
- **Virus scanning:** ClamAV is **opt-in, off by default.** Per §10 RAM budget, enabling ClamAV adds ~1 GB; instances running on a 2 GB VPS cannot afford it. Operators with headroom flip a flag in `rookery.toml`.
- **Action thresholds:** rspamd's own defaults (`reject` ≥15, `add header` 6-15, `greylist` ~4-6, no-action below). These are well-tuned by the rspamd project and we don't second-guess them in v1.
- **Bayesian training: not in v1.** No "mark as spam" button in the inbox UI. No `learn_spam` / `learn_ham` feedback loop. Stock rspamd does plenty without bayes (header heuristics, RBLs, SPF/DKIM/DMARC alignment, URL reputation, neural network module on by default). Per-user bayes training, the "mark as spam" UX, and the resulting training pipeline are deliberately Phase 8+ work — they touch the inbox UI, the storage model, *and* the spam pipeline simultaneously, which is too much surface for v1.
- **Operator overrides.** The shipped rspamd config lives at `/etc/rspamd/local.d/` inside the container; operators who want to tune anything mount a volume over it. Documented in the operator runbook. The dispatcher does not include rspamd-tuning subcommands — that's outside our scope; the operator uses `rspamc` directly via the `rookery exec rspamd rspamc ...` escape hatch.
- **What this means for users in v1.** Spam goes to the **Trash** virtual view (§11.5), not a separate Spam folder — keeping the mailbox model flat. The `X-Spam-Status` header rspamd adds is preserved and visible in the message detail view, so curious users can see the score. Mail tagged `add header` (medium-confidence spam) lands in Inbox with a visible "possible spam" badge; mail tagged `reject` is rejected at SMTP time and never enters storage.
- **What this is *not*:** a long-term spam strategy. v1 ships rspamd and walks away. Phase 8+ revisits training, per-user models, the Spam folder vs Trash question, and the "mark as spam" UI as a coherent piece of work.

### 11.14 UI visual direction

The v1 UI is server-rendered HTML styled with a single hand-written stylesheet (§7). The visual direction is committed at the principle level here so that PRs, future contributors, and reviewers have a stable reference point and the UI does not drift towards consumer-webmail polish by accident. The lineage we target is **the techie-utility homepage** — `archlinux.org`, `voidlinux.org`, `man.archlinux.org`, `suckless.org` — pages that are dense with information, light on decoration, and read like well-laid-out documentation rather than marketing.

Concrete commitments:

- **Light, neutral palette, one muted accent.** Near-white background (not pure `#FFFFFF` — slightly off, like Arch's), near-black body text, a single low-saturation accent colour for links, headings, and the small handful of status indicators that need to stand out (encrypted-vs-plaintext badges, send-button state). No second accent. No gradients. No drop shadows. No glassmorphism.
- **No dark mode in v1.** A single, well-tuned light theme is more honest than two half-tuned themes. Dark mode is Phase 8+ if it earns its place; the audience overlap with people who run `redshift` / `f.lux` / OS-level inversion is high enough that we don't urgently need to ship our own. **Exception:** we use `prefers-color-scheme` only to set sensible system-cursor and form-control defaults; we do not produce a custom dark stylesheet.
- **System font stack, no webfonts.** A single `font-family` declaration along the lines of `system-ui, -apple-system, "Segoe UI", Roboto, sans-serif` for body text and `ui-monospace, "SF Mono", "Cascadia Mono", "JetBrains Mono", Menlo, monospace` for fingerprints, addresses, message bodies, and anything else that benefits from monospace. No webfont downloads — this saves a roundtrip, removes a third-party origin from the CSP (P11, ADR-0016), eliminates a class of FOUT/FOIT issues, and matches the audience's expectations: they already have good fonts on their system.
- **Hierarchy through type and rules, not colour or shadow.** Headings are heavier weight and slightly larger than body, not coloured boxes. Sections are separated by horizontal rules or generous whitespace, not card containers. Tables have thin borders, not zebra stripes. The page reads top-to-bottom as a document; nothing floats, nothing sticks (except a minimal top nav, if we have one at all — leaning towards "we don't").
- **No icons except where they carry information.** A lock icon next to "encrypted" carries information. A paperclip next to "attachments" carries information. Decorative envelope icons in headers do not. We use Unicode characters (●, →, ✓, ✗) before we use SVG sprites, and we use SVG sprites before we use icon fonts; we never use icon fonts (a webfont we explicitly forbade anyway).
- **No animation.** No fades, no slides, no skeleton loaders, no spinners-as-decoration. The one place a progress indicator is justified is decryption of a large attachment or upload of a large draft, and there a plain `<progress>` element is the right tool. Hover states change colour, not size.
- **Information density is moderate.** Not Hacker News, not Substack. The inbox list shows enough rows per screen to scan quickly; the read view leaves room for the body but does not pad it into another country. Whitespace exists to group, not to decorate.
- **Operational copy, no marketing prose.** Every visible string is informational. "Send" not "Send your message →." "Encrypted with Bob's key" not "Your message is safely on its way!" Error messages name the thing that went wrong and the next action. Empty-state copy says "no messages" and stops.
- **Plain links, not buttons, wherever it works.** Underlined accent-coloured text for navigation, anchor links, in-page actions. Buttons are reserved for state-changing form submits where the action is meaningfully a button — Send, Delete, Confirm. No pill-shaped button styling. The `<button>` element with default-ish browser styling, lightly normalized, is the target.
- **Forms look like forms.** Labels above inputs, inputs at full available width, no floating labels, no inline validation that hides what you typed. The signup flow, the compose page, and the settings pages all use the same form patterns.
- **The compose page and the read page are pages, not modals.** No overlay UIs, no slide-in panels, no modal dialogs except for hard-confirmation flows (account deletion, "send in plaintext anyway" acknowledgement) where blocking the rest of the UI is the point.
- **Mobile lays out vertically and stops trying.** Per P9 and §5.4, mobile is tolerated, not optimized. The single stylesheet uses a small number of `max-width` breakpoints to stop multi-column layouts from breaking on narrow viewports, and that's the entire mobile story. No touch-specific gestures, no thumb-zone optimization, no bottom navigation.
- **No JavaScript-driven layout.** Layout is CSS; `partials.js` swaps content into existing structural slots but does not compute positions, sizes, or visibility based on viewport. This keeps the page legible even when JS is disabled (where it is meaningful to be legible — see P11 / §6).

What this *doesn't* commit to:
- Exact accent colour, exact font sizes, exact spacing scale, exact heading weights. These are implementation details to be decided at coding time and refined in use; they are noise at the planning level. The principle is "Arch/Void style, hand-written, no framework" — the pixel-level realization is a coding-time call, not an ADR-level one.
- A complete component library, design tokens, a style guide document. The single stylesheet *is* the style guide; future contributors read it.
- A logo, an icon, a wordmark, a colour identity beyond the muted accent. These are marketing concerns and live with the project-name decision (§11.10 "Still genuinely deferred").

This subsection serves as the design-direction ADR-equivalent for the UI; an actual ADR is unnecessary because there is no architectural choice here to revisit, only an aesthetic commitment that the rest of the project's principles already imply.

### 11.15 Decisions deliberately not made here

A short list of things this section intentionally does not pin down, because they're implementation details that can be decided at coding time without rippling through the architecture:

- Exact CSP header strings.
- Exact CSRF token mechanism (double-submit vs SameSite-only vs synchronizer-token).
- Cookie names, session key lengths, etc.
- Specific Prometheus metric names.
- Exact log format.

These are noise at the planning level; the relevant principle is "follow current best practice, don't invent." If any of them turns out to be load-bearing for the threat model in a way we missed, we promote it to an ADR.

## 12. Repo layout (proposed)

```
cmd/rookery-server/        # the only binary: HTTP + SMTP + background workers
internal/smtp/             # inbound + outbound SMTP
internal/web/              # HTTP handlers, html/template rendering
internal/web/templates/    # *.gohtml files
internal/keydir/           # local key directory + WKD publishing + auto-attach helpers
internal/discovery/        # remote key discovery (WKD, keyservers)
internal/store/            # DB + blob storage
internal/auth/             # user auth, sessions, 2FA
internal/queue/            # outbound mail queue
internal/domains/          # custom-domain registration, DNS verification, drift checks
internal/acme/             # per-domain ACME (Let's Encrypt) for HTTPS, MTA-STS
internal/addresses/        # address routing, aliases, plus-addressing, catch-all
internal/lifecycle/        # account deletion, backup, export/import
web/static/                # hand-written CSS, partials.js (hand-written), the bundled crypto JS module (OpenPGP.js included via esbuild, SRI-locked)
web/partials/              # source for partials.js — hand-written, no build step, ships as-is
web/crypto/                # source for the JS crypto module (bundled by esbuild — esbuild runs *inside* the Containerfile build, never on the developer's host; see §7)
rookery                    # operator + developer dispatcher (single POSIX shell script; §11.12, ADR-0033). The only command the README teaches.
compose.yaml               # service definitions consumed by the dispatcher (dev server, test runner, linter, mailpit, prod Caddy)
Containerfile              # the build. Multi-stage: Go compile + esbuild for the crypto JS + distroless final image. `docker build` on a clean checkout produces the deployable image.
docs/
  adr/                     # architecture decision records
  ops/                     # deployment, DNS, TLS, runbook docs
PLAN.md                    # this file
README.md                  # quickstart with `rookery init` + `rookery up`
SECURITY.md                # threat model + reporting (Phase 6)
LICENSE                    # AGPLv3
```

No `rookery-cli` Go binary: the `rookery` script at the repo root is a single POSIX shell dispatcher (§11.12, ADR-0033) — inspectable end-to-end with `cat rookery`, no build step. Per-task shell scripts (`run.sh`, `scripts/new-invite.sh`, `scripts/send-test-mail.sh`) were consolidated into it.

## 13. ADR index and starting work

### ADR index

The ADRs below capture the decisions made across this plan. They are listed here for traceability; each one becomes a short document under `/docs/adr/`. **ADRs 0001–0009 (the architectural foundations) are written before Phase 1 code lands** — they are short, they're already decided in this plan, and committing them as standalone documents grounds future PRs in stated decisions rather than vibes. The remaining ADRs can be written when their topic comes up, except where a phase's deliverable explicitly requires one first (ADR-0028 before Phase 7, ADR-0029 before Phase 6, ADR-0032 before Phase 5). The plan itself is the canonical record until each ADR is written.

**Architectural foundations:**
- `ADR-0001` — PGP-first mail server speaking standard SMTP; no new wire protocols.
- `ADR-0002` — Server-rendered HTML, hand-written JS only (crypto + partials); no SPA, no HTMX, no third-party clients in v1.
- `ADR-0003` — No persistent device state, no account recovery: every login on any device requires passphrase + recovery file.
- `ADR-0004` — Key discoverability: WKD + auto-attach on outbound; Autocrypt later.
- `ADR-0005` — Operator UX as first-class concern, but operator works from the shell; no admin web UI; 30-minute active-time-to-instance NFR.
- `ADR-0006` — Deliberately replaceable: standards-compatible formats, no lock-in.
- `ADR-0007` — Custom domains are a v1 feature with per-domain MTA-STS/TLS-RPT/ACME and a kill switch.
- `ADR-0008` — One in-app role (user). No admin in the app; the operator works from the shell. Invite-only registration; first user is created via `new-invite.sh` like any other user.
- `ADR-0009` — Desktop-first, mobile-tolerated.

**Cryptography:**
- `ADR-0010` — Private key handling: client-only custody (user-held recovery file required on every login; unlocked key cached in `localStorage`, cleared on logout; server never holds the private key). Records the rejected "encrypted blob on the server" and "IndexedDB cache between sessions" alternatives and the reasons.
- `ADR-0011` — OpenPGP key defaults: Curve25519 (ed25519 + cv25519); RSA legacy import only.

**Frontend & dependencies:**
- `ADR-0012` — No HTMX; in-house `partials.js`; HTML-fragment endpoints.
- `ADR-0013` — Aggressive dependency minimalism / supply-chain posture.

**Identity & addresses:**
- `ADR-0014` — Identity model: key-as-identity, address-as-attribute.
- `ADR-0015` — Authentication: challenge/response signed by the private key (no server-side passphrase hash); cookie sessions; 2FA by design (passphrase + recovery file, both required); TOTP not implemented (redundant under this model); CSRF protection; no SMS.
- `ADR-0016` — Content Security Policy: strict by default, stricter on crypto pages.
- `ADR-0017` — Address model: multiple addresses per user, plus-addressing, non-plus aliases, opt-in catch-all on custom domains.
- `ADR-0018` — Reserved local-parts (`postmaster`, `abuse`, `hostmaster`, `webmaster`).

**SMTP, storage, transport:**
- `ADR-0019` — SMTP listener policy: ports, TLS, auth requirements, mail-size limits, bounce policy.
- `ADR-0020` — Outbound rate limits (per-user, per-instance).
- `ADR-0021` — Mailbox model: flat list with virtual views, soft-delete trash, per-user quota.
- `ADR-0022` — Storage: Postgres + content-addressed filesystem blobs; `golang-migrate` for migrations.
- `ADR-0023` — Server master key: scope, encryption-at-rest policy, operator responsibility.
- `ADR-0024` — DNS, TLS, WKD: advanced-method WKD only, ACME HTTP-01 (via Caddy sidecar — see implementation note in ADR), MTA-STS mode handling (testing → enforce), DKIM ed25519+RSA dual selectors. **Written; Phase 3 complete.**
- `ADR-0025` — Account suspension flow.

**Account lifecycle:**
- `ADR-0026` — Account deletion and data retention.

**Operator interface:**
- `ADR-0027` — Configuration model (env + config file split) and operator runbook (shell-script dispatcher + documented `psql` queries; no admin web UI; no separate Go CLI binary).
- `ADR-0033` — Unified `rookery` shell-script dispatcher. Consolidates `run.sh`, `scripts/new-invite.sh`, and `scripts/send-test-mail.sh` into a single executable at the repo root with subcommand dispatch. Splits bootstrap into a user-local `rookery init` (writes `.env`, `rookery.toml`, `Caddyfile`, and a staged `./rookery.service`) and a single-sudo `rookery install` (copies the unit into `/etc/systemd/system/` + `daemon-reload`). Adds `rookery start [--prod]` / `stop` / `restart`, `rookery update` (`git pull --ff-only && docker compose build`), `rookery invite create`, and `rookery send-mail`. Supersedes in part ADR-0005 (the "separate admin CLI binary" alternative — still rejected as a Go binary, accepted as a shell-script dispatcher) and ADR-0008 (the `./scripts/new-invite.sh` invocation form, now `rookery invite create`). **Written; Phase 3 follow-up.**

**Shape-committed; wire format and exact spec deferred to the ADR document:**
- `ADR-0028` — Key-rotation attestation protocol. In-band message headers signed by the outgoing key, covering `(old fp, new fp, monotonic counter, timestamp)`; lost-key fallback to TOFU. Wire format TBD. [needed before Phase 7]
- `ADR-0029` — Backup format and encryption. `tar.zst` of `pg_dump` + content-addressed blob tree, encrypted with `age` to an operator-provided recipient public key. Bundled `backup.sh` / `restore.sh`. Verified roundtrip via in-repo test (container-driven, no hosted-CI dependency, §7). [needed before Phase 6]
- `ADR-0030` — Smarthost integration shape. Opt-in (off by default), per-instance scope, rookery signs DKIM before handoff (smarthost is opaque transport). Same configuration block accepts either a commercial relay (SES/Postmark/Mailgun) or a *relay rookery* (another rookery instance acting as upstream); the relay-rookery arrangement is bilateral, operator-configured out of band, with abuse exposure for the relay-rookery operator named honestly. No directory, no auto-discovery — there is no rookery federation protocol. [Phase 8]

**Bundled services:**
- `ADR-0032` — Spam filter: rspamd + bundled Redis, stock defaults, ClamAV opt-in (off by default for the 2 GB RAM budget). No Bayesian training UI in v1; no "mark as spam" button. Spam routed to Trash, not a separate Spam folder. Operator tunes via mounted volume over `/etc/rspamd/local.d/`. Training UX and per-user bayes are Phase 8+. [before Phase 5]

### Concrete starting work

1. Add `LICENSE` (AGPLv3).
2. Scaffold the Go module, `chi` HTTP server with `/healthz`, multi-stage Containerfile (the build, §7), thin Makefile wrapper. No hosted-CI config — the project is forge-agnostic.
3. Stand up `compose.yaml` with Postgres and `mailpit` for local SMTP testing.
4. Sketch the HTTP resource model (users, messages, keys, domains, addresses, invites) as an internal reference under `/docs/`. Not a public contract — just a shared vocabulary before the first handler is written.
5. **Write the foundational ADRs (0001–0009) before non-trivial code lands** — this is a hard prerequisite for Phase 1, not a "should." The rest of the ADRs can be written when their topic comes up, except where a phase's deliverable requires one first (see the ADR index above).
