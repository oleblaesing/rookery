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

**Accounts are pseudonymous by default.** Signup asks for a local-part, a login
passphrase, and a PGP passphrase. Nothing else. No name, no phone, no recovery
email, and the server does not log connecting IPs. The account/key pair is the
only identity rookery knows about a user, and that is the property we want to
preserve. The recipient and the network path still see standard SMTP metadata —
that is a consequence of speaking email to the rest of the world, not a property
rookery can hide; see §4.

**The user owns their key. The server never holds it, not even encrypted.** The
PGP private key is generated in the browser, encrypted with a passphrase-derived
key, and stored only in two places the user controls: in IndexedDB on the
device(s) where the user has chosen to set it up, and in a recovery file the
user downloads at signup and must keep off-device. The server holds the public
key (it has to — outbound signing auto-attaches it and WKD publishes it). The
server never holds the private side. This is a stronger property than the
common "encrypted blob on the server" model and matches the principle that the
user — not the instance — owns the identity; the operational consequences are
spelled out in §5 and §11.1.

rookery is a complete email stack — server + web client — in one container. Postfix
+ Dovecot + Roundcube, opinionated and PGP-first, deployable in one command. That's
the entire scope. We are not building a network, a movement, or a federation
protocol. We are building a piece of software that runs email well.

If many people run good instances, the consolidation problem solves itself as a
side effect — but that outcome is not the goal of the design. The goal is for the
software to be correct, small, honest, and pleasant to operate.

## 2. Guiding principles

1. **The instance is the product.** The hard work is operational: deliverability, spam filtering, setup, migration, day-2 ops. Not crypto, not protocols. Optimize for "this is easy to run well," not "this has clever new technology."
2. **Standards only, no novel crypto or protocols.** SMTP, MIME, OpenPGP (RFC 9580), PGP/MIME (RFC 3156), WKD, Autocrypt, DKIM/SPF/DMARC, MTA-STS, TLS-RPT, Argon2id. We are consumers of standards via `ProtonMail/go-crypto` and `OpenPGP.js`. No new wire protocols, no new key-exchange schemes, no roll-our-own anything. SMTP is how rookery instances talk to other mail servers; that is not a feature we invented, it is the existing internet.
3. **Aggressively standards-compatible, deliberately replaceable.** A user's PGP key generated in our client is a normal OpenPGP key — exportable to and importable from `gpg`. Our messages are byte-compatible with what `gpg --encrypt --sign` produces; any conforming PGP implementation can decrypt them. Our WKD records are consumable by any WKD client. Our HTTP API is documented as a stable, public interface. The user is never locked in. We are the convenient default; the standards are the escape hatch.
4. **Zero-trust server for content.** A compromised server must not be able to read PGP-encrypted message bodies or forge user signatures. Metadata leakage to the server is accepted and documented.
5. **PGP-first, not PGP-only.** Outgoing messages are encrypted whenever the recipient's key is discoverable. Plaintext fallback exists but always requires explicit confirmation.
6. **Our web UI is the v1 client, not the only conceivable client.** Server-rendered HTML, small amount of JS for PGP operations only. No SPA, no IMAP/POP for third-party clients in v1. The HTTP API is the actual product surface (see P1); it is designed and documented from day one as a stable contract so future clients (native, CLI, community-built) can be written against it without us reinventing anything. The web UI is the *first consumer* of that API, not a privileged one.
7. **Utilitarian UI in v1.** Inbox list, read, compose. Nothing else. The UI should look like a competent admin panel or a well-made distribution homepage (think `archlinux.org`, `voidlinux.org`, `man.archlinux.org`) — information-forward, no marketing prose, no decoration that doesn't carry information — not Superhuman. The visual direction is spelled out in §11.15. Polish in the "Superhuman-y" sense is Phase 7+ or never; the disciplined-utility look of §11.15 is shipped from v1.
8. **Techies as the user target.** Hard rules instead of compromised UX: one device per key, lose-your-passphrase-lose-your-mail, manual key import/export supported.
9. **Desktop-first, mobile-tolerated.** The target user lives on a desktop or laptop: a real keyboard, a file system, `gpg`, an `$EDITOR`, the ability to keep a passphrase-protected key on durable local storage they control. We design the web UI to be *usable* in a mobile browser (it should not break), but we do not optimize for mobile, we do not ship a native mobile app in v1, and we do not pretend a smartphone is a good place to hold a long-lived PGP private key. Push notifications, mobile-share targets, and similar mobile-native affordances are explicit non-goals for v1.
10. **Operators are a target audience too, but they operate from the shell.** A competent Linux user with a domain should get a working instance — TLS, verified DNS, one user — in under 30 minutes of active configuration time. The operator's interface to the system is **the shell on the box**, not a web admin panel: editing a config file, running `docker compose up`, occasionally running a documented `psql` snippet or a small script from the repo. There is no admin web UI, no in-app admin role, no setup wizard. The operator already has root on the VPS; reinventing access controls in a browser would be busywork. Anything that requires a separate admin app to do is either a sign we got the data model wrong, or a sign it doesn't belong in v1.
11. **Boring server, small browser.** Server-side: Postgres, Go stdlib, `html/template`. No frameworks, no clever runtimes. Browser-side: we are honest that the stack (OpenPGP.js, WASM Argon2id, IndexedDB-stored encrypted key, future SSE) is *not* boring — it is the most security-sensitive code we ship. We keep it small, auditable, pinned, and SRI-protected, and we treat its review burden accordingly.
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
- An IMAP/POP server. No third-party client support.
- A network, a federation, or a movement. rookery instances talk to other mail servers via plain SMTP, the same as every mail server on the internet. There is no inter-instance coordination, no shared directory, no special protocol between rookery servers.
- A messaging app reinventing email. We use real RFC 5322 messages.
- A consumer product. UX targets people who know what a keypair is.
- An inventor of cryptographic protocols. We use OpenPGP via established libraries; no novel cryptography.
- A Unix shell in the browser. We don't run `gpg` in WASM, we don't pretend the browser is your local environment. The browser is a sandbox; we are honest about that. The `pass`-philosophy property is achieved through standards-compatibility and a clean HTTP API — not by faking a Unix toolchain in the page.

## 4. Threat model (initial sketch)

| Actor | Can do | Cannot do |
|---|---|---|
| Home server (honest-but-curious) | See envelope (From/To/Subject/timestamp/size), see plaintext for non-PGP mail, see ciphertext for PGP mail | Read PGP-encrypted bodies, forge user signatures, derive private key |
| Home server (malicious) | Drop/delay mail, serve wrong public keys to *new* contacts (key-discovery MITM), DoS the user, log everything, serve tampered JavaScript to extract passphrases on next login | Decrypt past PGP traffic, retroactively forge signed history, offline-brute-force user private keys (none are stored server-side, §11.1) |
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
2. **Copy the example compose file.** The README ships a known-good `compose.yaml` (Docker with the Compose v2 plugin; that is the only supported runtime — see §7). Operator copies it to the VPS along with the example `rookery.toml` config file.
3. **Edit the config.** `rookery.toml` is short and commented. Operator sets at minimum: primary domain (`rookery.example`), Let's Encrypt contact email, instance display name. Secrets (DB password, server master key, session-signing key) come from environment variables documented in the compose file — the operator either sets them inline or sources a `.env` file. The server master key (§11.6) is the one secret they need to back up themselves.
4. **`docker compose up -d`.** Server starts, opens ports 25/80/443/465/587, generates DKIM keys on first run, logs the required DNS records as structured log lines.
5. **Add the DNS records.** Operator either reads them from the log (`docker compose logs rookery | grep DNS`) or runs the bundled script `docker compose exec rookery /opt/rookery/scripts/print-dns.sh`. They paste records into their DNS provider, wait for propagation. The server periodically rechecks DNS and logs the status; when everything resolves correctly it provisions Let's Encrypt certs automatically (via `certmagic`) and starts accepting outbound mail.
6. **Create the first invite.** `docker compose exec rookery /opt/rookery/scripts/new-invite.sh` runs a small shell script (which under the hood is `psql -c "INSERT INTO invites ..."` plus a `printf` of the resulting URL). The script prints the invite URL to stdout. Operator visits the URL in their browser and goes through the user flow in §5.2a — picks a local-part, generates a PGP key in the browser, etc. They are now a regular user of the instance; that's the only role they need.
7. **(Optional) Users add their own custom domains.** Custom domains are always self-serve via the web UI flow in §5.2b. The user visits the custom-domain settings page, enters their domain, and follows the DNS-record wizard. The server generates per-domain DKIM keys, provisions ACME for `mta-sts.alice.com` and `openpgpkey.alice.com`, and guides the user through verification. There is no `add-domain.sh` script; operators who want to pre-register a domain for a user can do so via a direct `psql INSERT` into the `domains` table.

**Time budget:** under 30 minutes of *active configuration time* (DNS propagation and provider PTR turnaround excluded — see §10). Active steps are: edit config file (~5 min), `docker compose up` and wait for it to settle (~2 min), paste DNS records into registrar (~5 min), run invite script and complete user signup (~5 min). The rest is waiting on DNS, which is not us.

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

1. **Invite landing page.** Plain explanation of what they're about to do: "You're joining `rookery.example`, an encrypted email instance run by `<operator-display-name>`. The next steps will generate a PGP key in your browser. You will need to remember a passphrase. **If you lose this passphrase, your mail is unrecoverable. There is no reset.** We do not ask for your name, phone, or any other identifying information; the account is pseudonymous. The recipients of your mail and the network in between will still see standard email metadata (your address, theirs, subject lines, timestamps) — that is how email works, and it is not something we can change." One-click to proceed; one-click to abandon.
2. **Pick a local part.** Alice picks `alice`. Server confirms it's available on `rookery.example`.
3. **Pick a login passphrase.** This protects the account at the HTTP layer (session login). Stored as Argon2id hash on the server.
4. **Pick a PGP passphrase.** Separate from login passphrase, by design. This one *never* leaves the browser. Argon2id-derives a symmetric key in WASM; the resulting key encrypts Alice's private OpenPGP key. The passphrase is not uploaded; the encrypted private key is not uploaded either — see step 7.
5. **Keypair generation, in browser.** Curve25519 by default. Fingerprint shown. Alice sees `alice@rookery.example` and a fingerprint like `A1B2 C3D4 ... 9F0E`.
6. **Public key uploaded to the server.** The server needs the public key to publish via WKD and to attach to Alice's outbound mail. *Only the public key.* The private key has not left the browser at any point and never will.
7. **Recovery file — mandatory.** Page shows the encrypted private key as a downloadable `.asc` file along with the fingerprint and a printable copy of the public key. **Alice must download this file before the page lets her continue.** This file is the only off-device copy of her private key. The server does not keep a copy. The wording on the page is unambiguous: "This file plus your passphrase *is* your account. If you lose either, your mail is gone — there is no reset, no server-side rescue, no recovery flow. Treat this file the way you would treat the only key to a safe."
8. **Encrypted private key stored locally in IndexedDB on this device.** Same encrypted blob the user just downloaded, also cached in the browser so daily logins on this device only need the passphrase. Logins on a *different* browser or device require importing the recovery file once on that device (see §5.3).
9. **Done.** Alice lands in an empty inbox. WKD is now publishing her public key under `rookery.example`.

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
6. **Then: same flow as 5.2a from step 3 onward.** Login passphrase, PGP passphrase, key generation, public-key upload, mandatory recovery-file download, local IndexedDB caching.

**Total time:** dominated by DNS propagation, ~15 minutes if Alice's registrar is fast (Cloudflare, Namecheap), up to a couple of hours if it's slow. Active configuration time: maybe 10 minutes of copy-paste.

**Why this is the killer feature:** Alice's identity is `alice@alice.com`, owned by Alice, not by the instance. If she ever leaves this instance — operator quits, instance goes down, Alice gets unhappy with policies — she changes her MX and DKIM CNAMEs to point at a new instance, exports her mailbox from instance A and imports it into instance B (her key never left her browser to begin with, so there is nothing key-shaped to "move"), and her *email address is unchanged*. This is what "deliberately replaceable" means at the user level. Without custom domains, leaving an instance is a forced address change. With them, it's a DNS update.

### 5.3 Daily-use journey — "I have an account, what's it like?"

Most of the product surface lives here, and most of the time it looks unremarkable, which is the point.

**Login on a device Alice has used before.** Alice visits `https://rookery.example` (or her own bookmark). Enters login passphrase. Server returns a session cookie. The browser reads the encrypted private key from IndexedDB on this device, prompts Alice for her PGP passphrase, Argon2id-derives the key, decrypts the private key, holds it in memory for the session. Inbox loads, server-rendered.

**Login on a new device (or a browser where IndexedDB has been cleared).** Same first step: Alice enters her login passphrase, server returns a session cookie. The browser looks in IndexedDB, finds no key, and the UI prompts: "no key found on this device — import your recovery file to continue." Alice drags her `.asc` recovery file onto the page (or pastes its contents), enters her PGP passphrase, the key is decrypted in memory, and a checkbox **"remember on this device"** controls whether the encrypted blob is also written to IndexedDB. The default is *off* — borrowed-browser use leaves nothing behind. On Alice's own laptop she ticks it; the next login on this device is the seamless flow above. The server is uninvolved in any of this beyond serving the static page and the session cookie; no key material is uploaded.

**Reading an encrypted message.** Server renders inbox row → Alice clicks → read page renders headers, structural metadata, attachment list. Body area initially shows "decrypting..." JS module fetches the ciphertext, decrypts in memory, renders. Signed-by status is shown plainly: "Signed by Bob (fingerprint match)" / "Signed but key unknown" / "Unsigned." Plaintext-received messages render normally with an obvious "this message was received in plaintext" banner.

**Composing to someone with a known key.** Alice clicks "Compose." As she types `bob@…`, a small in-house JS helper (see §7 and ADR-0012) debounces and hits the server's discovery endpoint. Server checks: known-keys cache → WKD → keyserver. Result shows next to the recipient: green padlock with fingerprint preview, or yellow "first seen" badge, or red "no key found." Multi-recipient: each gets its own indicator. On submit, the JS module fetches the recipient public keys + Alice's decrypted private key, builds a PGP/MIME message, attaches Alice's own public key, POSTs ciphertext. Server queues.

**Composing to someone with no discoverable key.** Same flow, but the recipient row shows red "no key — this will be plaintext." The send button is disabled until Alice explicitly toggles "Send in plaintext anyway" per-recipient. Mixed recipients (some known-key, some not) show a banner: "This message will be sent encrypted to 2 recipients and in plaintext to 1." Alice must acknowledge before sending.

**Receiving a reply from someone new.** Bob (using Thunderbird+OpenPGP, or another `rookery` instance, or Proton, or `gpg` directly) replies. His message includes his public key as an auto-attached PGP key, or our server discovered it via WKD on the next send. Either way, Alice's known-keys cache now contains Bob's key with a "first seen on `<date>`" annotation. Subsequent threads with Bob are seamlessly encrypted.

**Losing the device.** Alice's laptop dies. She goes to any browser, logs in with her login passphrase, gets the "no key found" prompt, drags her recovery `.asc` file in, enters her PGP passphrase, and resumes. The recovery file is the only off-device copy of her key; the server has nothing to "return." **If she has no recovery file, her mail is unrecoverable, regardless of whether the server is up.** Hard rule, said plainly at onboarding (§5.2a step 7). She can register a new keypair on a new account, but past mail decrypted under the old key is gone. This is the inverse of the common webmail model and it is deliberate: the server has no power to lock Alice out of her mail, and equally no power to rescue her from a lost recovery file. She holds both halves.

**Migration to another instance.** (Phase 5.) Alice on `alice@alice.com` decides to move from instance A to instance B. From instance A she exports her mailbox archive (server-side data: messages, addresses, aliases, known-keys cache, metadata). She joins instance B via the custom-domain flow, imports the mailbox archive there, and uploads her existing public key so instance B can publish it via WKD and attach it to outbound. Her private key was never on instance A in the first place — it lives in her browser's IndexedDB (per-origin, so instance B's web UI starts fresh and treats her like a new device) and in the recovery file she controls. The first login on instance B is the new-device flow described above: import the recovery file, enter the PGP passphrase, tick "remember on this device." She points her DNS records at instance B's hostnames, waits for propagation. Her address, her key, her thread history — all preserved. Correspondents notice nothing.

### 5.4 What these journeys explicitly rule out

Naming the absences is as important as naming the features:

- **No "forgot my passphrase" link, anywhere, ever.** Not on login, not in settings, not as a recovery flow with security questions. Hard rule, surfaced honestly at onboarding.
- **No server-side private-key storage.** The server holds public keys (it has to, for WKD and outbound auto-attach) and nothing else key-shaped. The encrypted private key lives in the user's browser IndexedDB and in the recovery file the user downloaded at signup. The server cannot rescue a user who lost both, and cannot be compelled, subpoena'd, or breached into surrendering private keys it does not possess. §11.1 / ADR-0010 spells out the model and the trade-off against the "encrypted blob on the server" alternative we considered and rejected.
- **No multi-device sync.** Alice's key lives on one device at a time. Using the same account from a second device means importing the recovery file once on that device (a deliberate, manual action), not transparent sync.
- **No mobile app, and no mobile-optimized experience, in v1.** Mobile browsers will *load* the same UI and basic flows will work, but we do not optimize layouts, gestures, or input for phones, and we do not ship a native iOS/Android app. This is a deliberate match to the audience: the target user is desktop-heavy, has a keyboard and a real file system, and is unlikely to want a long-lived PGP private key sitting on a phone they lose, lend, or replace every two years. A future PWA or native client is a Phase 7+ conversation, not a v1 gap.
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
   ─── SMTP (25/465/587) ──▶│                       │◀── HTTPS ──┐
   ◀── SMTP ──────────────│  ┌─────────────────┐    │            │
                          │  │ inbound SMTP    │    │   ┌────────┴────────────┐
                          │  │ outbound SMTP   │    │   │ Server-rendered HTML │
                          │  │ MIME + PGP/MIME │    │   │ + plain JS only:     │
                          │  │ WKD server      │    │   │   - OpenPGP.js       │
                          │  │ public-key      │    │   │   - WASM Argon2id    │
                          │  │   auto-attach   │    │   │   - in-house         │
                          │  │ key discovery   │◀───┼───┤     partials.js      │
                          │  │ html/template UI│    │   │     (fetch + swap)   │
                          │  │ message store   │    │   │   - key in IndexedDB │
                          │  └─────────────────┘    │   │     (passphrase-enc) │
                          │   Postgres + blobs      │   └──────────────────────┘
                          └─────────────────────────┘
```

Key ideas:
- **The browser is the trust anchor for content.** Private keys are generated in the browser, encrypted with a passphrase-derived key, and stored only in IndexedDB on the user's device(s) and in a recovery file the user controls. The server never holds the private key — not in plaintext, not encrypted. See §11.1 for the model and the trade-off.
- **The server renders the chrome.** Inbox lists, threads, settings, navigation — all server-rendered HTML. No client-side router, no SPA, no HTMX-style attribute framework.
- **JS does crypto.** A small, auditable JS module on the compose and read pages handles encrypt/decrypt against locally-held keys. Form submit is intercepted, ciphertext is posted to the server. Without JS, compose and read show a "JS required for PGP" notice; the rest of the UI works fine.
- **JS also does partial updates, in-house.** A second small module — `partials.js`, hand-written, no third-party library — provides `fetch + swap` helpers for the handful of places we want partial-page updates (recipient key-status hints, DNS verification polling, mark-as-read, inbox refresh). It exposes a few primitives (`swap`, `poll`, `debounce`, `onSubmit`) and operates on `data-*` attributes. Endpoints called by this module return **HTML fragments**, never JSON, except where the JS module needs raw data (ciphertext, key material). This rule is the discipline that prevents drift toward an accidental SPA. The reasoning and the contract live in ADR-0012.

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
- Later (Phase 7): also exposed via Autocrypt headers on outbound mail for clients that prefer that mechanism.

## 7. Tech stack

| Layer | Choice | Rationale |
|---|---|---|
| Server language | **Go** | Mature SMTP libs (`emersion/go-smtp`, `emersion/go-message`), strong stdlib, single-binary deploys. |
| HTTP framework | `net/http` + `chi` | Boring, fast, no magic. |
| SMTP (inbound + outbound) | `emersion/go-smtp` + `emersion/go-message` | De facto standard Go SMTP/MIME stack. |
| OpenPGP on server (for discovery, signing of WKD records) | `ProtonMail/go-crypto` (OpenPGP fork) | Actively maintained, used in production by Proton. |
| Database | **PostgreSQL** | Boring, reliable. One backend, not two — see §11.6. |
| Migrations | `golang-migrate` | Decided in §11.6. |
| Blob storage (raw `.eml` files) | Filesystem, content-addressed paths (`/blobs/sha256/ab/cd/...`) | §11.6. S3-compatible is a Phase 7+ option if it's ever wanted. |
| Frontend rendering | **Go `html/template`** (stdlib) | No framework, no build step for HTML. |
| Frontend interactivity | **In-house `partials.js`** — hand-written, no third-party library | `fetch + swap` helpers for partial updates (key-status hints, DNS polling, mark-as-read). Replaces HTMX. Per P12, every avoided dependency is a removed supply-chain attack surface; this one we can replace with ~150–250 lines of code we own and audit. Endpoints return HTML fragments. Reasoned out in ADR-0012. |
| Frontend styling | Hand-written CSS, single stylesheet. Visual direction: techie-utility, in the lineage of `archlinux.org` and `voidlinux.org` — see §11.15 for the full spec. | Techie audience, no design system needed. We deliberately **avoid** even classless frameworks like `pico.css` — same supply-chain reasoning (P12). Hand-written CSS in a single file is fine for the v1 UI's scope, and the visual target is information-forward enough that no framework would help anyway. |
| Client crypto module | **OpenPGP.js**, loaded as a single pinned + SRI'd script on compose/read pages only | The standard. Tiny isolated surface. *This is one of the few third-party browser deps we accept; we are not going to write OpenPGP ourselves.* Pinned to a specific commit, SRI-locked, no transitive deps at runtime. |
| Passphrase KDF | Argon2id via WebAssembly (e.g. `argon2-browser`) | Strong KDF, runs locally. Same dep posture as OpenPGP.js: pinned, SRI-locked, vendored if necessary. |
| Client storage | IndexedDB on each set-up device; private key stored encrypted with passphrase-derived key. Recovery `.asc` file (same encrypted blob) held off-device by the user, mandatory at signup. | Passphrase never leaves the device. Private key never leaves the user's control — server holds nothing key-shaped on the private side, see §11.1. |
| Server-push (later) | Server-Sent Events via browser-native `EventSource` for new-mail notifications | Long-poll first. No WebSockets. No library — `EventSource` is stdlib in the browser. |
| Build | **The Containerfile is the build.** `docker build` on a clean checkout produces the deployable image, with no other host-side toolchain required. Inside the multi-stage build: Go toolchain compiles the server; a single `esbuild` invocation bundles the JS crypto module (and only that — `partials.js` ships hand-written, no bundler). No `npm run dev`, no Vite. No transitive `postinstall` scripts permitted at any build stage. **No hosted CI provider is assumed.** The project is forge-agnostic — GitHub, Codeberg, sourcehut, a self-hosted Gitea, or a tarball on someone's web server are all equally valid hosting choices. If a hosted CI is in use for a particular fork or mirror, it runs the same `docker build` and the same in-repo test scripts that any developer or self-hoster runs locally; the project does not ship forge-specific workflow files in v1. Lint and test entrypoints (`go test`, `go vet`, optionally `golangci-lint`) are invoked inside the container build or via a small Makefile / `dev.sh` wrapper, runnable by anyone with `docker` installed and nothing else. | Minimal toolchain, minimal supply-chain exposure, no vendor lock-in for the build pipeline. |
| Container | Multi-stage `Dockerfile` (also valid `Containerfile`), distroless final image. **The Containerfile is the only supported build path** — not just for deployment but for development too, where JS bundling is involved (Go code can be iterated with native `go run` / `go test` on the host, which is normal and fast; the JS crypto module goes through the container build so developers don't have to install Node or esbuild on their host). **Runtime: Docker only, with the Compose v2 plugin.** Rootless Podman was evaluated during Phase 0 and rejected — privileged-port binding, OCI vs Docker image format, short-name resolution, and `podman-compose` bookkeeping noise added up to too much friction for too little gain, and supporting both runtimes doubled the surface area we'd have to test and document. The compose-spec file is what it is; operators on Podman hosts can run the Docker CLI against the Podman socket if they really want to, but that path is not tested or supported. | Easy self-host. One runtime to document, one runtime to test against; we explicitly trade a small piece of audience preference for a much simpler operator experience. |
| License | **AGPLv3** | Closes the SaaS loophole. Anyone running rookery as a service has to ship their changes back. |

### Explicitly deferred / rejected

- **No SPA.** Server-rendered HTML + a tiny hand-written `partials.js`. JS for crypto and a handful of partial updates; nothing else.
- **No frontend framework.** No React/Vue/Svelte/Solid/etc.
- **No HTMX or HTMX-equivalent.** We considered HTMX and rejected it on supply-chain and minimalism grounds. Our partial-update needs (recipient key hints, custom-domain DNS verification polling for user self-serve, mark-as-read) are small enough to handle in ~200 lines of hand-written JS. See ADR-0012.
- **No CSS framework**, not even classless ones like `pico.css`. Hand-written CSS only.
- **No IMAP/POP** server. Hard rule for v1.
- **No mobile apps**, no PWA, no mobile-optimized layout in v1. See P9 and §5.4.
- **No custom inter-instance protocol, no DHT, no libp2p, no blockchain.** Two rookery servers communicate the same way Postfix and Exchange do: SMTP over the internet. There is nothing else.
- **No multi-device key sync.** One device per account by default.
- **No account recovery.** Lose passphrase → lose mailbox. Documented.
- **No encrypted Subject lines.** Standard PGP/MIME leaks them; ecosystem norm; not solvable interoperably.
- **No `npm`-style dependency cascades anywhere.** OpenPGP.js and the WASM Argon2id binary are vendored or pinned-with-SRI; we never run `npm install` in production paths, and the Containerfile build forbids transitive `postinstall` scripts (P12).

## 8. Roadmap

This is a side project. The roadmap is a dependency graph and a rough sizing signal, not a deadline.

**Phase budgets** below are given in *engineer-weeks of focused full-time work* — useful for chunking and for knowing which phases are big vs small relative to each other. Real calendar time on a side-project cadence is whatever it is; multiply by your own pace factor. The sizing exists to communicate "this phase is twice as big as that one," not "you'll be done by month four."

**Phase ordering** is not strict. The phases overlap freely — Phase 3 (custom-domain infrastructure) shares ACME and DNS-verification code with Phase 4 (operator setup), and the HTTP API contract (P6 + P1) grows alongside Phase 1 rather than being frozen later. Treat phases as cohesive workstreams, not as a Gantt chart.

**ADR prerequisites** are called out inline where a phase depends on a design decision not yet made (see §11).

### Phase 0 — Foundations (≈1 week)
- Repo scaffolding, Go module, Containerfile (multi-stage: Go build + JS bundle + distroless final image). No Makefile — `docker compose` is the only interface; see §7.
- ADRs for the major decisions in this doc (at minimum: ADR-0001 through ADR-0008 from §13).
- README + this plan.
- `compose.yaml` with Postgres + a minimal SMTP test harness (e.g. `mailpit`) for local dev.
- **HTTP API sketch.** A first draft of the resource model (users, messages, keys, domains, invites) before any handler is written. Not frozen yet, but the shape exists on paper. This is the artifact P6 promises.

**Deliverable:** `docker compose --profile dev up --build` boots an empty server with `/healthz` (and mailpit for SMTP testing). The project builds from a clean checkout on any host with only `docker` installed. ADRs committed. API sketch reviewable.

### Phase 1 — Receive mail, decrypt in the browser (≈4–6 weeks)
- Inbound SMTP listener (port 25, STARTTLS-preferred, see §11.4) that accepts mail for the instance's primary domain.
- User accounts (login passphrase Argon2id-hashed server-side; PGP passphrase only ever used client-side, see §11.2). Cookie-based sessions with sliding expiry.
- In-browser keypair generation (Curve25519, §11.1); **public key uploaded; private key stays in the browser** — encrypted with the PGP passphrase, cached in IndexedDB, and downloaded by the user as a mandatory recovery file. The server never receives the private side.
- **Plus-addressing** from day one: `alice+anything@<primary>` routes to `alice`. Free with proper local-part parsing; cheap to do now, painful to retrofit.
- **Reserved local-parts** (`postmaster@`, `abuse@`, `hostmaster@`, `webmaster@`) auto-created on the primary domain and routed to the operator's user account (or to a configured fallback address).
- WKD endpoint serving local users' public keys, advanced method (§11.7). Z-base-32 SHA-1 hashing of local-parts is non-trivial; budget for interop testing.
- Mailbox model from §11.5: inbox, read/unread state, soft-delete to trash, virtual sent/drafts/bounced views (sent/bounced are empty in Phase 1; the structure is in place).
- Server-rendered inbox + read pages. Small JS module on the read page decrypts PGP/MIME bodies locally.
- Mail can be sent **into** the system from any external mailer (e.g. `gpg` + `swaks`, Thunderbird) and read in the browser.
- **HTTP API: first stable surface area** for everything implemented in this phase. The handlers the web UI calls are documented as the public API from day one — they are not "internal" routes we'll formalize later.

**Deliverable:** External user PGP-encrypts a message to `alice@yourdomain` via WKD lookup, sends it from their normal mailer; Alice reads it decrypted in her browser. The HTTP endpoints that made that work are documented.

> **Phase 1 is not yet a "useful product" in isolation** — you can receive PGP mail but not send it. Phases 1 and 2 should be viewed as a unit; we ship to friends-testing only at the end of Phase 2. This is a deliberate softening of P13 ("useful at every milestone") for the first two phases; we are honest about it.

### Phase 2 — Send mail outbound, key discovery, primary-domain delivery (≈4–6 weeks)
- Submission listeners on 465 (implicit TLS) and 587 (STARTTLS), auth required (§11.4).
- Server-rendered compose page.
- Server-side key discovery: local directory → WKD → optional keyserver. Cached with TTL. Recipient key-status hints (rendered as HTML fragments by the server, swapped into the compose page by `partials.js`) update next to each address as Alice types, with debounce + in-flight cancellation.
- Client-side PGP/MIME encryption + signing on form submit.
- **Auto-attach Alice's public key** to every outbound message.
- **Harvest auto-attached keys** from inbound messages into the per-user known-keys cache (with "first seen" indicators).
- Outbound SMTP queue with retries, DSN handling, and the bounce policy in §11.4.
- Per-user and per-instance outbound rate limits (§11.4).
- Plaintext fallback with explicit confirmation when no key is found for a recipient.
- Basic threading (group by `In-Reply-To` / `References`).
- **DKIM signing** (ed25519 + RSA-2048 fallback per §11.7), SPF and DMARC alignment on outbound, **for the instance's primary domain only.** (Per-user custom-domain DKIM lands in Phase 3.)
- Sent and Drafts virtual views become populated.
- HTTP API extended to cover send, draft, discovery, and queue-status endpoints.

**Deliverable:** Two-way email with the rest of the world, on the *instance's primary domain*. PGP-to-PGP works automatically when a key is discoverable via WKD or has been auto-attached on a prior message. Plain SMTP delivery on the open internet works with proper DKIM/SPF/DMARC alignment for the primary domain.

### Phase 3 — Custom domains and per-domain infrastructure (≈6–8 weeks)
**This phase is the killer-feature work.** It was previously bundled into Phase 2 as a bullet point; it is in fact the largest single workstream in the project, because it is the thing that makes §5.2b — `alice@alice.com` on a self-hosted instance — actually work. Without this phase delivered well, the project is "Proton but you host it," which is a worse Proton, not a real alternative.

- **User journey for adding a domain.** UI generates the full set of DNS records (MX, SPF, DKIM CNAME/TXT — both ed25519 and RSA selectors, WKD CNAME, MTA-STS CNAME + TXT, TLS-RPT, DMARC) with copy-paste values. TXT-challenge verification (`_rookery-challenge.<domain>`) before the domain is activated.
- **Per-domain DKIM lifecycle.** Two DKIM keypairs (ed25519 + RSA-2048, §11.7) are generated when a domain is verified; private keys encrypted at rest with the server master key (§11.6); public keys published via the user's DNS as CNAMEs to our selectors. Outbound mail from `@<domain>` is signed with that domain's keys. Rotation tooling stub (full dual-selector rotation lands in Phase 7).
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

### Phase 4 — Operator runbook and deliverability foundations (≈4–6 weeks)
The "make it actually-runnable for the operator" phase. Reuses ACME, DNS-verification, and key-lifecycle code from Phase 3. **No setup wizard, no admin web UI** — per P10 the operator works from the shell.

- **`compose.yaml` and `rookery.toml` examples** in the README, with sensible defaults. Operator copies, edits two or three values, brings up the stack. The config schema is documented inline in the example file.
- **Server-side bootstrapping on first run.** First-run server generates the DB schema, the per-instance signing keys, the primary-domain DKIM keys, the ACME account; logs the DNS records the operator needs to publish. No interactive flow.
- **Server master key generation and rotation.** First run generates the server master key and writes a one-time setup note to the log telling the operator to back it up. Rotation is a documented `psql` + `./scripts/rotate-master-key.sh` procedure.
- **Operator scripts** bundled in the image under `/opt/rookery/scripts/` (and mirrored in `/scripts/` in the repo for inspection). Each is a small shell script that mostly invokes `psql`. v1 set: `new-invite.sh`, `add-domain.sh`, `suspend-user.sh`, `unsuspend-user.sh`, `delete-user.sh`, `print-dns.sh`, `print-deliverability-stats.sh`, `rotate-master-key.sh`. Each script is a few dozen lines, runnable via `docker compose exec rookery /opt/rookery/scripts/<name>.sh`.
- **Bundled, pre-configured spam filtering** per §11.14 (ADR-0032): rspamd with stock defaults, Redis sidecar, ClamAV opt-in. No Bayesian training UI in v1 — that's a coherent Phase 7+ piece of work touching the inbox UI, storage model, and spam pipeline together. *We acknowledge per §9.2 that "works out of the box" here means "reasonable defaults, not Gmail-quality"; ongoing tuning is expected work.*
- **2FA (TOTP) for user accounts**, opt-in, set up in account settings (§11.2). This is user-facing; no operator surface.
- **Observability**: structured logs, Prometheus metrics endpoint. Cert renewal status, queued mail, recent bounces, per-user outbound volume, anomaly signals — all exposed as metrics. Operators wire their own Grafana or Alertmanager if they want graphs and alerts; we don't ship a UI for these.
- **Docs**: deployment guide, DNS reference, troubleshooting, "your mail is going to spam" runbook (which honestly explains the IP-reputation problem; see §10 and the README), custom-domain onboarding guide, **operator runbook** documenting every shipped script and the common `psql` queries (`SELECT * FROM users`, `UPDATE users SET quota = ... WHERE address = ...`, etc.).

**Deliverable:** A competent operator with a domain and a $5/month VPS goes from "fresh box" to "first invite URL generated" in under 30 minutes of *active configuration time* (DNS propagation and reverse-DNS turnaround excluded — see §10). The flow is: copy `compose.yaml` and `rookery.toml`, edit two or three values, `docker compose up -d`, paste DNS records, wait for propagation, run `new-invite.sh`. If any of those steps drift past the time budget, fix the example files or the script set, not the operator's expectations.

### Phase 5 — Productionize the user experience (≈4–6 weeks)

> **Prerequisite spike:** before Phase 5 planning locks, run a one-day perf investigation of OpenPGP.js with a 25 MB attachment (encrypt + decrypt round-trip, in a real browser, on a representative laptop). The output is a number, not a design — we need to know whether chunked encryption is "a week" or "a month" of work before committing to the Phase 5 budget. Per §9.7 the problem is known; the spike is what turns the known unknown into a sized known.

- Attachments (PGP/MIME parts; **chunked encryption** in the client for large files — this is a real piece of OpenPGP.js work, budget for it; the prerequisite spike above sizes it).
- Client-side full-text search index (decrypted in the browser, never sent to server, §11.5).
- **Account deletion flow** with the design from §11.9 (user-initiated web flow with 7-day grace period and double-passphrase confirmation; operator-initiated variant via `./scripts/delete-user.sh` for abuse cases).
- **Backup tooling.** Single-command encrypted backup per §11.10 (ADR-0029): `tar.zst` of `pg_dump` + blob tree, encrypted with age to an operator-provided recipient, bundled `backup.sh` and `restore.sh` scripts. Automated restore-from-backup test in the in-repo test suite per the NFR (runnable by anyone with `docker`; no hosted-CI dependency, §7).
- Per-user export of full mailbox (server-side data only — the user's private key has never been on the server, see §11.1; the recovery file the user already holds is the key half of the migration), in the format the migration story uses (Phase 6 will consume this).
- **HTTP API officially frozen.** Everything the UI uses is now versioned and committed to per §11.13 (ADR-0031): `/api/v1/` URL versioning, semver, ≥6-month deprecation window, stable JSON error format, cookie sessions plus per-user Bearer tokens for programmatic clients, cursor pagination, idempotency keys. The API has been designed iteratively since Phase 0; this is the formal freeze.
- Documented interop recipes: "decrypt your stored mail with `gpg` directly," "import your `rookery` key into Thunderbird," "export and re-import into another instance."
- Threat model written up in `SECURITY.md`.

**Deliverable:** A version trusted to run on a real domain for real correspondence, with a documented escape hatch and a stable client-facing contract.

### Phase 6 — Portability & migration (≈4–6 weeks)
This is what makes "trust no single instance" real. If migration between instances is trivial, no operator becomes load-bearing.

> **Design prerequisite:** the key-rotation attestation protocol is shape-committed in §11.10 (ADR-0028) but the wire format and exact header layout still need a written ADR before code lands. The identity model and address model are already resolved (§11.1, §11.3); the attestation protocol is the last design document to draft.

- **Key-as-identity in practice:** a user's identity is their long-lived PGP key fingerprint (§11.1). Their bundle of addresses is portable along with the key. On a destination instance the user imports the export, then re-registers each address (instance-domain addresses become new addresses; custom-domain addresses come with the user by repointing DNS).
- **Full mailbox export from the server**: complete mailbox + addresses + aliases + known-keys cache + metadata + the user's public key, in the format established in Phase 5. **The export does not contain the private key** — it has never been on the server (§11.1); the user already holds the only copies, in their browser's IndexedDB and in their recovery file. Migration is therefore *two* artifacts that the user owns: the mailbox archive (from instance A's export) and the recovery file (which they already have).
- **Import** on a fresh instance from the mailbox archive. The new instance's web UI prompts for the recovery file on first login, exactly as in the new-device flow (§5.3); the user enters the PGP passphrase and is back in business. There is no special "key import" step in the migration UI — re-using the existing recovery-file affordance keeps the migration flow small and the audit surface tiny.
- **Address forwarding** during migration windows so contacts using the old address still reach the user. (Applies primarily to users leaving an instance's primary domain; custom-domain users repoint DNS instead.)
- **Key rotation** with audit trail visible to user and (signalled to) past correspondents via signed key-change attestations included with future messages, per the shape committed in §11.10 (ADR-0028): attestations are message headers, signed by the outgoing key, covering `(old fp, new fp, counter, timestamp)`, attached to outbound for 90 days post-rotation. Wire format and exact header layout are specified in the ADR.

**Deliverable:** A user on a custom domain can move from instance A to instance B in under 15 minutes of active work (DNS propagation excluded), without losing mail or breaking encrypted threads. Users on the instance's domain get a forwarding window but accept an address change — that's the cost of not owning a domain, and we say so.

### Phase 7 — Hardening & ecosystem (open-ended)
- Autocrypt support (header-based key exchange) — sibling of our auto-attach.
- Instance-level abuse controls: rate limits, optional peer allowlists.
- Interop conformance tests against major providers (Gmail, Fastmail, Posteo, Proton).
- Optional smarthost integration (e.g. AWS SES, Postmark) for instances that don't want to fight IP reputation directly, per the shape committed in §11.10 (ADR-0030): opt-in (off by default), per-instance scope, rookery signs DKIM before handoff. *This is the realistic deliverability fix for new operators; see §9.1.*
- DMARC aggregate report ingestion + per-domain dashboard surfacing alignment failures.
- DKIM key rotation tooling (dual-selector transitions, automated DNS-update prompts).
- Hardware key (YubiKey) support for unlocking the encrypted private key in the browser, replacing or supplementing the passphrase-derived key.

**Deliverable:** A version that survives the open internet at small-instance scale.

### Phase 8+ — Possibly later
- **Reference Unix-tools client.** A documented set of bash/curl recipes (or a small Go CLI) that read and send mail against the HTTP API using the user's local `gpg`, `$EDITOR`, and shell. The `pass`/Mutt-philosophy back door. Community contribution welcome; not a project priority. Architecturally already possible from Phase 1 onward thanks to the day-one API discipline.
- **Mobile.** If and only if there is sustained demand from the actual user base, *and* a contributor wants to own it: an installable PWA first, a native client only if the PWA hits real limits. Per P9 and §5.4, this is explicitly not a v1 concern; the v1 target user is on a desktop.
- Optional minimal IMAP read-only export (controversial — discuss before building).
- Key transparency log integration.
- Group conversations / mailing list assistant.
- UI polish, keyboard shortcuts, threaded views, the Superhuman-y stuff. Only if it earns its place.

### What's load-bearing vs nice-to-have

If energy or time runs thin and the project needs to be pruned to its essential shape, this is the map.

**Load-bearing — these phases *are* the thesis. Without any one of them the project is not what §1 claims:**
- **Phase 1 + 2** (receive and send PGP mail in the browser). Obvious.
- **Phase 3** (custom domains). Without it, leaving an instance forces an address change, and "deliberately replaceable" collapses into marketing.
- **Phase 4** (operator UX). Without it, "one competent person can run an instance" is false in practice.
- **Phase 6** (migration). Without it, custom domains are just custom domains, not a portable identity story.
- **The HTTP API discipline running through Phases 0–5.** Without it, the "the web UI is one of many possible clients" principle is a slogan.

**Nice-to-have — defer freely:**
- Phase 5 polish items (client-side search index, chunked attachments). The product works without these.
- Phase 4 niceties beyond the example compose file, the bundled scripts, and the metrics endpoint. Nice-to-haves like Grafana dashboard JSON, fancier scripts, or pretty-printed CLI output are all defer-able.
- All of Phase 7 (Autocrypt, smarthost, hardware keys, DMARC reports, key rotation tooling).
- All of Phase 8+.

**Phases 0–6 total roughly 27–39 engineer-weeks of focused work.** On a side-project cadence that's whatever it is. The thing that matters is the order of the dependencies, not the calendar.

## 9. Hard problems we will hit (be aware now)

The hard work in this project is operational, not cryptographic. The crypto is solved (we use OpenPGP via mature libraries). These are the actual challenges:

1. **Deliverability.** This is *the* problem that kills self-hosted email today. Even with perfect DKIM/SPF/DMARC, a fresh IP gets junked by Gmail for weeks or months. We can mitigate (good DNS defaults, IP warming guidance, optional smarthost integration in Phase 7), but we cannot fully solve it. **The honesty pointer:** this caveat must be in the README, not just in §9 of this plan. The first thing a prospective operator reads should be "your outbound mail to Gmail will be unreliable for weeks; here's why; here's what you can do (warm the IP slowly, or use a smarthost in Phase 7)." Hiding it inside a 400-line plan is a trap.
2. **Spam filtering that works out of the box.** Bundling rspamd is the easy part; tuning it so it doesn't reject legitimate mail or accept obvious spam, without per-operator tweaking, is hard. Plan for this to be ongoing work.
3. **Outbound spam abuse.** If anyone can register on your instance, you become a spam source. Default to invite-only (§11.8); per-user and per-instance outbound rate limits (§11.4) land in Phase 2; abuse-relevant metrics (per-user volume, bounce rate, recent rejection codes) land in Phase 4 as Prometheus metrics that operators can alert on or graph in Grafana — we don't ship a dashboard ourselves (§11.8).
4. **Key discovery & TOFU.** WKD relies on the recipient's domain serving the right key. Domain operator (or anyone with TLS for that domain) can MITM first-contact. Auto-attached keys on inbound mail have the same trust property. Long-term mitigations: fingerprint verification UX, key transparency logs (out of scope for us), Autocrypt history.
5. **Migration without breakage.** "Easy migration" is the load-bearing feature for the trust-distribution claim. Getting it right (mailbox + key + identity + forwarding + correspondents updated) is finicky and easy to half-ass.
6. **Browser as a secure environment.** XSS = total compromise. Strict CSP, no third-party scripts ever, SRI on every asset. The no-SPA design helps a lot here: tiny, auditable JS surface.
7. **OpenPGP.js attachment performance.** Fine for messages, painful for big files. Chunked encryption is part of Phase 5; if it turns out attachments are needed earlier (e.g. for a real-user trial after Phase 2), we can pull it forward and accept the rework cost.
8. **No account recovery.** Hard rule, but we still need a *very* clear onboarding flow so users understand it. Otherwise it's just data loss with extra steps.
9. **Replying to plaintext threads.** If half a thread is plaintext on the server and half is E2E ciphertext, the UI must make the security state of every message obvious.
10. **Pseudonymity vs abuse signals.** Not logging connecting IPs (§5.4, §11.2) and accepting Tor without penalty (§11.4) is a deliberate property of the system, and it costs us something concrete: we lose the IP-based heuristics that conventional mail systems use to detect compromised accounts and brute-force login attempts. The defenses we keep are (a) invite-only registration by default (§11.8), (b) per-user and per-instance outbound rate limits (§11.4), (c) per-user bounce-rate and rejection-code metrics (Phase 4) that an operator can alert on. Public instances combining open registration, no IP logging, and Tor-tolerance take on real abuse risk; the README and the config-file comments must say so out loud. We are not going to recover the IP signal by giving up the pseudonymity property — that trade was the point.

## 10. Non-functional requirements

These are measurable targets. Each is paired with the honesty caveat that makes it actually achievable, because an NFR you can't hit is just a lie with a number on it.

- **Time-to-instance:** under **30 minutes of active configuration time** for a competent Linux user with a domain, on a properly-provisioned VPS. The flow being measured is the one in §5.1: copy `compose.yaml` and `rookery.toml`, edit two or three values, `docker compose up -d`, paste DNS records, run `new-invite.sh`, complete the user-signup flow. *Excluded from this budget, because they are outside our control:* DNS propagation, reverse-DNS (PTR) turnaround at the VPS provider (often a support-ticket process — documented in §5.1), Let's Encrypt rate-limit cooldowns if the operator has previously burned attempts on the same hostname. Honestly measured by running through the README on a clean VPS and recording the steps; if the steps take longer than budget, the README or the scripts are the bug, not the budget.
- **Resource footprint:** a working single-user instance fits comfortably on a **2 GB RAM** VPS (1 vCPU, 25 GB disk) with rspamd + Redis enabled and ClamAV disabled by default. The popular "$5 VPS" target hits this on most providers (Hetzner CX22, OVH, etc.); the older 1 GB tier is *technically* runnable but leaves no headroom and will OOM under sustained spam load. We document the realistic minimum rather than the marketing minimum. ClamAV is opt-in; enabling it adds ~1 GB RAM.
- **Deliverability — configuration score:** an instance brought up with the example `compose.yaml` and `rookery.toml` passes **all DNS/auth configuration checks** (SPF, DKIM, DMARC, MTA-STS, TLS-RPT, PTR, valid TLS chains) on first try, once the operator has published the DNS records the server logs at startup. The server's own preflight checker is the source of truth for this NFR; the project ships a scripted, repo-local test that runs the preflight against a controlled environment. Anyone with `docker` installed can run it; whoever maintains a fork or tags a release is responsible for running it before releasing. The project does not depend on a hosted CI provider to enforce this — see §7's Build row. This is the part of "deliverability" that is actually under our control.
- **Deliverability — reputation score:** **not an NFR, on purpose.** Per §9.1, the headline `mail-tester.com` score and inbox-placement at Gmail/Outlook depend on the *IP reputation of the VPS provider's range*, which we do not control. A fresh budget-VPS IP frequently starts in the 6–8 range on mail-tester regardless of configuration, and can land mail in spam at Gmail for weeks or months. The operator can run `mail-tester` themselves; we don't paper over the result with a gate. The docs explain why operators who need guaranteed deliverability use a smarthost (Phase 7) or a clean dedicated IP.
- **Backup:** a single command produces a complete, encrypted, restorable backup. The project ships an automated restore-from-backup test as part of its in-repo test suite, runnable by anyone with `docker` installed (one command). Whoever tags a release runs it before tagging; whoever maintains a fork runs it on their own cadence. No hosted-CI dependency — see §7.
- **Migration:** a user **on a custom domain** can move between instances in under 15 minutes of active work, with their address unchanged (Phase 6 deliverable). A user on the instance's own domain cannot meet this NFR — they accept an address change, get a forwarding window, and we say so plainly in onboarding (§5.2a explicitly).
- **API stability:** once frozen in Phase 5, the public HTTP API follows semver per §11.13 / ADR-0031: minor versions are non-breaking, breaking changes ship only in new majors with ≥6 months of overlap, and the previous major emits `Deprecation` and `Sunset` headers during the window.
- **Browser-stack auditability:** the bundled JS that touches keys or plaintext is **under 200 KB unminified** and built reproducibly from a single `esbuild` invocation inside the Containerfile build, with no transitive npm postinstall scripts. SRI hashes are committed. Anyone can reproduce the exact bundle byte-for-byte from a clean checkout with only `docker` installed. This is the operational form of P11's "small browser" promise — it is reviewable in an afternoon.

## 11. Architectural decisions

This section captures every architectural choice that affects the shape of the product. Each decision is committed and gets its own ADR for the long-form rationale; the entries here are the summary plus enough detail to build against. Decisions are grouped by topic.

### 11.1 Cryptography and key handling

- **Private key handling: client-only custody.** The user's PGP private key is generated in the browser and encrypted with a passphrase-derived key (Argon2id). The encrypted private key is stored only in two places, both controlled by the user: (a) IndexedDB on each device where the user has chosen to set the account up (the "remember on this device" affordance, §5.3) and (b) a recovery `.asc` file downloaded at signup, mandatory before the signup flow completes (§5.2a step 7). **The server never holds the private key, in any form.** Only the public key is uploaded — the server needs it for WKD publishing and for auto-attaching to outbound mail. *Why this over a server-side encrypted blob:* (a) the server is not a centralized brute-force target — an attacker who compromises the server walks away with public keys, mail content, and metadata, but not private-key material that could be cracked offline at leisure; (b) the tampered-blob attack (server hands the client a substituted encrypted private key on login) is removed from the threat model entirely; (c) it aligns the storage model with what the principle "the user owns their key" actually means — the user holds their key, the way they hold their `gpg` private key on their own machine; (d) the operational trade-off — second-device setup requires importing the recovery file once, and IndexedDB wipes require the same — is acceptable for the techie audience this product targets (§2 P8) and is honest about what the user is responsible for. The previously-considered "encrypted blob on the server" alternative is documented in ADR-0010 with the reasons it was rejected; the JavaScript-tampering vector remains the dominant residual risk and is mitigated by SRI, strict CSP, the no-third-party-scripts rule, and the small auditable browser-stack footprint (§10, P11). ADR-0010.
- **OpenPGP key defaults.** Curve25519 — ed25519 for signing, cv25519 for encryption. RSA-4096 supported only as legacy import; we do not generate RSA keys. ADR-0011.
- **Key-rotation attestation protocol.** Shape committed (§11.10, ADR-0028): when the user rotates their key, attestations signed by the *outgoing* key — covering `(old fp, new fp, monotonic counter, timestamp)` — travel as headers on outbound mail for a 90-day window. Receiving clients verify against the cached old key and silently update; lost-key rotations fall back to TOFU. Wire format and exact header layout still need a written ADR before Phase 6 code lands.
- **Identity model: key-as-identity, address-as-attribute.** The user's identity is their long-lived OpenPGP key fingerprint. Addresses are mutable attributes of an identity — a user can hold one or many addresses, and addresses can be added, removed, or migrated without breaking the identity. The export format and migration flow are designed around this. ADR-0014.

### 11.2 Authentication and session model

- **Login secret.** A user has a *login passphrase* (HTTP-layer authentication) distinct from their *PGP passphrase* (browser-side key decryption). The login passphrase is Argon2id-hashed on the server. They are deliberately separate so a compromise of one does not imply compromise of the other; in practice a user may set them to the same value, which we discourage in onboarding but do not prevent. ADR-0015.
- **Sessions.** Cookie-based, server-side session store (Postgres). HttpOnly, Secure, SameSite=Lax. Sliding expiry only: a session expires after `session_expiry_days` days of inactivity (default 7); there is no hard expiry ceiling. "Remember me" is implicit (sliding window) — there is no separate long-lived-token flow. Logout invalidates the session row server-side; concurrent sessions are allowed and listed in account settings **by last-seen timestamp only** — neither the IP nor the user agent is recorded, in line with the pseudonymity-by-default property in §1 and §4. Operators who explicitly enable IP logging at the instance level (a config-file flag, off by default, §5.4) get IP/UA columns surfaced in the same settings page; users on such an instance see exactly what is being stored about them. ADR-0015.
- **2FA on login.** TOTP support is in scope for v1, opt-in per user, set up in account settings. WebAuthn / hardware-key 2FA is Phase 7 (alongside YubiKey unlock of the PGP key). SMS 2FA is explicitly ruled out, consistent with §5.4's "no phone number." ADR-0015.
- **CSRF.** Standard double-submit cookie or per-request token; not deciding the exact mechanism here, but every state-changing endpoint requires it. The HTTP API consumed by `partials.js` follows the same rule. ADR-0015.
- **Content Security Policy.** Strict, by default: no inline scripts, no inline styles, no third-party origins, `frame-ancestors 'none'`. The crypto pages additionally serve a stricter policy that allows the pinned OpenPGP.js and WASM Argon2id (via SRI) and nothing else. Exact directives live in the implementation, not this plan. ADR-0016.

### 11.3 Addresses, aliases, multiple identities

- **Multiple addresses per user account.** A single user account / single PGP key can be associated with one or many addresses. Example: Alice has `alice@personal.example`, `alice@work.example`, and `a@a.li` — all bound to the same account, the same inbox, the same PGP key. Each address can be on the instance's primary domain or on any verified custom domain the user (or operator) controls. The user picks a default From address; other addresses are selectable per-message in the compose page. ADR-0017.
- **Plus-addressing.** `alice+anything@domain` routes to `alice@domain`. Standard RFC 5233 sub-addressing. No configuration needed; works for every address by default. Users can filter on the tag in the local part for their own organization (filtering itself is Phase 7+). ADR-0017.
- **Address aliases (non-plus).** Independent aliases like `support@domain` → `alice@domain` are supported. Per-user, configurable by the user in account settings; operator-configurable at the domain level via `psql` for things like `postmaster@` and `abuse@`. Aliases share the inbox, the key, and the identity of their target user. ADR-0017.
- **Catch-all on custom domains.** `*@alice.com → alice` is supported as an opt-in per-domain setting. Off by default (catch-alls attract spam); when enabled, a per-domain rate-limit and an obvious indicator in the inbox row ("via catch-all: `random-thing@alice.com`") let the user manage the noise. The catch-all routes to one user — there is no "round-robin to admins" feature in v1. ADR-0017.
- **Reserved local-parts.** Every domain managed by an instance reserves `postmaster@`, `abuse@`, `hostmaster@`, and `webmaster@` as required/conventional addresses. These are auto-created and route to the operator's user account (or to a configured fallback address) on instance setup and on every custom-domain verification. The operator cannot disable them; they're RFC-required and DMARC-aggregate-report-required. ADR-0018.

### 11.4 SMTP listener and transport policy

- **Ports.** 25 (inbound MX), 465 (submission, implicit TLS), 587 (submission, STARTTLS). Plain port 25 submission is not offered — the instance does not relay for arbitrary clients. ADR-0019.
- **Authentication on submission ports.** Required, always. Login passphrase, same credential as the web UI. (For now; SASL XOAUTH or app-passwords are Phase 7+ if and only if a third-party IMAP-or-similar client story emerges, which §3 explicitly defers.)
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
- **Search.** Phase 5: client-side full-text index, decrypted in the browser, never sent to the server. The server provides only the message ciphertexts and metadata.

### 11.6 Storage

- **Database.** PostgreSQL. SQLite was previously listed as "optional for single-user installs"; we drop that. Postgres on a single machine is operationally simple enough that maintaining two storage backends is not worth it. Single-user instances get the same Postgres container; resource footprint (§10) is still met. ADR-0022.
- **Migrations.** `golang-migrate`. Both `golang-migrate` and `goose` are fine; we pick `golang-migrate` and stop debating. ADR-0022.
- **Blob storage.** Raw RFC 5322 messages (encrypted or not, as received) are stored on the filesystem with content-addressed paths (`/blobs/sha256/ab/cd/abcdef...eml`). Postgres holds metadata and references to the blob. v1 is filesystem-only; an S3-compatible interface is a Phase 7+ option if anyone wants it. ADR-0022.
- **Server-side encryption at rest.** Out of scope for the message store — PGP-encrypted messages are already encrypted; plaintext messages received from the outside world are stored as received (this matches every other mail server). DKIM private keys, session secrets, and ACME account keys *are* encrypted at rest with a server master key, which lives in an env var / Docker secret loaded at startup and never persisted to disk by the server itself. **User PGP private keys are not in this list because they are not on the server at all** (§11.1). Losing the master key bricks the instance for the server-side secrets it protects (DKIM, sessions, ACME) but does not put user mailboxes at risk in the way a traditional webmail compromise would. Operators back the master key up. ADR-0023.

### 11.7 DNS, TLS, and WKD

- **WKD method.** **Advanced method only** (`openpgpkey.<domain>/.well-known/openpgpkey/<domain>/...`). The direct method on the apex makes operating a separate web service on the apex domain harder for users with their own websites. The advanced method's CNAME-to-our-host approach is what makes per-user custom domains tractable. ADR-0024.
- **ACME challenge type.** HTTP-01 for the instance's primary domain; HTTP-01 for `mta-sts.<custom-domain>` and `openpgpkey.<custom-domain>` (both reached via CNAME to our infrastructure, so HTTP-01 works without registrar API access). We do not require DNS-01, which would force operators to integrate with registrar APIs. ADR-0024.
- **MTA-STS policy mode.** `enforce` once a domain is fully verified. `testing` mode is available as a per-domain override for the first 48 hours after activation; the UI explains the trade-off (strict = inbound mail fails if our TLS breaks; testing = TLS failures only get reported). ADR-0024.
- **DKIM key strength and rotation.** Ed25519 DKIM signatures (RFC 8463) primary, RSA-2048 fallback for receivers that don't grok ed25519 (still common). Each domain has both, published under distinct selectors. Manual rotation tooling in Phase 7. ADR-0024.

### 11.8 Registration, abuse, and the operator model

- **One role: user. There is no in-app admin.** The system has a single application-level role — *user*. The **operator** is whoever has shell access to the VPS; they have root and they have `psql`, and that is enough. There is no admin web UI, no in-app admin login, no admin role flag in the database. Anything an admin "would have done" is either (a) a user-facing action the user does themselves in the web UI, or (b) something the operator does on the box via documented commands. This is a hard simplification and a real principle (P10). ADR-0008.
- **Registration.** Invite-only, always. There is no open-registration mode and no config knob to enable one — the abuse risk on a pseudonymous, IP-log-free instance is not a trade-off worth offering. Invite tokens are rows in an `invites` table; the operator creates them via `./scripts/new-invite.sh` (a thin `psql INSERT` wrapper). User-issued invites are a Phase 7+ option; not in v1. ADR-0008.
- **Custom-domain registration.** Users add their own custom domains via the web UI (§5.2b), always. There is no operator-managed-only mode and no per-instance policy toggle. The server generates DKIM keypairs, provisions ACME, and logs DNS records when the user completes DNS verification through the UI. Operators can also insert domain rows directly via `psql` for advanced cases (e.g. pre-registering a domain before inviting the user), but the web UI flow is the supported path.
- **Outbound spam abuse.** Per-user and per-instance rate limits (§11.4) are enforced unconditionally. Beyond that, anomaly detection lives in **Prometheus metrics** (outbound volume per user, bounce rate, recent rejection codes) and **structured logs** — the operator can `grep`, alert via their existing Alertmanager rules, or write small queries against the metrics. There is no "anomaly dashboard" page we ship; if the operator wants one, they wire up Grafana against the metrics endpoint. The point is: the operator already has these tools; we don't reinvent them.
- **Account suspension.** Suspending a user is a flag on the user row (`suspended_at`). Set the column via `psql` (or `./scripts/suspend-user.sh`); the server checks the flag on every inbound and outbound operation. Suspended accounts cannot send or receive (inbound rejected at SMTP time with `550 5.7.1 Account suspended`, producing a normal bounce; outbound attempts fail with a clear error in the user's web UI). Suspension is reversible by clearing the flag. ADR-0025.
- **First-user bootstrapping.** On a fresh instance, the first user account must come from somewhere. The operator creates it with `./scripts/new-invite.sh` (which writes an invite row to the DB and prints the invite URL to stdout), then visits that URL in their browser like any other invited user. No special bootstrap dance, no `is_admin` column to set. This is the same flow every subsequent user takes; the first user just happens to also be the operator. ADR-0008.

### 11.9 Account deletion and data retention

- **User-initiated account deletion.** A user can delete their own account from settings. The flow requires the login passphrase **and a proof-of-key-control** (the client signs a server-issued nonce with the user's private key, which requires the PGP passphrase to unlock — same effect as the old "type both passphrases" UX, but it works under the client-only-key model since the server has no encrypted blob to test the passphrase against), plus a typed-out confirmation, plus a 7-day grace period during which the account is suspended but not yet purged. During grace the user can cancel; the account also goes "hold" if there are unread messages from the past 24 hours (a soft tripwire to avoid impulsive deletion). ADR-0026.
- **What deletion removes.** All messages (encrypted blobs and metadata), the user's stored **public** key, all addresses and aliases owned by the user, the user's known-keys cache, all DKIM keys for domains exclusively owned by this user (if no other user uses the domain), all session rows, and the user record itself. There is no encrypted private-key blob to remove — the server never had one (§11.1). Backups created before deletion will still contain the user's server-side data until they age out; we document this. The user's *own* IndexedDB and recovery file are theirs to deal with; deleting the account does not reach into their devices. ADR-0026.
- **What deletion does not remove.** Bounced/DSN copies of mail this user sent that ended up in *other users'* inboxes are not chased down — they are the recipients' mail. Public-key copies that have been auto-attached to past outbound messages are obviously in the wild forever; that is the nature of having published a key, and we say so.
- **Operator-initiated deletion.** The operator can delete a user (e.g. for abuse) via `./scripts/delete-user.sh <address>`, which writes a tombstone row and starts the same purge sequence as user-initiated deletion (minus the grace period — the operator made an explicit choice). A `DELETED` tombstone with the timestamp, the operator's hostname/user, and a reason string is retained for audit. ADR-0026.
- **Domain deletion.** Removing a custom domain from the instance requires no users to be using it for any address. If users are using it, they must remove or migrate those addresses first. We do not orphan-delete addresses behind a user's back. ADR-0026.
- **Data retention defaults.** No automatic purge of any mail beyond Trash (§11.5). Sent mail, received mail, drafts: all retained until the user deletes them or the account is deleted. This is policy, not technical limit — operators with regulatory needs can change it. We document it explicitly. ADR-0026.
- **GDPR / data-subject requests.** Out of scope to provide a tooling answer for every regulation, but the architecture supports the basics: export (Phase 5 mailbox-export covers right-to-data-portability), deletion (above covers right-to-erasure). Operators in regulated jurisdictions are responsible for their own compliance; we document what the software does and doesn't do. ADR-0026.

### 11.10 Key rotation, backup, smarthost — architectural commitments

Three items were "genuinely open" earlier in the planning process. The *shapes* are now committed; the wire formats and exact specifications still need their own ADRs before the relevant phases.

**Key-rotation attestation protocol** [ADR-0028, needed before Phase 6]

When a user rotates their PGP key (planned rotation, or because the old one was compromised), their past correspondents need to learn the new key automatically — without falling back to "manually call your friend and read fingerprints" and without silently accepting an attacker's swap. The committed shape:

- Attestations are **message headers**, signed by the *outgoing* (old) key, attached to outbound mail for a configurable window after rotation (default 90 days).
- An attestation covers `(old fingerprint, new fingerprint, monotonic counter, timestamp)`. The counter increments per rotation and prevents replay of older attestations.
- Receiving clients verify the attestation against the cached old key, update their known-keys cache to the new key, and surface a small unobtrusive notice ("This contact rotated their key on date X, verified by their previous key"). No yes/no prompt — verified means trusted.
- **Lost-key fallback.** If the user has lost the old key entirely (no signature possible), the rotation falls back to TOFU: correspondents see the same "first seen" yellow badge as for a brand-new contact. We do not try to invent a recovery path; §11.1 already commits to single-device, no-recovery, and key rotation inherits that property.
- **Out of scope for the shape (handled in the ADR):** wire format and exact header name; behaviour under concurrent rotations on different devices (mostly prevented by single-device design, but the ADR should specify); whether attestations are also published via WKD (probable answer: no — WKD serves the *current* key only, attestations belong in-band with messages).

The ADR will be drafted and reviewed before Phase 6 code lands. This is real cryptographic protocol design and the shape commits us to "in-band, signed by old key, monotonic" but the wire-level details deserve their own document.

**Backup format and encryption** [ADR-0029, needed before Phase 5]

The "single command produces an encrypted, restorable backup" NFR (§10) is now spec'd at the shape level:

- **Format:** a single `.tar.zst` archive containing (a) `pg_dump --format=custom` of the `rookery` database, (b) the content-addressed blob storage tree, (c) a small `manifest.json` with schema version, rookery version, and a list of included paths. **The backup does not — and cannot — contain user PGP private keys**: those live in users' browsers and recovery files (§11.1), not on the server. Restoring from a backup gives users back their mailboxes, addresses, and metadata; users still need their recovery files to actually decrypt past mail. We document this clearly so operators do not develop a false sense of having a complete user-data backup. A "complete" backup from any user's perspective is *the server backup plus that user's own recovery file* — and the recovery file is their responsibility, by design.
- **Encryption:** the archive is encrypted with **age** (https://age-encryption.org/) to an operator-provided age recipient public key. The recipient public key is configured in `rookery.toml`; the corresponding age identity (private key) is held *by the operator*, off the server. This survives loss of the server master key — and the server master key being lost is precisely when a backup matters.
- **Why age over GPG:** smaller dependency surface, simpler key format, modern crypto defaults, and the backup recipient is unambiguously distinct from a PGP user-identity key (which would invite confusion). The rest of the project uses OpenPGP because that is what email and PGP/MIME require for interop; backups are a local disaster-recovery artifact and have no such constraint.
- **Why not encrypt with the server master key:** because the master key is on the server, and losing the server is the disaster the backup must survive.
- **Bundled scripts:** `./scripts/backup.sh` produces a timestamped archive on stdout (or to a path); `./scripts/restore.sh` consumes it on a fresh instance. Both are thin wrappers (`pg_dump | age -r ... | zstd > backup.tar.zst.age`).
- **Automated verification:** the test harness generates a throwaway age keypair, runs a backup against a seeded instance, spins up a fresh instance, restores, and asserts that key invariants hold (users, messages, addresses, blobs all present and decryptable). This is the "automated restore-from-backup test" the NFR commits to. It lives in the repo as a scripted, container-driven test that anyone with `docker` installed can run; release tagging requires running it. No dependence on a hosted CI provider, in keeping with §7.
- **Out of scope for the shape (handled in the ADR):** archive layout details, exact pg_dump options, blob deduplication strategy for incremental backups (v1 is full-backup only; incremental is Phase 7 if anyone wants it).

**Smarthost integration shape** [ADR-0030, Phase 7]

Smarthosts are an optional outbound relay (e.g. AWS SES, Postmark) that operators can opt into when their VPS's IP reputation makes direct delivery unreliable (§9.1). The committed shape:

- **Opt-in, off by default.** A `rookery.toml` block (`[smtp.smarthost]`) is absent by default and the server delivers mail directly. Setting `enabled = true` plus host/port/username — and providing `ROOKERY_SMTP_RELAY_PASSWORD` as an env var — switches the server to relay mode.
- **Per-instance scope.** One smarthost configuration applies to all outbound from the instance. Not per-domain, not per-user. If an operator needs different smarthosts for different domains, they can run multiple instances, or — more realistically — wait until v1+ proves the demand. Per-instance keeps the config small and the DKIM story consistent.
- **DKIM signs first, then handoff.** rookery signs every outbound message with the user's domain DKIM key *before* handing it to the smarthost. The smarthost is opaque transport. This means: (a) the From-domain DKIM signature is what receivers verify, so DMARC alignment works without published smarthost keys; (b) operators can swap smarthost providers (or drop the smarthost) without anything about message authentication changing; (c) the smarthost cannot impersonate the user cryptographically — only relay what we've already signed.
- **What the smarthost sees:** the message envelope (From, To, Subject, Date, all standard headers) and the message body. For PGP-encrypted mail, the body is the encrypted blob — useful privacy property. For non-PGP outbound (which exists: replies to plaintext senders, mail to addresses without published keys), the smarthost sees plaintext, same as any other SMTP hop. We document this clearly so operators choosing a smarthost choose one they trust.
- **Out of scope for the shape (handled in the ADR):** retry behaviour when the smarthost itself is down (probably: queue locally and retry, same as direct delivery, but with different timeouts); whether to support multiple smarthost providers as failover (probable answer: no in v1, yes in Phase 7+ if anyone asks); exact `rookery.toml` schema for the smarthost block.

**Still genuinely deferred:**

- *(none at present — the project name was the last remaining identity-level deferral and is settled, see the note at the top of this document.)*

### 11.11 Configuration model

The instance is configured via a **mix of environment variables (for secrets) and a config file (for everything else)**, mounted into the container.

- **Config file:** `rookery.toml`, mounted at `/etc/rookery/rookery.toml`. Contains the primary domain, Let's Encrypt contact email, the per-instance policy toggles (open registration, custom-domain self-service), quota defaults, rate-limit overrides, paths to data directories, log verbosity. The file is short and heavily commented. Example file lives in the repo and is the canonical schema reference. Changes to the file require a server restart in v1; hot-reload is not in scope. ADR-0027.
- **Environment variables (secrets only):**
  - `ROOKERY_DB_PASSWORD` — Postgres password. The connection URL is not configurable — rookery always connects to `postgres://rookery:<password>@postgres:5432/rookery`. Only the password varies, and it is always generated automatically by `secrets-init` on first `compose up`.
  - `ROOKERY_MASTER_KEY` — server master key (§11.6). Generated on first run if absent and printed to the log with a one-time "back this up" notice; on subsequent runs the operator provides it.
  - `ROOKERY_SESSION_KEY` — HMAC key for session cookies. Same generate-on-first-run pattern.
  - `ROOKERY_SMTP_RELAY_PASSWORD` — optional, only if a Phase 7 smarthost is configured.
- **Why this split:** secrets stay out of the config file so it's safe to commit a sanitized example, version-control the config alongside the compose file, etc. Everything that isn't a secret is in the config file because env vars don't scale well past about a dozen settings.
- **What's deliberately not configurable in v1:** the SMTP port set (always 25/465/587), the WKD method (always advanced), the database engine (always Postgres). Locking these down keeps the config schema small.

### 11.12 Operator runbook

The shape of "the operator does ops from the shell" is concrete: a small set of shipped scripts and a documented set of `psql` queries. The scripts live in the server image at `/opt/rookery/scripts/` and in the repo at `/scripts/` so they're easy to inspect before running.

**Shipped scripts (v1 minimum):**

| Script | What it does | Implementation shape |
|---|---|---|
| `new-invite.sh [validity_days]` | Generate a new invite URL | `psql -c "INSERT INTO invites ..." \| printf` |
| `suspend-user.sh <address>` | Mark a user suspended | `psql -c "UPDATE users SET suspended_at = now() WHERE primary_address = ..."` |
| `unsuspend-user.sh <address>` | Reverse the above | `psql -c "UPDATE users SET suspended_at = NULL WHERE ..."` |
| `delete-user.sh <address> [reason]` | Operator-initiated deletion (§11.9) | calls a small server endpoint at `localhost:internal-port` that runs the same deletion logic the user flow would, or directly writes tombstone + triggers purge |
| `print-dns.sh [domain]` | Print the DNS records required for a domain (defaults to primary) | reads from `domains` table, formats output |
| `print-deliverability-stats.sh` | Quick summary of recent outbound stats | a couple of `SELECT count(*) FROM messages WHERE ...` queries |
| `rotate-master-key.sh` | Rotate the server master key | documented procedure: re-encrypt DKIM private keys, session secrets, and ACME account keys under the new master; replace env var; restart. (No user PGP private keys to re-encrypt — they are not on the server, §11.1.) |

**Documented `psql` queries** for everything not covered by a script. The deployment guide includes a "common operator tasks" section with copy-pasteable queries: list users, change a user's quota, find a message by ID, view the outbound queue, expire old sessions, etc. The point is *the data model is meant to be readable and writable by hand*; queries are not workarounds, they're the supported interface.

**Constraint this places on the data model:** every operator-meaningful state change must be expressible as a small set of row updates that preserve invariants. Adding a user requires inserting into one table; suspending requires updating one column; deleting requires marking a tombstone and letting the server's purge worker handle the rest. If we ever find ourselves writing "the operator should run these seven `INSERT`s in this order," that's a design smell and the schema needs flattening.

**What the scripts are *not*:** they are not a long-running CLI tool, they are not a separate Go binary, they do not maintain their own state. They are thin shell wrappers around `psql` (and occasionally `curl localhost:<port>/internal/...` for operations that need server cooperation). Anyone reading them should be able to understand what they do in 30 seconds. ADR-0027.

### 11.13 HTTP API contract

The HTTP API is the actual product surface (P6, P1, ADR-0006). The web UI is its first consumer, not a privileged one. The contract below is what Phase 5 formally freezes; the *shape* is committed now, the exact endpoint list lives in the Phase 0 API sketch under `/docs/`.

- **Versioning in the URL path.** All API routes live under `/api/v1/...`. Future major versions get `/api/v2/...`. URL path versioning was chosen over `Accept` header versioning for ergonomics — `curl` users and humans reading logs can see the version at a glance, which matters more for a project whose audience reads access logs. ADR-0031.
- **Semver.** The API version `v1` is a major; we ship minor versions inside it. Adding optional request fields, adding response fields, adding endpoints, adding new error codes — all non-breaking, fine in minor versions. Removing fields, changing field types, changing semantics, removing endpoints, repurposing error codes — all breaking, requires `v2`.
- **Deprecation window.** Breaking changes ship in a new major (`/api/v2/`) and the previous major is supported for **at least 6 months** after the new major's release. During that window, `v1` endpoints emit a `Deprecation` and `Sunset` header per RFC 8594. We never silently break.
- **Error format.** All error responses share a stable JSON shape: `{"error": {"code": "<stable_string_code>", "message": "<human readable>", "details": {...}}}`. The `code` is the part API clients pattern-match on; it never changes meaning within a major version. The `message` is for humans and may be tweaked freely. Error codes are documented per-endpoint.
- **Authentication for browser clients:** cookie-based session, same as the web UI (§11.2). The web UI calling `/api/v1/...` is the same as any other API consumer with a session cookie.
- **Authentication for programmatic clients:** **per-user API tokens.** A user generates a token in account settings, gives it a name and an optional expiry, and the server returns the token once (the user copies it; we never show it again). Tokens are stored hashed (Argon2id, same as login passphrases) server-side. Sent as `Authorization: Bearer <token>`. Each token has scopes — at minimum `read`, `send`, `admin` (admin here = settings/keys/etc., not instance-admin which doesn't exist per §11.8). Tokens are revocable from the same settings page; revocation is immediate. **Tokens do not unlock the PGP private key.** Programmatic clients that need to decrypt or sign must hold the user's PGP passphrase themselves and perform crypto locally — same constraint as the web UI, just in a different runtime. This is the architectural reason the future Unix-tools client (§8 Phase 8+) is possible: it gets an API token for transport and uses local `gpg` for crypto. ADR-0031.
- **Rate limiting.** API endpoints are rate-limited per-user (and per-token where applicable). Limits are the same as the SMTP outbound limits in §11.4 for send-mail endpoints; read endpoints get a generous default (e.g. 600 req/min/user) intended to catch loops, not legitimate use. 429 responses include a `Retry-After` header. Specific numbers go in the operator-tunable config; the ADR locks in the *shape* (per-user limits, 429 with Retry-After, configurable).
- **Idempotency.** State-changing endpoints (`POST /messages` to send, `POST /invites`, etc.) accept an optional `Idempotency-Key` header. The server caches the response for 24 hours keyed by `(user, idempotency_key)`. Retrying with the same key returns the cached response; without a key, retries can duplicate. This makes the API safe for a CLI client to retry on network failure.
- **Pagination.** Cursor-based, never offset-based. List endpoints return `{"items": [...], "next_cursor": "<opaque>"}`; clients pass `?cursor=<opaque>` to get the next page. Cursor format is opaque to clients and may change between minor versions. Page size defaults to 50, max 200.
- **What the API does *not* include in v1:** webhooks (Phase 7+ if anyone wants them — operators currently get the same info from Prometheus metrics and structured logs), GraphQL (we are not adding a second query language), batch endpoints (multiple operations per request — defer until a real use case appears).

### 11.14 Spam filtering

Spam filtering in v1 is **rspamd with stock defaults**. The goal is "reasonable out-of-the-box behaviour for a small instance," not "Gmail-quality classification." Per §9.2 we are honest that good spam filtering is ongoing operational work, not a problem we solve in v1.

- **Spam filter:** rspamd, bundled in the deployment. ADR-0032.
- **Backing store:** Redis, bundled as a sidecar container (rspamd requires it for bayes, fuzzy, ratelimits, and several other modules). The compose file ships Redis alongside rookery and rspamd; operators don't see Redis as a separate operational concern.
- **Virus scanning:** ClamAV is **opt-in, off by default.** Per §10 RAM budget, enabling ClamAV adds ~1 GB; instances running on a 2 GB VPS cannot afford it. Operators with headroom flip a flag in `rookery.toml`.
- **Action thresholds:** rspamd's own defaults (`reject` ≥15, `add header` 6-15, `greylist` ~4-6, no-action below). These are well-tuned by the rspamd project and we don't second-guess them in v1.
- **Bayesian training: not in v1.** No "mark as spam" button in the inbox UI. No `learn_spam` / `learn_ham` feedback loop. Stock rspamd does plenty without bayes (header heuristics, RBLs, SPF/DKIM/DMARC alignment, URL reputation, neural network module on by default). Per-user bayes training, the "mark as spam" UX, and the resulting training pipeline are deliberately Phase 7+ work — they touch the inbox UI, the storage model, *and* the spam pipeline simultaneously, which is too much surface for v1.
- **Operator overrides.** The shipped rspamd config lives at `/etc/rspamd/local.d/` inside the container; operators who want to tune anything mount a volume over it. Documented in the operator runbook. The bundled scripts do not include rspamd-tuning helpers — that's outside our scope; the operator uses `rspamc` directly (`docker compose exec rspamd rspamc ...`).
- **What this means for users in v1.** Spam goes to the **Trash** virtual view (§11.5), not a separate Spam folder — keeping the mailbox model flat. The `X-Spam-Status` header rspamd adds is preserved and visible in the message detail view, so curious users can see the score. Mail tagged `add header` (medium-confidence spam) lands in Inbox with a visible "possible spam" badge; mail tagged `reject` is rejected at SMTP time and never enters storage.
- **What this is *not*:** a long-term spam strategy. v1 ships rspamd and walks away. Phase 7+ revisits training, per-user models, the Spam folder vs Trash question, and the "mark as spam" UI as a coherent piece of work.

### 11.15 UI visual direction

The v1 UI is server-rendered HTML styled with a single hand-written stylesheet (§7). The visual direction is committed at the principle level here so that PRs, future contributors, and reviewers have a stable reference point and the UI does not drift towards consumer-webmail polish by accident. The lineage we target is **the techie-utility homepage** — `archlinux.org`, `voidlinux.org`, `man.archlinux.org`, `suckless.org` — pages that are dense with information, light on decoration, and read like well-laid-out documentation rather than marketing.

Concrete commitments:

- **Light, neutral palette, one muted accent.** Near-white background (not pure `#FFFFFF` — slightly off, like Arch's), near-black body text, a single low-saturation accent colour for links, headings, and the small handful of status indicators that need to stand out (encrypted-vs-plaintext badges, send-button state). No second accent. No gradients. No drop shadows. No glassmorphism.
- **No dark mode in v1.** A single, well-tuned light theme is more honest than two half-tuned themes. Dark mode is Phase 7+ if it earns its place; the audience overlap with people who run `redshift` / `f.lux` / OS-level inversion is high enough that we don't urgently need to ship our own. **Exception:** we use `prefers-color-scheme` only to set sensible system-cursor and form-control defaults; we do not produce a custom dark stylesheet.
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

### 11.16 Decisions deliberately not made here

A short list of things this section intentionally does not pin down, because they're implementation details that can be decided at coding time without rippling through the architecture:

- Exact CSP header strings.
- Exact CSRF token mechanism (double-submit vs SameSite-only vs synchronizer-token).
- Specific Argon2id parameters (memory, iterations, parallelism) — there are good defaults; we'll pick current OWASP recommendations and revisit.
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
scripts/                   # operator shell scripts (new-invite.sh, suspend-user.sh, etc.) — §11.12. Mirrored into the container image at /opt/rookery/scripts/
web/static/                # hand-written CSS, partials.js (hand-written), the bundled crypto JS module, pinned OpenPGP.js + WASM Argon2id (vendored, SRI-locked)
web/partials/              # source for partials.js — hand-written, no build step, ships as-is
web/crypto/                # source for the JS crypto module (bundled by esbuild — esbuild runs *inside* the Containerfile build, never on the developer's host; see §7)
compose.yaml               # dev server, test runner, linter, mailpit — single entry point
rookery.toml.example       # annotated config file schema
Containerfile              # the build. Multi-stage: Go compile + esbuild for the crypto JS + distroless final image. `docker build` on a clean checkout produces the deployable image.
docs/
  adr/                     # architecture decision records
  ops/                     # deployment, DNS, TLS, runbook docs
PLAN.md                    # this file
README.md                  # quickstart with compose snippet
SECURITY.md                # threat model + reporting (Phase 5)
LICENSE                    # AGPLv3
```

No `rookery-cli` binary: operator ops are shell scripts (§11.12), not a separate Go program.

## 13. ADR index and starting work

### ADR index

The ADRs below capture the decisions made across this plan. They are listed here for traceability; each one becomes a short document under `/docs/adr/`. **ADRs 0001–0009 (the architectural foundations) are written before Phase 1 code lands** — they are short, they're already decided in this plan, and committing them as standalone documents grounds future PRs in stated decisions rather than vibes. The remaining ADRs can be written when their topic comes up, except where a phase's deliverable explicitly requires one first (ADR-0028 before Phase 6, ADR-0029 before Phase 5, ADR-0031 before the Phase 5 API freeze, ADR-0032 before Phase 4). The plan itself is the canonical record until each ADR is written.

**Architectural foundations:**
- `ADR-0001` — PGP-first mail server speaking standard SMTP; no new wire protocols.
- `ADR-0002` — Server-rendered HTML, hand-written JS only (crypto + partials); no SPA, no HTMX, no third-party clients in v1.
- `ADR-0003` — Single-device, no account recovery.
- `ADR-0004` — Key discoverability: WKD + auto-attach on outbound; Autocrypt later.
- `ADR-0005` — Operator UX as first-class concern, but operator works from the shell; no admin web UI; 30-minute active-time-to-instance NFR.
- `ADR-0006` — Deliberately replaceable: standards-compatible formats, documented HTTP API from day one, no lock-in.
- `ADR-0007` — Custom domains are a v1 feature with per-domain MTA-STS/TLS-RPT/ACME and a kill switch.
- `ADR-0008` — One in-app role (user). No admin in the app; the operator works from the shell. Invite-only registration; first user is created via `new-invite.sh` like any other user.
- `ADR-0009` — Desktop-first, mobile-tolerated.

**Cryptography:**
- `ADR-0010` — Private key handling: client-only custody (IndexedDB + user-held recovery file; server never holds the private key). Records the rejected "encrypted blob on the server" alternative and the reasons.
- `ADR-0011` — OpenPGP key defaults: Curve25519 (ed25519 + cv25519); RSA legacy import only.

**Frontend & dependencies:**
- `ADR-0012` — No HTMX; in-house `partials.js`; HTML-fragment endpoints.
- `ADR-0013` — Aggressive dependency minimalism / supply-chain posture.

**Identity & addresses:**
- `ADR-0014` — Identity model: key-as-identity, address-as-attribute.
- `ADR-0015` — Authentication: login passphrase + cookie sessions, 2FA (TOTP) opt-in, CSRF protection, no SMS.
- `ADR-0016` — Content Security Policy: strict by default, stricter on crypto pages.
- `ADR-0017` — Address model: multiple addresses per user, plus-addressing, non-plus aliases, opt-in catch-all on custom domains.
- `ADR-0018` — Reserved local-parts (`postmaster`, `abuse`, `hostmaster`, `webmaster`).

**SMTP, storage, transport:**
- `ADR-0019` — SMTP listener policy: ports, TLS, auth requirements, mail-size limits, bounce policy.
- `ADR-0020` — Outbound rate limits (per-user, per-instance).
- `ADR-0021` — Mailbox model: flat list with virtual views, soft-delete trash, per-user quota.
- `ADR-0022` — Storage: Postgres + content-addressed filesystem blobs; `golang-migrate` for migrations.
- `ADR-0023` — Server master key: scope, encryption-at-rest policy, operator responsibility.
- `ADR-0024` — DNS, TLS, WKD: advanced-method WKD only, ACME HTTP-01, MTA-STS mode handling, DKIM ed25519+RSA.
- `ADR-0025` — Account suspension flow.

**Account lifecycle:**
- `ADR-0026` — Account deletion and data retention.

**Operator interface:**
- `ADR-0027` — Configuration model (env + config file split) and operator runbook (shell scripts + documented `psql` queries; no admin web UI; no separate CLI binary).

**Shape-committed; wire format and exact spec deferred to the ADR document:**
- `ADR-0028` — Key-rotation attestation protocol. In-band message headers signed by the outgoing key, covering `(old fp, new fp, monotonic counter, timestamp)`; lost-key fallback to TOFU. Wire format TBD. [needed before Phase 6]
- `ADR-0029` — Backup format and encryption. `tar.zst` of `pg_dump` + content-addressed blob tree, encrypted with `age` to an operator-provided recipient public key. Bundled `backup.sh` / `restore.sh`. Verified roundtrip via in-repo test (container-driven, no hosted-CI dependency, §7). [needed before Phase 5]
- `ADR-0030` — Smarthost integration shape. Opt-in (off by default), per-instance scope, rookery signs DKIM before handoff (smarthost is opaque transport). [Phase 7]

**Public interface and bundled services:**
- `ADR-0031` — HTTP API contract: `/api/v1/` URL versioning, semver + 6-month deprecation window, stable JSON error format, cookie sessions for browsers + per-user Bearer tokens (hashed, scoped, revocable) for programmatic clients, cursor pagination, idempotency keys on state-changing endpoints. Tokens never unlock the PGP private key. [needed before Phase 5 freeze]
- `ADR-0032` — Spam filter: rspamd + bundled Redis, stock defaults, ClamAV opt-in (off by default for the 2 GB RAM budget). No Bayesian training UI in v1; no "mark as spam" button. Spam routed to Trash, not a separate Spam folder. Operator tunes via mounted volume over `/etc/rspamd/local.d/`. Training UX and per-user bayes are Phase 7+. [before Phase 4]

### Concrete starting work

1. Add `LICENSE` (AGPLv3).
2. Scaffold the Go module, `chi` HTTP server with `/healthz`, multi-stage Containerfile (the build, §7), thin Makefile wrapper. No hosted-CI config — the project is forge-agnostic.
3. Stand up `compose.yaml` with Postgres and `mailpit` for local SMTP testing.
4. Sketch the HTTP API resource model (users, messages, keys, domains, addresses, invites) as a reviewable document under `/docs/`. This is the artifact the "deliberately replaceable" principle (§2, P6) demands; it should exist on paper in Phase 0, not be reverse-engineered in Phase 5.
5. **Write the foundational ADRs (0001–0009) before non-trivial code lands** — this is a hard prerequisite for Phase 1, not a "should." The rest of the ADRs can be written when their topic comes up, except where a phase's deliverable requires one first (see the ADR index above).
