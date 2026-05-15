# Pitch — rookery for security-minded readers

This document is the short version of why `rookery` exists, written for someone
who already knows what PGP, WKD, SMTP, and a KDF are. It is not marketing prose.
If you want the full design, read [PLAN.md](../PLAN.md). If you want the
user-facing summary, read [README.md](../README.md).

---

## The 30-second version

Self-hostable PGP-first email server in one container. The server never holds
the user's private key, not even encrypted — it lives only in a recovery file
the user controls. Authentication is challenge/response signed by the key, so
the server has no password hash either. A full breach of the box leaks
ciphertext and public metadata, and **zero authentication material**.
Standards-only: SMTP, OpenPGP (RFC 9580), WKD, Autocrypt, DKIM/SPF/DMARC,
MTA-STS. No novel crypto, no federation protocol, no SPA.

That paragraph is the entire pitch. Everything below is the follow-up.

---

## The properties that actually matter

Stated as post-breach guarantees, because that is the language the threat model
is written in.

1. **Server compromise leaks no login credentials.** No passphrase, no
   passphrase hash, no encrypted private key on disk. Auth is a nonce signed
   by the user's PGP key; the server only stores the public half (which it
   publishes via WKD anyway). Compare to the common "encrypted blob on the
   server" webmail model, where a breach plus offline GPU cracking against
   the KDF *is* the attack.
2. **Server compromise cannot retroactively decrypt PGP-encrypted bodies.**
   Standard E2E property, but worth stating.
3. **Server compromise cannot forge signed mail from users.** Signing keys
   are not on the server.
4. **Subpoena resistance is a property of the data model, not a policy.**
   The operator cannot hand over private keys or passphrase hashes — they
   do not exist on the box. They can hand over ciphertext, envelope
   metadata, and the public key. That is the whole set.
5. **No PII at signup.** No name, phone, or recovery email. Connecting IPs
   are not logged by default on the web UI or the submission ports. The
   account *is* the keypair.
6. **No lock-in, deliberate replaceability.** Keys are standard OpenPGP,
   exportable to and importable from `gpg`. WKD records are standard.
   Custom domains mean the user's address survives leaving the instance:
   change MX + DKIM CNAMEs, import the mailbox archive, done.

## The honest trade-offs

Naming the downsides up front is part of the pitch.

- **Lose the recovery file or passphrase → mail is gone.** No reset, no
  rescue. The server has nothing to give back. This is the cost of
  property (1).
- **Metadata leaks are not solved.** From / To / Subject / timestamps and
  the `Received:` chain are visible to the recipient's server and the
  network path. PGP does not hide subjects; we do not pretend it does.
- **Browser-side crypto is the most security-sensitive code in the
  project, and we say so.** OpenPGP.js is the single browser dependency —
  SRI-pinned, no transitive `postinstall` scripts, dependency list
  reviewed periodically.
- **While logged in, your private key is in browser `localStorage` in
  plaintext.** The AES-GCM session-key wrapping is an ergonomic measure,
  not a cryptographic barrier — the wrapping key and blob coexist at the
  same origin, so anything that can read browser storage (another user on
  the same OS account, a malicious extension, remote access) can recover
  the private key during an active session. The server never holds the
  key; the risk is local and session-scoped. Logout clears it completely.
  **Log out on shared or untrusted machines.** The UI surfaces this
  warning at login and in settings.
- **A malicious server can still serve tampered JS on next login.** That
  is the unavoidable webmail caveat. The mitigation is operator
  accountability — i.e. running your own instance — not technical magic.
- **Deliverability from a fresh IP is hard.** Standard IP-reputation
  reality. Documented in the README; smarthost support is on the Phase 7
  roadmap. The same `[smtp.smarthost]` config block accepts either a
  commercial relay (SES, Postmark, Mailgun) or a *relay rookery* — another
  rookery instance acting as upstream. The wire shape is identical SMTP
  submission; rookery signs DKIM with the user's domain key *before*
  handoff, so the smarthost cannot impersonate users cryptographically and
  operators can swap one for the other without changing message
  authentication. The relay-rookery arrangement is bilateral and
  configured out of band; there is no rookery federation protocol, no
  directory, no auto-discovery — two instances relay between each other
  the way any two SMTP systems do.

## How it differs from the adjacent options

**vs. Proton / Tutanota / Mailbox.org.** Those are one company, one trust
anchor, encrypted-blob model. `rookery` is self-hosted, has no encrypted
private key on the server at all, and uses standards-compatible keys that
exit cleanly to `gpg`. The trust target is the operator (often: yourself),
not a vendor.

**vs. Postfix + Dovecot + Roundcube + Mailvelope.** That stack works, but
the cost is not the weekend it takes to stand up — it is the indefinite tax
of staying competent at seven moving parts (`main.cf`, Dovecot config,
nginx vhosts, opendkim, certbot, rspamd Lua, an IMAP-aware PGP plugin),
each with its own config language, upgrade cycle, and CVE feed. `rookery`
collapses that to one Go binary plus Postgres, one TOML config file, and
one rebuild command (`git pull && docker compose up -d --build`; the
Containerfile is the build, no registry round-trip). DKIM, ACME, WKD,
MTA-STS, DMARC reporting, Autocrypt and PGP/MIME live inside the binary as
features, not as separate packages. The operator's mental model is the
size of one program. First-run in under 30 minutes is a consequence of
that architecture, not the value proposition.

## The one-line version

> Self-hosted PGP webmail where a server breach cannot decrypt past mail or
> forge user signatures — no passwords, no hashes, no encrypted private keys
> exist on the server. What does leak: envelope metadata, active session tokens,
> and DKIM signing keys. The threat model spells out what is and is not protected.

That sentence is the differentiator. Lead with it.
