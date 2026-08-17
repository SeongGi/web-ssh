# Security and incident response

## Exposed SSH credential incident (2026-08-13)

An earlier Git revision contained `ssh-servers.tar.gz`. The archive contained three
private SSH keys and an SSH client configuration. Deleting the archive in a later
commit does not remove it from Git history.

Treat every key in that archive as compromised. For each affected server:

1. Create a new key pair on a trusted machine.
2. Add the new public key to the intended account and verify access.
3. Remove the old public key from every `authorized_keys`, cloud metadata, image,
   backup, CI secret, and agent that may contain it.
4. Review SSH authentication and privilege logs from the first exposure time onward.
5. Revoke active sessions and rotate any secret reachable from those accounts.

Changing file permissions or deleting the archive is not a substitute for key
rotation. Assume forks, clones, caches, CI artifacts, and container layers may retain
the old data.

The repository history was rewritten on 2026-08-13 to remove
`ssh-servers.tar.gz` and `ssh-export/` from every branch and tag. All collaborators
must re-clone instead of merging from an old clone. Hosting-provider caches, forks,
local clones, CI artifacts, and container layers may still retain the old data, so
key rotation remains mandatory.

## Relevant attack paths

- A reader of the old Git object can extract the archive, derive each public key,
  identify a matching server/account, and authenticate wherever the key remains
  authorized.
- The former fixed `admin/adminpassword` portal credential enabled immediate portal
  takeover on a fresh deployment, followed by access to stored SSH connections.
- Unlimited login attempts enabled online password guessing.
- Returning private keys to the browser expanded exposure to browser extensions,
  injected scripts, screenshots, and client-side logs.
- Plain HTTP exposes terminal traffic and credentials to an on-path observer. Deploy
  behind HTTPS and set `COOKIE_SECURE=true`.
- SSH host keys are not pinned yet, so a first-connection man-in-the-middle remains a
  residual risk. Restrict the portal network path and independently verify remote
  host fingerprints before using privileged accounts.

## Security audit button

The portal can run a read-only posture check against a stored server over SSH
(`POST /api/servers/:id/audit`). What it does and does not do:

- Every probe is read-only. Nothing is installed, written, restarted, or reconfigured.
- Privileged probes go through `sudo -n`, so they fail closed instead of prompting.
  When sudo is unavailable the report says so and falls back to config-file parsing;
  treat those results as weaker evidence than the `sshd -T` effective configuration.
- Each probe has a hard time cap. A probe that times out is reported as
  "확인 불가" rather than being dropped — an audit must never render an unchecked
  item as a clean one.
- The audit reads paths and settings, not file contents of keys or secrets. It reports
  that a private key exists and its mode; it never transmits key material.
- Findings are heuristics, not proof. A default-ACCEPT INPUT policy with a fail2ban
  rule is reported as "no host firewall" because that is what it is, but the operator
  still has to decide whether the cloud security group is sufficient.
- Audit results are only as trustworthy as the server. A compromised host can lie to
  every one of these checks; this is a hygiene tool, not intrusion detection.

## Google login

Google is the only identity provider. Local password authentication was removed: it was
a second, weaker credential guarding the same thing (a root shell on every managed
server), it had to be stored and rotated by hand, and its default-password bootstrap
path caused a live exposure on 2026-08-17. A Google account now grants full portal
access, so:

- The server refuses to *start* unless `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and
  an allow list (`GOOGLE_ALLOWED_EMAILS` or `GOOGLE_ALLOWED_DOMAINS`) are all present.
  Without an allow list any Google account on the internet would be accepted, and
  because this is the only login path, a partially configured portal that still serves
  traffic could be mistaken for a healthy one. Failing closed at boot is deliberate.
- The allow list is environment-only and has no UI. A hijacked session therefore cannot
  widen who may log in.
- There is no stored credential, so there is no password to leak, rotate, or brute
  force. Account lockout, throttling and MFA are Google's responsibility.
- Losing access is recovered by fixing the environment and restarting — not through the
  UI. Portal lockout does not affect SSH access to the managed servers themselves.
- Only accounts whose email Google reports as verified (`email_verified`) pass.
- ID tokens are validated against Google's JWKS (RS256 signature, `iss`, `aud`, `exp`,
  `iat`, `nonce`) rather than being trusted as received.
- The authorization request carries `state` (CSRF), `nonce` (replay), and PKCE S256.
- `GOOGLE_CLIENT_SECRET` is a credential. Keep it in the environment or a secret
  manager, never in the repository, and rotate it in the Google Cloud console if it
  leaks.
- Prefer an `Internal` OAuth consent screen when the portal serves a single Workspace
  organization, and keep the allow list as narrow as possible.
- Removing an account from the allow list blocks future logins but does not end
  sessions already open; restart the service to drop in-memory sessions.
- A leftover `auth.json` from a password-login release is deleted at startup so a
  no-longer-honoured hash does not linger in the data volume.

## Deployment requirements

- Configure Google login fully before first start; the server refuses to boot without
  a client ID, a client secret, and an allow list. There is no local password to set.
- Keep `/app/data` in a protected volume; files are created with owner-only access.
- Never commit `data/`, `.env`, SSH exports, archives, private keys, or backups.
- Put the service behind an authenticated HTTPS reverse proxy or private VPN; do not
  expose port 3000 directly to the public internet.
- Backups contain credentials and must be encrypted with separately managed keys.
