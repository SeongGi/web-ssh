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

## Deployment requirements

- Set a unique `ADMIN_PASSWORD` of at least 12 characters before first start.
- Keep `/app/data` in a protected volume; files are created with owner-only access.
- Never commit `data/`, `.env`, SSH exports, archives, private keys, or backups.
- Put the service behind an authenticated HTTPS reverse proxy or private VPN; do not
  expose port 3000 directly to the public internet.
- Backups contain credentials and must be encrypted with separately managed keys.
