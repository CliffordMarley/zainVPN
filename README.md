# zainVPN

A minimal Radmin/Hamachi-style virtual LAN for playing LAN games (e.g. Blur) with friends over the internet.

```
 [Your PC]                      [AWS: coordinator]                  [Friend's PC]
 zainVPN app + service ─TCP 29814─► Docker container ◄─TCP 29814─ zainVPN app + service
 adapter 10.77.0.1                - assigns 10.77.0.x               adapter 10.77.0.2
        │                         - shares endpoints                        │
        │                         - UDP 29814 relay fallback                │
        │                         - serves the installer (21958)            │
        └────────────── direct UDP, encrypted (hole-punched) ───────────────┘
```

- **Coordinator**: a small Go server running in Docker on your AWS instance. It admits devices to networks, gives each device a fixed virtual IP, helps peers connect directly, and relays traffic when a direct connection isn't possible. On port 21958 it serves an admin dashboard, and its sign-in page offers the Windows installer for download.
- **Client**: a desktop app, zainVPN, plus a background Windows service that runs a virtual network adapter (Wintun). Broadcast and multicast packets are copied to every friend, so LAN game discovery works. Closing the window leaves the VPN running.
- **Invite codes**: one person creates a network in the app and gets a code like `blur-7K3M-9X2Q-8W4T`. Friends paste the code to join. The random part of the code is the secret: traffic is end-to-end encrypted with a key derived from it (Argon2id + XChaCha20-Poly1305). The coordinator only sees a one-way fingerprint of the code, so it can't read traffic or recover the code.
- **Installer**: built automatically on the server by `deploy.sh`. It only contains the coordinator address, so it's safe to share publicly.

## 1. Deploy the coordinator on AWS

**Security group** (and ufw, if it's enabled): open these inbound ports.

| Port | Protocol | Source | Used for |
|---|---|---|---|
| 29814 | TCP + UDP | 0.0.0.0/0 | clients' control connection, relay, hole punching |
| 21958 | TCP | 0.0.0.0/0 | installer download page, password-protected admin dashboard |

With ufw: `sudo ufw allow 29814 && sudo ufw allow 21958/tcp`. Give the instance an Elastic IP so its address doesn't change.

**On the instance:**

```bash
git clone https://github.com/CliffordMarley/zainVPN.git && cd zainVPN
bash deploy.sh
```

`deploy.sh` does the following:
- installs Docker if it's missing;
- pulls the latest code and builds the coordinator;
- cross-compiles the Windows app and packages the installer with NSIS, with this server's public IP built in;
- (re)starts the container.

On the first run it creates `.env` with a random admin password and prints it. To update later, push your changes and run `bash deploy.sh` again; every deploy also produces a fresh installer.

- Logs: `docker logs -f zainvpn-coordinator`
- State and any uploaded installer live in the `zainvpn-data` Docker volume.
- If you connect through a DNS name, set `ZAINVPN_PUBLIC_ADDR` in `.env` (see `.env.example`) so installers use it.

## 2. Play

1. Open `http://<server-ip>:21958/` and click **Download zainVPN for Windows**. Send friends the same link.
2. Run the installer, approve the admin prompt, and pick a nickname.
3. Open zainVPN from the Start menu:
   - You: **Create network**, type a name such as `blur`, and send friends the invite code it shows.
   - Friends: paste the code under **Join network**.
4. In Blur, choose LAN. Games hosted by friends appear automatically. If a game asks for an IP address, use the host's virtual IP (10.77.0.x) from the Players list.

## Troubleshooting

- **The installer or zainVPN is blocked with "An Application Control policy has blocked this file".** Smart App Control is on for that PC, and it blocks unsigned programs. Turn it off in *Windows Security → App & browser control → Smart App Control*. The permanent fix is to code-sign the exes.
- **SmartScreen says "Windows protected your PC".** Click **More info → Run anyway**. This appears because the installer isn't code-signed.
- **"That invite code has a typo".** The code's built-in check character didn't match. Copy and paste the code instead of retyping it.
- **Friends can't see my game.** Allow the game through Windows Firewall when asked. If you clicked Cancel earlier, open *Windows Defender Firewall → Allow an app* and tick both boxes for the game. zainVPN already allows all inbound traffic from 10.77.0.0/24.
- **Connection shows "Relayed".** This is normal behind strict or carrier-grade NAT. The game still works, with a bit more latency.
- **Stuck on "Connecting".** Check the security group and ufw for TCP and UDP 29814, then look at the log at `C:\ProgramData\zainVPN\zainvpn.log` (also shown under **Logs** in the app).
- **Command line** (as administrator): `zainvpn status`, `zainvpn stop`, `zainvpn install`, `zainvpn run`.

## Building on Windows (optional)

`.\build.ps1 -Server <ip>` builds `dist\zainVPN-Setup.exe` locally. It needs Go and NSIS: `winget install GoLang.Go NSIS.NSIS`. Add `-Publish` to upload the result to the dashboard. The server already builds the installer, so this is only for testing.

## Uninstall

*Settings → Apps → zainVPN → Uninstall* removes the app, the service, the adapter, the firewall rule, the driver and `C:\ProgramData\zainVPN`.

## Layout

```
cmd/zainvpn/          Windows service + CLI + local UI (served on 127.0.0.1:7779)
cmd/zainvpn-app/      desktop window (WebView2) showing that UI
cmd/zainvpn-server/   coordinator entry point
internal/proto/       wire format, invite codes, crypto
internal/server/      coordinator core (control, relay, state)
internal/dashboard/   coordinator dashboard + installer download
internal/client/      client engine (paths, hole punching, routing)
installer/            NSIS script, icon, exe resource definitions
third_party/wintun/   signed Wintun driver (redistributable)
Dockerfile, deploy.sh coordinator + installer build and deployment
```
