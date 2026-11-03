# zainVPN

A minimal Radmin/Hamachi-style virtual LAN for playing LAN games (e.g. Blur) with friends over the internet.

```
 [Your PC]                    [AWS: coordinator]                [Friend's PC]
 zainVPN service  ──TCP 29814──►  Docker container  ◄──TCP 29814──  zainVPN service
 adapter 10.77.0.1               - assigns 10.77.0.x               adapter 10.77.0.2
        │                        - shares endpoints                       │
        │                        - UDP 29814 relay fallback                │
        └───────────── direct UDP, encrypted (hole-punched) ──────────────┘
```

- **Coordinator**: a small Go server running in Docker on your AWS instance. It admits devices to a network, gives each a fixed virtual IP, helps them connect directly, and relays traffic when a direct connection isn't possible. It has an admin dashboard on port 21958.
- **Client**: a Windows service with a virtual network adapter (Wintun). Broadcast and multicast packets are copied to every friend, so LAN game discovery works. A local status page runs at http://127.0.0.1:7779.
- **Installer**: one `zainVPN-Setup.exe` that you send to friends. They install it once, and it starts automatically with Windows after that.

Traffic between friends is end-to-end encrypted (XChaCha20-Poly1305, with the key derived from the network password using Argon2id). The coordinator only stores a hash of a separate token, so it can't read your traffic.

## 1. Deploy the coordinator on AWS

**Security group.** Open these inbound ports on the instance:

| Port | Protocol | Source | Used for |
|---|---|---|---|
| 29814 | TCP | 0.0.0.0/0 | client control connection |
| 29814 | UDP | 0.0.0.0/0 | registration and relay |
| 21958 | TCP | **your IP only** | admin dashboard |

Give the instance an Elastic IP so its address doesn't change. The installers you build contain this address.

**On the instance** (Amazon Linux or Ubuntu):

```bash
git clone <your-repo-url> zainvpn && cd zainvpn
bash deploy.sh
```

`deploy.sh` installs Docker if it's missing, pulls the latest code, builds the image, and (re)starts the container. It also raises the kernel's UDP buffer limits so relayed game traffic isn't dropped. On the first run it creates `.env` with a random dashboard password and prints it.

To update later, push your changes and run `bash deploy.sh` again.

- Logs: `docker logs -f zainvpn-coordinator`
- State: stored in the `zainvpn-data` Docker volume.

## 2. Build the installer (on Windows)

Requires Go and Inno Setup 6.6 or later (`winget install GoLang.Go JRSoftware.InnoSetup`).

```powershell
.\build.ps1 -Server <elastic-ip> -Network blur -Password "something-long"
```

The result is `dist\zainVPN-Setup.exe`. The coordinator address, network name and password are pre-filled in the installer, so friends only choose a nickname. Anyone who has this file can join your network, so share it only with your group. You can also put the defaults in `build.config.json` (see `build.config.example.json`) and run `.\build.ps1` with no arguments.

The network is created the first time someone joins it, using whatever password that person used.

## 3. Install and play

1. Run `zainVPN-Setup.exe`, approve the admin prompt, pick a nickname, and click Next until it finishes.
2. The zainVPN page (Start menu → zainVPN) shows your virtual IP and who's online, and whether each connection is **Direct** or **Relayed**.
3. In Blur, choose the LAN game mode. Games hosted by friends appear automatically. If a game asks for an IP address, use the host's virtual IP (10.77.0.x).

## Troubleshooting

- **Friends can't see my game.** When Windows asks whether to allow the game through the firewall, allow it. If you clicked Cancel earlier, Windows created a block rule: open *Windows Defender Firewall → Allow an app*, find the game, and tick both boxes. zainVPN already allows all inbound traffic from 10.77.0.0/24.
- **The connection shows "Relayed".** This is normal behind strict or carrier-grade NAT. The game still works, with a bit more latency. Choose an AWS region roughly between the players.
- **Status is stuck on "Connecting".** Check that the security group allows TCP and UDP 29814, and look at the log at `C:\ProgramData\zainVPN\zainvpn.log`.
- **"Wrong password for this network".** Someone created the network with a different password. Delete the network in the dashboard and reconnect.
- **Command line** (run as administrator): `zainvpn status`, `zainvpn stop`, `zainvpn install`, `zainvpn run` (run in the foreground for debugging).

## Uninstall

Use *Settings → Apps → zainVPN → Uninstall*. This removes the service, the adapter, the firewall rule, the driver, and `C:\ProgramData\zainVPN`.

## Layout

```
cmd/zainvpn/          Windows client: service, CLI, local UI
cmd/zainvpn-server/   coordinator entry point
internal/proto/       wire format and crypto
internal/server/      coordinator core (control, relay, state)
internal/dashboard/   coordinator admin dashboard
internal/client/      client engine (paths, hole punching, routing)
installer/            Inno Setup script and logo (zainvpn.ico, drawn by mkicon.go)
third_party/wintun/   signed Wintun driver (redistributable)
build.ps1             builds dist\zainVPN-Setup.exe
Dockerfile, deploy.sh coordinator deployment
```
