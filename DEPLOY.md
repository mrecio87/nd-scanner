# Deploying a new appliance, start to finish

Split into two phases. **Do everything in Phase 1 at your office**, on your own
network — it needs internet, and it needs GitHub credentials you should not be
typing on a client site. Phase 2 is what you do on the client's premises.

---

## Phase 1 — Build the appliance (at the office)

### 1. Install Debian

Debian 12 (bookworm) or newer. Two choices during the installer that are hard to
change afterwards:

- **Enable full-disk encryption.** Choose *Guided — use entire disk and set up
  encrypted LVM*. These boxes travel and can be stolen; disk encryption is the
  control that keeps a lost appliance from handing over its password, the
  TLS key, and any client findings still on disk. You cannot retrofit this
  without reinstalling.
- **Skip the desktop environment.** Under *Software selection*, untick everything
  except *SSH server* and *standard system utilities*. Nothing here needs a GUI,
  and a smaller install leaves more resources for scanning.

Create your technician user during install.

### 2. Install git and Docker

```bash
sudo apt-get update && sudo apt-get install -y git ca-certificates curl
```

```bash
sudo install -m 0755 -d /etc/apt/keyrings && sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc && sudo chmod a+r /etc/apt/keyrings/docker.asc && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null && sudo apt-get update && sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

### 3. Let your user run Docker

```bash
sudo usermod -aG docker $USER
```

**Then log out and back in.** The group membership does not apply to your current
session, and `setup.sh` will complain if you skip this.

### 4. Clone the repository

```bash
git clone https://github.com/mrecio87/nd-scanner.git netscan-appliance && cd netscan-appliance
```

The public repository needs no authentication. Cloning the **private** one asks
for credentials: username `mrecio87`, and the password field wants a **personal
access token**, not your account password.

If you do clone the private repository from an appliance, use a **fine-grained
token scoped to read-only Contents on that repository only** — not a classic token
with full `repo` scope. And do not run `git config credential.helper store` on an
appliance: it writes the token in plaintext to `~/.git-credentials`, so a stolen
box hands over your GitHub access along with everything else.

### 5. Run setup

```bash
./setup.sh --prompt
```

You are asked for a password (Enter generates a strong one). This detects the LAN address for the TLS certificate, sets the appliance
password, sets file ownership, builds the image, and starts the web UI.
The first build pulls the scanning tools and ~13,000 nuclei templates, so give it
a few minutes.

It finishes by printing the URL, the password source, and the **certificate
fingerprint**. Note the fingerprint.

### 6. Check it works before you leave

Browse to the URL it printed, compare the certificate fingerprint, log in with the
password you set, and run a **Quick look** scan against something harmless on your
own network. Confirm a report renders.

An appliance that has never been logged into is not a tested appliance.

### 7. Optional: trust the certificate

Worth doing only if someone other than you will be looking at the screen — it
removes the browser warning and adds no security. Copy `certs/appliance.crt` to
the machine you browse from and import it into its trusted-root store. Never copy
`appliance.key`.

---

## Phase 2 — On the client site

### 1. Place and power the box

It can only scan what it can route to, so put it on the segment being assessed.

### 2. Confirm its address

If the appliance gets a different IP than it had at the office, the certificate no
longer matches and the browser warns even if you trusted it. Fix it in one command:

```bash
./setup.sh
```

It re-detects the address, regenerates the certificate, and restarts. A DHCP
reservation avoids the issue entirely.

### 3. Scan

Open `https://<appliance-ip>:8080`, sign in, enter the authorised ranges, and run
a **Quick look** first — it takes a couple of minutes and tells you whether you can
actually reach the targets. Then run the real scan.

### 4. Deliver

Open the report and use **Print / Save as PDF**.

### 5. Decommission before the box leaves

`output/` holds that client's complete vulnerability map. It must not travel to the
next client:

```bash
docker compose down && rm -rf output/scan-*
```

`setup.sh` refuses to run on a box that still has another client's results, but do
not rely on that as your only control.

---

## If the client site has no internet

Phase 1 already handled it — the image is built and the templates are baked in, so
the appliance scans fine with no egress. Nothing in Phase 2 needs internet.

The only thing you lose is `NUCLEI_UPDATE=true` for fresh templates. Rebuild at the
office periodically instead.

## Deploying several appliances

Do Phase 1 once, then clone the disk. Each imaged box needs only:

```bash
cd netscan-appliance && ./setup.sh
```

to pick up its own address and certificate. That also avoids putting GitHub
credentials on every box.

Each imaged box keeps the password baked into the image. To give one its own,
run `./setup.sh --prompt` on it.
