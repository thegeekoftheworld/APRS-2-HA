# APRS → Home Assistant Control Gateway (`aprs-ha-gw.c`)

A single-file C program that lets you **control and query Home Assistant over APRS messaging** (via APRS-IS).  
Send APRS messages from your callsign (ex: `CALLSIGN-8`) to your gateway callsign (ex: `CALLSIGN`) and it will run pre-defined Home Assistant actions and reply with results.

✅ One-file project: `aprs-ha-gw.c`  
✅ Uses APRS-IS (TCP) for message RX/TX  
✅ Uses Home Assistant REST API (token)  
✅ Uses 6-digit TOTP as a one-time password (valid time window)  
✅ Per-sender authorization window (`auth`) for 5 minutes  
✅ OTP lockout: 1 OTP-validated command per sender per 60 seconds  
✅ Strips APRS message IDs like `{6}` / `{23}` so `IST{6}` works  
✅ Auto reloads `config.ini` every 10 seconds if changed  
✅ Auto reconnects APRS-IS if APRS config changes  
✅ Debug flag `-3` (or `-d`) shows verbose logs

---

## How it works

### Message formats

**1) Authenticate / authorize (required first):**
```
<OTP6> auth
```
Example:
```
926223 auth
```
If the OTP is valid, the gateway replies:
```
OK authorized 5 min
```
This authorizes **only the exact sender callsign** (e.g., `CALLSIGN-8`) for **5 minutes**.

**2) During the 5-minute authorization window (no OTP needed):**
```
view <ITEM>
toggle <ITEM>
on <ITEM>
off <ITEM>
set <ITEM> <VALUE>
```

Examples:
```
view IST
toggle PORCH
on KITCHEN
off PORCH
set THERM 70
```

**3) OTP lockout**
After a sender successfully uses an OTP, **that same sender** cannot use another OTP for **60 seconds**.  
(Authorized commands during the 5-minute window still work without OTP.)

---

## What gets accepted

### Callsign restriction

The program only accepts messages from senders whose **base callsign** matches:

`allowed_base_callsign = CALLSIGN`

That means:
- ✅ `CALLSIGN`
- ✅ `CALLSIGN-7`
- ✅ `CALLSIGN-14`

But not:
- ❌ `KJ7XYZ-9`

---

## Home Assistant “items” (abbreviations)

You define short item codes in the config like:

- `IST` = inside temp
- `PORCH` = porch light
- `THERM` = thermostat

The sender uses these abbreviations in APRS messages.

---

## Requirements

### System packages (Debian/Ubuntu)

```bash
sudo apt-get update
sudo apt-get install -y build-essential libcurl4-openssl-dev libssl-dev
```

---

## Build

From the folder containing `aprs-ha-gw.c`:

```bash
gcc -O2 -Wall -Wextra -o gw aprs-ha-gw.c -lcurl -lssl -lcrypto
```

---

## Install layout (recommended)

```
/opt/aprs-ha-bridge/gw
/opt/aprs-ha-bridge/config.ini
```

Example:

```bash
sudo mkdir -p /opt/aprs-ha-bridge/
sudo install -m 0755 ./gw /opt/aprs-ha-bridge/gw
sudo cp ./config.ini /opt/aprs-ha-bridge/config.ini
```

---

## Configuration

Create:

`/opt/aprs-ha-bridge/config.ini`

### Sample config (edit values!)

```ini
[aprs]
server = rotate.aprs2.net
port = 14580
login_callsign = CALLSIGN ; Replace with your actual callsign
aprs_passcode = 000000 ; Replace with your actual APRS passcode
filter = m/CALLSIGN

[security]
allowed_base_callsign = CALLSIGN ; Replace with your actual callsign
totp_secret_base32 = JBSWY3DPEHPK3PXP ; This is the base32-encoded secret for TOTP. You can generate it using a TOTP app or library.
totp_step_seconds = 30
totp_accept_steps = 1

[homeassistant]
base_url = http://192.168.1.100:8123 ; Replace with the actual URL of your Home Assistant instance
token = ENTER_YOUR_LONG_LIVED_ACCESS_TOKEN_HERE ; Replace with your actual long-lived access token

; ---------- ITEMS ----------
; Sensors can be read via "view"
[item_IST]
type = sensor
entity_id = sensor.inside_temperature
format = IST=%s

; Switch (generic)
[item_PORCH]
type = switch
entity_id = switch.porch_light
service_toggle = homeassistant/toggle
service_on = homeassistant/turn_on
service_off = homeassistant/turn_off

; Light domain (recommended explicit services)
[item_KITCHEN]
type = light
entity_id = light.kitchen
service_toggle = light/toggle
service_on = light/turn_on
service_off = light/turn_off

; Thermostat setpoint example
[item_THERM]
type = climate
entity_id = climate.house
service_set = climate/set_temperature
set_field = temperature
```

### How to get APRS passcode
APRS-IS passcodes are derived from the callsign. Many online calculators exist.
Use your existing passcode workflow.

### How to get Home Assistant token
Home Assistant:
- Profile (your user) → **Long-Lived Access Tokens** → Create token
- Paste it into `token = ...`

---

## Running

### Normal run
```bash
/opt/aprs-ha-bridge/gw /opt/aprs-ha-bridge/config.ini
```

### Debug run (recommended while testing)
```bash
/opt/aprs-ha-bridge/gw -3 /opt/aprs-ha-bridge/config.ini
```

Debug shows:
- APRS-IS login and logresp
- Incoming messages parsed
- Authorization windows
- HA API calls and responses

---

## Testing workflow (step-by-step)

1) Start gateway in debug:
```bash
gw -3 /opt/aprs-ha-bridge/config.ini
```

2) From your APRS radio/client (sender callsign like `CALLSIGN-8`), send a message **to the gateway callsign** (example gateway is `CALLSIGN`):
```
<OTP6> auth
```

3) Gateway replies:
```
OK authorized 5 min
```

4) Now send commands without OTP for 5 minutes:

**Read inside temp**
```
view IST
```

**Toggle porch switch**
```
toggle PORCH
```

**Turn kitchen light on**
```
on KITCHEN
```

**Set thermostat to 70**
```
set THERM 70
```

---

## Light support (Home Assistant `light.*`)

Home Assistant lights use the `light` domain.  
These services are valid and recommended in config:

- `light/toggle`
- `light/turn_on`
- `light/turn_off`

Example item:

```ini
[item_KITCHEN]
type = light
entity_id = light.kitchen
service_toggle = light/toggle
service_on = light/turn_on
service_off = light/turn_off
```

### Optional: brightness via `set`
You can map `set` to light brightness (0–255) by using `light/turn_on` with a brightness field:

```ini
[item_KITCHENB]
type = light
entity_id = light.kitchen
service_set = light/turn_on
set_field = brightness
```

Then send:
```
set KITCHENB 128
```

---

## Live config reload (10 seconds)

The gateway checks the config file every **10 seconds**:
- If the file changed, it reloads it
- All items/security/HA token update immediately
- If APRS server/login values changed, it auto-reconnects APRS-IS

This makes it easy to tweak item mappings without restarting.

---

## APRS message-id suffix `{NN}`

Many APRS clients append a message ID like `{6}` at the end of the text.
Example received:
```
926223 view IST{6
```

This gateway automatically strips it so item lookup works.

---

## Security notes / recommendations

- Use a strong, private TOTP secret.
- Keep the HA token private and restrict it to minimum permissions.
- Consider using a dedicated HA user for the token.
- This gateway accepts only your base callsign (and any SSID), which reduces exposure.
- OTP commands are rate-limited (60 seconds per sender) to reduce brute forcing.

---

## Example systemd unit (optional)

Create:
`/etc/systemd/system/aprs-ha-gw.service`

```ini
[Unit]
Description=APRS to Home Assistant Gateway
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/opt/aprs-ha-bridge/gw /opt/aprs-ha-bridge/config.ini
Restart=always
RestartSec=3
User=aprs2ha

[Install]
WantedBy=multi-user.target
```

Enable/start:
```bash
sudo useradd aprs2ha
sudo systemctl daemon-reload
sudo systemctl enable --now aprs-ha-gw
sudo systemctl status aprs-ha-gw
```

---

## Troubleshooting

### “ERR unknown item”
- Confirm you have `[item_XXX]` in config and that you’re sending `XXX`
- If your APRS client appends `{6}`, the gateway strips it automatically (this is supported)

### “ERR not authorized”
- You need to run:
  ```
  <OTP6> auth
  ```
  from that sender callsign first

### “ERR bad OTP”
- Check TOTP secret base32 in config
- Check system clock (NTP must be correct)

### HA read/service failing
- Confirm `base_url` is reachable from the host running the gateway
- Confirm HA token is valid and has permissions
- Confirm entity_id exists (check HA Developer Tools → States)

### APRS-IS login problems
- Verify callsign/passcode are correct
- You should see `logresp` output after connecting

---

## GitHub repository suggestion

Repo structure:

```
.
├── aprs-ha-gw.c
├── README.md
└── config.sample.ini
```

