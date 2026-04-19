# WiFi / BLE attacks (ESP32 Marauder)

All tools on this page require the ESP32 Marauder devboard connected
via USB. Start `promptzero` with `--wifi` (or set
`marauder.enabled: true` in your config). When the Marauder isn't
connected, the agent doesn't see these tools at all.

> **Not tested on the hardware used for this documentation** —
> the test bench ran Flipper-only. The prompts below are derived
> from the tool schemas and should be verified in your own lab.

## Scan nearby APs

> *"Scan for WiFi access points for 20 seconds"* →
> `wifi_scan_ap(duration_seconds=20)`.

Scan APs + stations together:

> *"Scan both WiFi access points and client stations for 20 seconds"*
> → `wifi_scan_all`.

## Target selection → attack

The flow is always **scan → list → select → attack**:

> *"Scan APs for 15 seconds, list them, select index 2, then deauth
> its clients for 30 seconds"*

Chain: `wifi_scan_ap` → `wifi_list_aps` → `wifi_select_ap(indices=2)`
→ `wifi_deauth(duration_seconds=30)`.

Select all APs with `indices="all"`.

## Capture PMKID → hashcat

> *"Sniff PMKID hashes on channel 6 for 60 seconds"* →
> `wifi_sniff_pmkid(flags="-c 6", duration_seconds=60)`.

Full pipeline (scan → strongest AP → PMKID capture → hashcat file):

> *"Run the WiFi-to-hashcat workflow — scan for 20s, capture PMKID
> for 30s, write the hash to /ext/wifi/hashcat.22000"*
> → `workflow_wifi_target_to_hashcat(scan_seconds=20,
> capture_seconds=30, output_path=…)`. Classified `critical`.

## Evil portal

> *"Start the evil portal with /ext/apps_data/evil_portal/corp.html"*
> → `wifi_evil_portal_start(filename=corp.html)`.

Generate a page first:

> *"Generate a corporate WiFi portal page and deploy it, then start
> the evil portal"* → `generate_evil_portal(…, deploy=true)` →
> `wifi_evil_portal_start`.
> ([generation transcript 23](../../transcripts/23-gen-evil-portal.json))

Stop: *"Stop the evil portal"* → `wifi_evil_portal_stop`.

## Beacon spam variants

- *"Broadcast 50 random WiFi beacons for 30 seconds"* →
  `wifi_generate_ssids(count=50)` → `wifi_beacon_spam`.
- *"Flood the area with the Rickroll beacons"* →
  `wifi_beacon_rickroll`.
- *"Clone SSIDs from nearby APs and spam them"* →
  `wifi_beacon_clone`.

## BLE spam

> *"BLE-spam Apple devices for 30 seconds"* →
> `wifi_ble_spam(mode=apple, duration_seconds=30)`.

Valid modes: `apple`, `google`, `samsung`, `windows`, `flipper`,
`all`.

## Sniffing

- `wifi_sniff_beacon` — beacon frames.
- `wifi_sniff_probe` — probe requests (reveals what networks
  devices are hunting for).
- `wifi_sniff_deauth` — detect active deauth attacks in the area.
- `wifi_sniff_pwnagotchi` — pwnagotchi handshake ads.
- `wifi_sniff_bt` — Bluetooth targets (airtag | flipper | flock |
  meta).
- `wifi_sniff_skimmer` — Bluetooth credit-card skimmers.
- `wifi_sniff_raw` — all 802.11 packets on the current channel.

## Network recon after joining

> *"Join AP index 3 with password 'letmein', then ping-scan the
> network"* → `wifi_join(ap_index=3, password=letmein)` →
> `wifi_ping_scan`.

> *"ARP-scan and port-scan IP 0"* → `wifi_arp_scan` →
> `wifi_port_scan(ip_index=0)`.

## MAC manipulation

- *"Randomise the Marauder MAC"* → `wifi_random_mac`.
- *"Clone AP index 2's MAC"* → `wifi_clone_mac(ap_index=2)`.

## Marauder system

- *"What firmware is the Marauder running?"* → `wifi_info`.
- *"Reboot the Marauder"* → `wifi_reboot`.
- *"Set WiFi channel to 11"* → `wifi_set_channel(channel=11)`.
