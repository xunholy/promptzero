# Marauder — passive / non-offensive flows

Active attacks live under
[`offensive/wifi-attacks.md`](offensive/wifi-attacks.md). This page
collects the passive / setup tools.

All require `--wifi` at launch (or `marauder.enabled: true` in config).

## Confirm the Marauder is there

> *"What firmware is the Marauder running?"*

Fires `wifi_info`. Returns board firmware version + MAC + status.
The REPL `/status` command also shows this at the top.

## Scan (passive)

Access points only:

> *"Scan WiFi access points for 20 seconds"* →
> `wifi_scan_ap(duration_seconds=20)`.

APs + clients:

> *"Scan both access points and client stations for 20 seconds"* →
> `wifi_scan_all`.

Stop early:

> *"Stop scanning"* → `wifi_stop_scan`.

## Review / clear state

> *"Show me the APs you found"* → `wifi_list_aps`.
> *"Show me the client stations"* → `wifi_list_stations`.
> *"Show me the SSID list"* → `wifi_list_ssids`.
> *"Clear the AP list"* → `wifi_clear_aps`.

## Save / load scans

> *"Save the current AP scan to the SD card"* → `wifi_save_aps`.
> *"Load the last saved AP scan"* → `wifi_load_aps`.
> *"Save my SSID list"* / *"Load my SSID list"* →
> `wifi_save_ssids` / `wifi_load_ssids`.

## Settings

> *"Show me all Marauder settings"* → `wifi_settings`.
> *"Set the display brightness setting to 200"* →
> `wifi_set_setting(name=DisplayBrightness, value=200)`.
> *"Switch to WiFi channel 6"* → `wifi_set_channel(channel=6)`.
> *"Reboot the Marauder"* → `wifi_reboot`.

## SSID list management (for later beacon-spam)

> *"Add the SSID 'Test_Net_01' to the beacon spam list"* →
> `wifi_add_ssid(name=Test_Net_01)`.
> *"Generate 50 random SSIDs for spam"* →
> `wifi_generate_ssids(count=50)`.
> *"Remove SSID index 3"* → `wifi_remove_ssid(index=3)`.
