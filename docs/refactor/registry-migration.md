# Tool-registry migration — runbook

**Branch:** `refactor/tool-registry` (this branch).
**Design artefacts:** `internal/tools/spec.go`, `internal/tools/spec_test.go`.
**Triggered by:** commit `c51cf34` — audit of 7 cross-mode bugs caused by the
three-place tool registration (MCP `s.add`, agent schema `tool(...)`, agent
dispatch `case "name":`).

This runbook is the single source of instructions for the six wave engineers
executing the migration. Each engineer works in an isolated worktree from
this branch's HEAD and reads only this document + their per-wave brief —
they will NOT see the conversation that produced it.

---

## Contents

- **Section A — Inventory.** Every tool, where it lives, its handler.
- **Section B — Wave assignments.** Per-wave tool lists (Waves 0–5).
- **Section C — Migration template.** Worked `device_info` example.
- **Section D — Acceptance criteria.** Per-wave build/test/lint/count gates.
- **Section E — Hardware gate.** The four harnesses the orchestrator runs
  between waves.
- **Section F — Edge cases.** Parsing-in-handler, snapshot-before-write,
  capability gates, synonyms.

---

## A. Inventory

### A.1 — MCP tools (`internal/mcp/server.go`)

125 total `s.add()` calls. All share the same wrapper:

```go
func (s *Server) add(name, desc string, opts []mcp.ToolOption,
                     required []string, handler toolHandler)
```

`toolHandler = func(ctx, args map[string]interface{}) (string, error)`.
Argument helpers: `sa` (string), `na` (float64), `naDefault`,
`naDefaultFloat`, `ba` (bool), `durationParam` (seconds → `time.Duration`).

| MCP tool | file:line | wrapped call |
|---|---|---|
| subghz_transmit | server.go:181 | `f.SubGHzTx(sa(a,"file"))` |
| subghz_receive | server.go:188 | `f.SubGHzRx(uint32(na(a,"frequency")), durationParam(...,30s))` |
| subghz_decode | server.go:198 | `f.SubGHzDecode(sa(a,"file"))` |
| subghz_tx_key | server.go:205 | `f.SubGHzTxKey(sa,uint32(na),uint32(na),int(na))` |
| subghz_rx_raw | server.go:217 | `f.SubGHzRxRaw(uint32(na), durationParam)` |
| subghz_chat | server.go:227 | `f.SubGHzChat(uint32(na), durationParam)` |
| ir_transmit | server.go:238 | `f.IRTxParsed(sa,sa,sa)` |
| ir_transmit_raw | server.go:249 | `f.IRTxRaw(uint32(naDefault), naDefaultFloat, sa)` |
| ir_receive | server.go:262 | `f.IRRx(durationParam(...,30s))` |
| ir_decode_file | server.go:269 | `f.IRDecodeFile(sa(a,"path"))` |
| ir_universal_list | server.go:276 | `f.IRUniversalList(sa(a,"library"))` |
| nfc_detect | server.go:284 | `f.NFCDetect(durationParam(...,30s))` — agent side also parses via `flipper.ParseNFCDetect` |
| nfc_emulate | server.go:291 | `f.NFCEmulate(sa)` |
| nfc_subcommand | server.go:298 | `f.NFCSubcommand(sa, durationParam)` |
| nfc_raw_frame | server.go:308 | `f.NFCRawFrame(sa, durationParam)` |
| nfc_apdu | server.go:318 | `f.NFCAPDU(sa, durationParam)` |
| nfc_mfu_rdbl | server.go:328 | `f.NFCMFURead(int(na), durationParam)` |
| nfc_mfu_wrbl | server.go:338 | `f.NFCMFUWrite(int(na), sa, durationParam)` |
| nfc_dump_protocol | server.go:349 | `f.NFCDumpProtocol(sa(a,"protocol"), durationParam)` — see §F.3 |
| rfid_read | server.go:360 | `f.RFIDRead(ctx, sa, durationParam)` |
| rfid_emulate | server.go:370 | `f.RFIDEmulate(sa,sa, durationParam)` |
| rfid_write | server.go:381 | `f.RFIDWrite(sa,sa)` |
| rfid_raw_read | server.go:391 | `f.RFIDRawRead(sa,sa, durationParam)` |
| rfid_raw_analyze | server.go:402 | `f.RFIDRawAnalyze(sa)` |
| rfid_raw_emulate | server.go:409 | `f.RFIDRawEmulate(sa, durationParam)` |
| ibutton_read | server.go:420 | `f.IButtonRead(durationParam)` |
| ibutton_emulate | server.go:427 | `f.IButtonEmulate(sa,sa, durationParam)` |
| ibutton_write | server.go:438 | `f.IButtonWrite(sa)` |
| gpio_set | server.go:446 | `f.GPIOSet(sa, int(na))` |
| gpio_read | server.go:456 | `f.GPIORead(sa)` |
| badusb_run | server.go:464 | `f.BadUSBRun(sa)` — agent-side adds validator gate (§F.2) |
| list_apps | server.go:472 | `f.LoaderList()` — agent-side uses `f.LoaderListParsed()` + JSON marshal |
| loader_open | server.go:478 | `f.LoaderOpen(sa,sa)` |
| loader_close | server.go:488 | `f.LoaderClose()` |
| loader_info | server.go:494 | `f.LoaderInfo()` |
| loader_signal | server.go:500 | `f.LoaderSignal(int(na), sa)` |
| loader_nfc_magic | server.go:511 | `f.LoaderNFCMagic()` |
| loader_mfkey | server.go:513 | `f.LoaderMFKey()` |
| loader_mifare_nested | server.go:515 | `f.LoaderMifareNested()` |
| loader_picopass | server.go:517 | `f.LoaderPicopass()` |
| loader_seader | server.go:519 | `f.LoaderSeader()` |
| loader_t5577_multiwriter | server.go:521 | `f.LoaderT5577MultiWriter()` |
| loader_subghz_bruteforcer | server.go:523 | `f.LoaderSubGHzBruteforcer()` |
| loader_subghz_playlist | server.go:525 | `f.LoaderSubGHzPlaylist()` |
| loader_protoview | server.go:527 | `f.LoaderProtoView()` |
| loader_spectrum_analyzer | server.go:529 | `f.LoaderSpectrumAnalyzer()` |
| loader_signal_generator | server.go:531 | `f.LoaderSignalGenerator()` |
| loader_nrf24mousejacker | server.go:533 | `f.LoaderNRF24Mousejacker()` |
| loader_uart_terminal | server.go:535 | `f.LoaderUARTTerminal()` |
| loader_spi_mem_manager | server.go:537 | `f.LoaderSPIMemManager()` |
| loader_unitemp | server.go:539 | `f.LoaderUnitemp()` |
| input_send | server.go:543 | `f.InputSend(sa,sa)` |
| storage_list | server.go:554 | `f.StorageList(sa)` |
| storage_read | server.go:560 | `f.StorageRead(sa)` |
| storage_write | server.go:566 | `f.StorageWrite(sa,sa)` — agent uses `StorageWriteCtx` |
| storage_delete | server.go:578 | `f.StorageRemove(sa)` |
| storage_mkdir | server.go:584 | `f.StorageMkdir(sa)` |
| storage_info | server.go:590 | `f.StorageStat(sa)` — agent parses via `flipper.ParseStorageStat` |
| storage_copy | server.go:596 | `f.StorageCopy(sa,sa)` — agent adds snapshot-before-write (§F.1) |
| storage_rename | server.go:605 | `f.StorageRename(sa,sa)` — agent snapshots both ends |
| storage_md5 | server.go:614 | `f.StorageMD5(sa)` |
| storage_tree | server.go:620 | `f.StorageTree(sa)` |
| onewire_search | server.go:628 | `f.OneWireSearch(durationParam)` |
| i2c_scan | server.go:634 | `f.I2CScan()` |
| js_run | server.go:641 | `f.JSRun(sa, durationParam)` |
| device_info | server.go:652 | `f.DeviceInfo()` — **synonym with `system_info` (§F.4)** |
| power_info | server.go:657 | `f.PowerInfo()` |
| device_reboot | server.go:662 | `f.Reboot()` |
| power_reboot_dfu | server.go:667 | `f.PowerRebootDFU()` |
| update_install | server.go:672 | `f.UpdateInstall(sa)` |
| crypto_store_key | server.go:678 | `f.CryptoStoreKey(int(na), sa, int(na), sa)` |
| flipper_raw_cli | server.go:689 | `f.RawCLI(sa)` |
| led_set | server.go:695 | `f.LED(sa, int(na))` |
| vibro | server.go:704 | `f.Vibro(ba)` |
| log_stream | server.go:710 | `f.LogStream(durationParam, sa)` |
| fileformat_read | server.go:734 | `readParsed(path)` → `{format, model}` JSON |
| fileformat_edit | server.go:750 | `readParsed` + `fileformat.ApplyEdits` + `SaveFile` + `StorageWrite` — agent snapshots before write (§F.1) |
| fileformat_diff | server.go:784 | `readParsed(a) + readParsed(b)` → `fileformat.Diff` → JSON |
| badusb_validate | server.go:816 | `f.StorageRead(path)` + `validator.Validate` → JSON |
| workflow_hw_recon_blackbox_device | server.go:842 | `workflows.HWReconBlackbox(ctx, deps, a)` |
| workflow_garage_door_triage | server.go:850 | `workflows.GarageDoorTriage(ctx, deps, a)` |
| workflow_phys_pentest_badge_walk | server.go:861 | `workflows.PhysPentestBadgeWalk(ctx, deps, a)` |
| wifi_scan_ap | server.go:879 | `m.ScanAP(durationParam)` — agent uses `ScanAPParsed` + JSON |
| wifi_scan_all | server.go:885 | `m.ScanAll(durationParam)` |
| wifi_stop_scan | server.go:891 | `m.StopScan()` |
| wifi_list_aps | server.go:894 | `m.ListAPs()` — agent uses `ListAPsParsed` + JSON |
| wifi_list_ssids | server.go:896 | `m.ListSSIDs()` |
| wifi_list_stations | server.go:898 | `m.ListStations()` — agent uses `ListStationsParsed` + JSON |
| wifi_clear_aps / wifi_clear_ssids / wifi_clear_stations | server.go:901-906 | `m.ClearAPs()` / `ClearSSIDs()` / `ClearStations()` |
| wifi_select_ap / wifi_select_station / wifi_select_ssid | server.go:908-925 | `m.SelectAP(sa)` / `SelectStation(sa)` / `SelectSSID(sa)` |
| wifi_deauth | server.go:927 | `m.DeauthAttack(durationParam)` |
| wifi_deauth_station_list | server.go:933 | `m.DeauthToStationList(durationParam)` |
| wifi_beacon_spam | server.go:939 | `m.BeaconSpamList(durationParam)` |
| wifi_beacon_random | server.go:945 | `m.BeaconSpamRandom(durationParam)` |
| wifi_beacon_clone | server.go:951 | `m.BeaconSpamClone(durationParam)` |
| wifi_probe_flood | server.go:957 | `m.ProbeFlood(durationParam)` |
| wifi_csa_attack | server.go:963 | `m.CSAAttack(durationParam)` |
| wifi_sae_flood | server.go:969 | `m.SAEFlood(durationParam)` |
| wifi_sniff_pmkid | server.go:976 | `m.SniffPMKID(int(na), ba, ba, durationParam)` |
| wifi_sniff_beacon / wifi_sniff_deauth / wifi_sniff_probe / wifi_sniff_raw | server.go:987-1010 | `m.SniffBeacon/Deauth/Probe/Raw(durationParam)` |
| wifi_ble_spam | server.go:1012 | `m.BLESpam(sa, durationParam)` |
| wifi_sniff_bt | server.go:1021 | `m.SniffBT(sa, durationParam)` |
| wifi_sniff_skimmer | server.go:1030 | `m.SniffSkimmer(durationParam)` |
| wifi_evil_portal_start | server.go:1037 | `m.EvilPortalStart(sa)` |
| wifi_evil_portal_stop | server.go:1043 | `m.StopScan()` — note: maps to `StopScan`, not a dedicated stop verb |
| wifi_info | server.go:1046 | `m.Info()` |
| wifi_reboot | server.go:1048 | `m.Reboot()` |
| wifi_settings | server.go:1050 | `m.Settings()` |
| wifi_set_setting | server.go:1052 | `m.SetSetting(sa,sa)` |
| wifi_set_channel | server.go:1061 | `m.SetChannel(int(na))` |
| marauder_gps_data / marauder_gps_field / marauder_nmea | server.go:1069-1086 | `m.GPSData()` / `m.GPSField(sa,sa)` / `m.NMEA(durationParam)` |
| marauder_packet_count / marauder_storage_ls | server.go:1088-1095 | `m.PacketCount()` / `m.StorageLS(sa)` |
| marauder_led_set / marauder_led_rainbow | server.go:1098-1105 | `m.LEDSetHex(sa)` / `m.LEDRainbow()` |
| wifi_portscan_service | server.go:1108 | `m.PortScanService(int(na), sa, durationParam)` |

**MCP-only, not in agent:** `marauder_gps_data`, `marauder_gps_field`,
`marauder_nmea`, `marauder_packet_count`, `marauder_storage_ls`,
`marauder_led_set`, `marauder_led_rainbow`, `wifi_portscan_service`.
These will be added to the agent via the registry in Wave 3 — the
original agent-schema omission is coverage drift to fix in passing.

### A.2 — Agent dispatch cases (`internal/agent/agent.go:990..1645`)

163-case switch starting at line 990. Helpers: `str(p,k)`, `intOr(p,k,def)`,
`boolOr(p,k,def)`, `floatOr(p,k,def)`. Each entry below lists the case
line + the one-line body from the switch.

```
 993  subghz_transmit          → a.flipper.SubGHzTx(str(p,"file"))
 995  subghz_receive           → a.flipper.SubGHzRx(uint32(intOr...), ...)
                                  then flipper.ParseSubGHzReceive + JSON
1006  subghz_decode            → a.flipper.SubGHzDecode(str(p,"file"))
1008  subghz_bruteforce        → a.flipper.ExecLong(fmt.Sprintf("subghz bruteforce %s %d", ...))
1012  ir_transmit              → a.flipper.IRTxParsed(str,str,str)
1014  ir_transmit_raw          → a.flipper.IRTxRaw(uint32(intOr...), floatOr, str)
1016  ir_receive               → a.flipper.IRRx(intOr*time.Second)
1018  ir_bruteforce            → a.flipper.ExecLong("ir bruteforce "+SanitizeArg, ...)
1022  nfc_read_save            → a.nfcReadSave(ctx, p)  [agent-only helper, ~95 lines]
1024  nfc_detect               → a.flipper.NFCDetect(...) + ParseNFCDetect + JSON
1032  nfc_emulate              → a.flipper.NFCEmulate(str(p,"file"))
1034  nfc_subcommand           → a.flipper.NFCSubcommand(str, intOr*time.Second)
1038  rfid_read                → a.flipper.RFIDRead(ctx, str, intOr*time.Second)
1040  rfid_emulate             → a.flipper.RFIDEmulate(str,str, intOr*time.Second)
1042  rfid_write               → a.flipper.RFIDWrite(str,str)
1046  ibutton_read             → a.flipper.IButtonRead(intOr*time.Second)
1048  ibutton_emulate          → a.flipper.IButtonEmulate(str,str, intOr*time.Second)
1050  ibutton_write            → a.flipper.IButtonWrite(str)
1054  gpio_set                 → a.flipper.GPIOSet(str, intOr)
1056  gpio_read                → a.flipper.GPIORead(str)
1060  badusb_run               → validator gate (§F.2) + a.flipper.BadUSBRun(path)
1071  badusb_validate          → a.validateBadUSB(path) + JSON
1081  list_apps                → a.flipper.LoaderListParsed() + JSON
1088  loader_open              → a.flipper.LoaderOpen(str,str)
1090  loader_close             → a.flipper.LoaderClose()
1094  input_send               → a.flipper.InputSend(str,str)
1098  storage_list             → a.flipper.StorageList(str)
1100  storage_read             → a.flipper.StorageRead(str)
1102  storage_write            → a.flipper.StorageWriteCtx(ctx, path, content) → "ok"
1114  storage_delete           → a.flipper.StorageRemove(str)
1116  storage_mkdir            → a.flipper.StorageMkdir(str)
1118  storage_info             → a.flipper.StorageStat(str) + ParseStorageStat + JSON
1132  system_info, device_info → a.flipper.DeviceInfo()  [synonym case]
1134  power_info               → a.flipper.PowerInfo()
1136  device_reboot            → a.flipper.Reboot()
1138  flipper_raw_cli          → a.flipper.RawCLI(str)
1140  led_set                  → a.flipper.LED(str, intOr)
1142  vibro                    → a.flipper.Vibro(boolOr)
1144  list_devices             → a.listDevices()
1148  subghz_tx_key            → a.flipper.SubGHzTxKey(str, uint32(intOr), uint32(intOr), intOr)
1150  subghz_rx_raw            → a.flipper.SubGHzRxRaw(uint32(intOr), intOr*time.Second)
1152  subghz_chat              → a.flipper.SubGHzChat(uint32(intOr), intOr*time.Second)
1156  ir_decode_file           → a.flipper.IRDecodeFile(str)
1158  ir_universal_list        → a.flipper.IRUniversalList(str)
1162  nfc_raw_frame            → a.flipper.NFCRawFrame(str, intOr*time.Second)
1164  nfc_apdu                 → a.flipper.NFCAPDU(str, intOr*time.Second)
1166  nfc_mfu_rdbl             → a.flipper.NFCMFURead(intOr, intOr*time.Second)
1168  nfc_mfu_wrbl             → a.flipper.NFCMFUWrite(intOr, str, intOr*time.Second)
1170  nfc_dump_protocol        → a.flipper.NFCDumpProtocol(str, intOr*time.Second)
1172..1180  loader_nfc_magic / mfkey / mifare_nested / picopass / seader → no-arg loader calls
1184  rfid_raw_read            → a.flipper.RFIDRawRead(str,str, intOr*time.Second)
1186  rfid_raw_analyze         → a.flipper.RFIDRawAnalyze(str)
1188  rfid_raw_emulate         → a.flipper.RFIDRawEmulate(str, intOr*time.Second)
1190  loader_t5577_multiwriter → a.flipper.LoaderT5577MultiWriter()
1194  onewire_search           → a.flipper.OneWireSearch(intOr*time.Second)
1198  i2c_scan                 → a.flipper.I2CScan()
1202  js_run                   → a.flipper.JSRun(str, intOr*time.Second)
1206  storage_copy             → snapshotBeforeWrite(dst) + a.flipper.StorageCopy(src,dst) (§F.1)
1212  storage_rename           → snapshotBeforeWrite(src)+snapshotBeforeWrite(dst) + Rename (§F.1)
1219  storage_md5              → a.flipper.StorageMD5(str)
1221  storage_tree             → a.flipper.StorageTree(str)
1225..1242  loader_subghz_bruteforcer / playlist / protoview / spectrum_analyzer /
            signal_generator / nrf24mousejacker / uart_terminal / spi_mem_manager / unitemp
            → matching no-arg loader calls
1245  loader_info              → a.flipper.LoaderInfo()
1247  loader_signal            → a.flipper.LoaderSignal(intOr, str)
1249  log_stream               → a.flipper.LogStream(intOr*time.Second, str)
1251  power_reboot_dfu         → a.flipper.PowerRebootDFU()
1253  update_install           → a.flipper.UpdateInstall(str)
1255  crypto_store_key         → a.flipper.CryptoStoreKey(intOr, str, intOr, str)
1257  bt_hci_info              → a.flipper.BTHCIInfo()
1261..1269  generate_* (evil_portal, badusb, subghz, ir, nfc)
            → a.generatePayloadWithBypass(ctx, type, desc, path, target_os, deploy, verify_bypass)
1271  run_payload              → a.runPayload(path, command)
1273  generate_deploy_run      → a.generateDeployRun(ctx, type, desc, path, target_os)
1277  analyze_image            → a.analyzeImage(ctx, image, question)
1281  discover_apps            → a.discoverApps()
1285  audit_query              → a.auditQuery(intOr(p,"limit",20))
1287  audit_export             → a.auditExport()
1289  audit_stats              → a.auditStats()
1293  docs_search              → a.docsSearch(query, intOr(p,"k",5))
1297  nrf24_sniff_start        → a.flipper.LoaderNRF24Sniffer()
1299  nrf24_mousejack_start    → a.flipper.LoaderNRF24Mousejacker()
1301  nrf24_list_targets       → a.nrf24ListTargets(ctx, path)
1303  nrf24_payload_build      → a.nrf24PayloadBuild(ctx, p)
1307  target_remember          → a.targetRemember(p)
1309  target_recall            → a.targetRecall(p)
1311  target_forget            → a.targetForget(p)
1315  subghz_bruteforce_generate → a.subghzBruteforceGenerate(ctx, p)
1317  subghz_freq_sweep        → a.subghzFreqSweep(ctx, p)
1319  subghz_build             → a.subghzBuild(ctx, p)
1321  rfid_build               → a.rfidBuild(ctx, p)
1323  ir_build                 → a.irBuild(ctx, p)
1325  nfc_build                → a.nfcBuild(ctx, p)
1329  fileformat_read          → a.fileformatRead(path)
1331  fileformat_edit          → a.fileformatEdit(ctx, path, edits, output_path) — snapshots inside helper
1333  fileformat_diff          → a.fileformatDiff(path_a, path_b)
1337..1352  workflow_* (8 tools) → workflows.<Func>(ctx, a.workflowDeps(), p)
1355..1640  wifi_* / requireMarauder() guard + m.<Method>(...) (73 entries)
```

Every agent-only case method lives in `internal/agent/agent.go` below the
dispatch switch (`a.nfcReadSave`, `a.listDevices`, `a.auditQuery`, etc.).
When migrating, COPY the case body verbatim and substitute receivers.

### A.3 — Agent schema declarations (`internal/agent/{tools,gen_tools,marauder_tools}.go`)

170 total `tool(...)` / `toolEx(...)` declarations.

- `internal/agent/tools.go` — 92 entries (core Flipper: RF, NFC, RFID,
  iButton, BadUSB, storage, GPIO, system, loader, workflows, fileformat).
- `internal/agent/gen_tools.go` — 26 entries (generate_*, parametric
  builders, audit, docs_search, NRF24, target memory).
- `internal/agent/marauder_tools.go` — 51 entries (every wifi_* tool).

The schema helper is:

```go
tool(name, desc string, properties map[string]interface{}, required ...string)
```

`props(reqProp(...), optProp(...))` merges per-parameter maps. Both
`reqProp` and `optProp` return `{name: {type, description}}`;
optionality is controlled by which names appear in the `required`
variadic. `toolEx` wraps `tool` with a few-shot `Examples:` block.

### A.4 — Cross-reference

| Where | Count |
|---|---|
| In MCP **and** agent | 116 |
| In MCP only (to be added to agent via registry) | 9 (all 8 `marauder_*` / GPS tools + `wifi_portscan_service`) |
| In agent only (54) | 36 AgentOnly by design + 18 WiFi extras to expose in MCP |

**In MCP only (9)** — becomes agent-callable when registered (Wave 3):
`marauder_gps_data`, `marauder_gps_field`, `marauder_nmea`,
`marauder_packet_count`, `marauder_storage_ls`, `marauder_led_set`,
`marauder_led_rainbow`, `wifi_portscan_service`. *(MCP also has
`device_info` with no `system_info` — that's a synonym, see §F.4.)*

**AgentOnly by design (36)** — stays agent-only after migration:
`nfc_read_save`; `generate_evil_portal`, `generate_badusb`,
`generate_subghz`, `generate_ir`, `generate_nfc`; `run_payload`,
`generate_deploy_run`; `subghz_build`, `rfid_build`, `ir_build`,
`nfc_build`, `subghz_bruteforce_generate`, `subghz_freq_sweep`;
`analyze_image`, `discover_apps`, `docs_search`; `audit_query`,
`audit_export`, `audit_stats`; `target_remember`, `target_recall`,
`target_forget`; `list_devices`; `workflow_nfc_badge_pipeline`,
`workflow_wifi_target_to_hashcat`, `workflow_rolljam_lab_demo`,
`workflow_badusb_target_profile`, `workflow_mousejack`;
`nrf24_sniff_start`, `nrf24_mousejack_start`, `nrf24_list_targets`,
`nrf24_payload_build`; `subghz_bruteforce`, `ir_bruteforce`;
`bt_hci_info`.

**WiFi extras to expose in MCP (18)** — currently agent-only but no
reason they shouldn't also be MCP-callable. Wave 3 simply registers
them with `AgentOnly: false`: `wifi_beacon_rickroll`,
`wifi_beacon_funny`, `wifi_sniff_pwnagotchi`, `wifi_sniff_sae`,
`wifi_add_ssid`, `wifi_remove_ssid`, `wifi_generate_ssids`, `wifi_join`,
`wifi_ping_scan`, `wifi_arp_scan`, `wifi_port_scan`, `wifi_random_mac`,
`wifi_clone_mac`, `wifi_save_aps`, `wifi_save_ssids`, `wifi_load_aps`,
`wifi_load_ssids`.

(`subghz_bruteforce` and `ir_bruteforce` use `ExecLong` passthrough and
are handled as Critical AgentOnly per §F.5.)

---

## B. Wave assignments

Every wave runs in an isolated worktree off this branch. Each wave
engineer opens their per-wave brief, reads this document, does the
migration, runs the acceptance gates in §D, and hands the worktree back
for the orchestrator's hardware gate in §E.

**Coexistence rule (Waves 0–4).** Old `s.add()` calls and old `case`
branches stay in place while the registry is populated incrementally.
The MCP server registers ALL specs via the registry AND keeps its
direct `s.add()` calls until Wave 5 — duplicate registration is
impossible because Register panics on duplicates. The order of
operations within each wave is therefore:

1. Create the Wave's per-topic files under `internal/tools/<topic>.go`
   with `func init() { tools.Register(Spec{...}) }`.
2. Remove the corresponding `s.add()` calls in `internal/mcp/server.go`
   and the corresponding `case "..."` branch in `internal/agent/agent.go`
   **in the same commit**, so the panic-on-duplicate rule never fires.
3. Ensure the adapter layer (§C.5) calls `tools.All()` and registers
   every Spec with the MCP server + Anthropic schema builder.

**Do not touch /dev/ttyACM0 from a worktree.** Hardware integration is
the orchestrator's job (§E).

### Wave 0 — skeleton + 3 proof migrations (task #2)

**Tools:** `device_info` (+ alias `system_info`), `storage_write`, `nfc_detect`.

- Create `internal/tools/system.go` registering `device_info` with
  `Aliases: []string{"system_info"}`. Handler calls `d.Flipper.DeviceInfo()`.
- Create `internal/tools/storage.go` registering `storage_write`.
  Handler calls `d.SnapshotBeforeWrite(ctx, path)` then
  `d.Flipper.StorageWriteCtx(ctx, path, content)` returning `"ok"` on
  success.
- Create `internal/tools/nfc.go` registering `nfc_detect`. Handler calls
  `d.Flipper.NFCDetect(...)` then `flipper.ParseNFCDetect` + JSON marshal.
- Add the **adapter wiring** both modes need (see §C.5):
  - `internal/mcp/server.go`: call `tools.All()` in `NewServer` and
    register each non-AgentOnly Spec via `s.srv.AddTool(...)`.
  - `internal/agent/tools.go`: extend `buildTools()` / `ToolCatalog` so
    registry-backed Specs produce `anthropic.ToolUnionParam` entries.
  - `internal/agent/agent.go` dispatch: add a *lookup-first* short-circuit
    that calls `tools.Get(name)`, builds a `Deps`, and invokes the
    handler; falls through to the existing switch for every case not
    yet migrated.
- Remove the 3 migrated tools from `s.add()` + `case`.
- Registry size: **3** specs (device_info, storage_write, nfc_detect).

### Wave 1 — system + storage primitives (task #4)

**Tools:** `system_info` (NOTE: already done as Wave 0 alias — skip),
`power_info`, `device_reboot`, `flipper_raw_cli`, `led_set`, `vibro`,
`list_devices`, `bt_hci_info`, `loader_info`, `loader_open`,
`loader_close`, `list_apps`, `i2c_scan`, `onewire_search`, `gpio_set`,
`gpio_read`, `input_send`, `log_stream`, `loader_signal`,
`power_reboot_dfu`, `update_install`, `crypto_store_key`, plus every
`storage_*` not yet in Wave 0 (`storage_list`, `storage_read`,
`storage_delete`, `storage_mkdir`, `storage_info`, `storage_copy`,
`storage_rename`, `storage_md5`, `storage_tree`).

Files: extend `internal/tools/system.go` and `internal/tools/storage.go`.
Also add `internal/tools/loader.go`, `internal/tools/hw.go` (gpio/i2c/
onewire/input).

Special handling:
- `storage_info` must parse via `flipper.ParseStorageStat` + JSON-marshal
  (mirror agent behaviour; MCP returns raw string today but parsed
  output is strictly better).
- `storage_copy` / `storage_rename` must call `d.SnapshotBeforeWrite`
  (§F.1).
- `list_apps` must parse via `f.LoaderListParsed()` + JSON-marshal
  (mirror agent behaviour).
- `list_devices`: **AgentOnly: true** (depends on agent's device
  registry — keep the existing `a.listDevices()` body as the handler).
  Registered via adapter.

Registry size after Wave 1: **3 + 31 = 34** specs (of which 1 is
AgentOnly, the rest are MCP-exposed).

### Wave 2 — NFC + RFID + IR + SubGHz primitives (task #6)

**Tools (primitives only — no `_build` / `_generate` / `_bruteforce_generate`):**

- SubGHz: `subghz_transmit`, `subghz_receive`, `subghz_decode`,
  `subghz_bruteforce`, `subghz_tx_key`, `subghz_rx_raw`, `subghz_chat`.
- IR: `ir_transmit`, `ir_transmit_raw`, `ir_receive`, `ir_bruteforce`,
  `ir_decode_file`, `ir_universal_list`.
- NFC (primitives, `nfc_detect` already done in Wave 0): `nfc_emulate`,
  `nfc_subcommand`, `nfc_raw_frame`, `nfc_apdu`, `nfc_mfu_rdbl`,
  `nfc_mfu_wrbl`, `nfc_dump_protocol`, plus NFC loader FAPs
  (`loader_nfc_magic`, `loader_mfkey`, `loader_mifare_nested`,
  `loader_picopass`, `loader_seader`).
- RFID: `rfid_read`, `rfid_emulate`, `rfid_write`, `rfid_raw_read`,
  `rfid_raw_analyze`, `rfid_raw_emulate`, `loader_t5577_multiwriter`.
- iButton: `ibutton_read`, `ibutton_emulate`, `ibutton_write`.
- BadUSB: `badusb_run` (keep validator gate — §F.2), `badusb_validate`.
- JS: `js_run`.
- SubGHz / misc loader FAPs: `loader_subghz_bruteforcer`,
  `loader_subghz_playlist`, `loader_protoview`,
  `loader_spectrum_analyzer`, `loader_signal_generator`,
  `loader_nrf24mousejacker`, `loader_uart_terminal`,
  `loader_spi_mem_manager`, `loader_unitemp`.
- FileFormat: `fileformat_read`, `fileformat_edit` (snapshot §F.1),
  `fileformat_diff`.

Files: `internal/tools/{subghz,ir,nfc,rfid,ibutton,badusb,js,fileformat}.go`
(plus extending `loader.go`).

Special handling:
- `nfc_dump_protocol`: canonical-to-Momentum token translation stays
  inside `f.NFCDumpProtocol` — the wrapper already handles it. Do NOT
  add translation logic in the handler (§F.3).
- `nfc_subcommand` / `nfc_raw_frame` / `nfc_apdu` / `nfc_mfu_*` depend
  on the nfc subshell (Momentum/stock/Unleashed/RogueMaster, not
  Xtreme); the `f.Capabilities().HasNFCSubshell` check is enforced
  inside the flipper commands, so handlers stay simple — see §F.5.
- `badusb_run`: the pre-flight validator gate (cfg.Validator.BadUSB)
  must move into the handler. Wave 2 engineer imports `internal/config`
  and `internal/validator` and copies the gating logic from
  `agent.go:1060..1070`.
- `subghz_bruteforce` / `ir_bruteforce` use `f.ExecLong(...)` with a
  pre-built command string. Copy verbatim.
- `subghz_receive`: parse via `flipper.ParseSubGHzReceive` + JSON.
- `wifi_evil_portal_stop`: NOTE — this lives in Wave 3, not here. The
  MCP handler maps to `m.StopScan()` (no dedicated stop verb); copy
  that.

Registry size after Wave 2: **34 + 55 = 89** specs (all MCP-exposed
except `ir_bruteforce` and `subghz_bruteforce` which are AgentOnly).

### Wave 3 — Marauder + WiFi tools (task #8)

**Tools:** every `wifi_*`, `marauder_*`, `nrf24_*` primitive. That's
the 73 dispatch cases under `--- Marauder WiFi ---` plus the 8 MCP-only
`marauder_*` / `wifi_portscan_service` entries from §A.4.

Files: `internal/tools/{wifi,marauder,nrf24}.go`.

The orchestrator does NOT have a Marauder devboard, so these are
unit-test only. Use mocks; do not attempt hardware verification.
`d.Marauder == nil` handlers must return the same friendly error that
`a.requireMarauder()` produces today. Consider adding a helper
`d.RequireMarauder() error` on `Deps` to match the existing shape.

Special handling:
- Most handlers are straight `m.<Method>(durationParam | args)`.
- `wifi_scan_ap` / `wifi_list_aps` / `wifi_list_stations` parse via
  `ScanAPParsed` / `ListAPsParsed` / `ListStationsParsed` and JSON.
- `wifi_sniff_sae` is a wrapper over `m.SniffRaw(60s default)` with a
  trailing hint string appended to the result.
- `wifi_evil_portal_stop` maps to `m.StopScan()` (see Wave 2 note).
- `nrf24_sniff_start` / `nrf24_mousejack_start` are `f.LoaderNRF24*()`
  calls — i.e. they use the **Flipper**, not the Marauder. They stay
  AgentOnly because they're part of the LLM-driven mousejack workflow.
  `nrf24_list_targets` / `nrf24_payload_build` are AgentOnly too (the
  file-parsing + DuckyScript validation logic lives in `agent.go`
  methods).

Registry size after Wave 3: **89 + 73 + 8 (MCP-only extras) = ~170** specs.

### Wave 4 — agent-only LLM compositions (task #10)

**All tools in this wave have `AgentOnly: true`.**

**Tools:** `nfc_read_save`, `generate_evil_portal`, `generate_badusb`,
`generate_subghz`, `generate_ir`, `generate_nfc`, `run_payload`,
`generate_deploy_run`, `subghz_build`, `rfid_build`, `ir_build`,
`nfc_build`, `subghz_bruteforce_generate`, `subghz_freq_sweep`,
`analyze_image`, `discover_apps`, `docs_search`, `audit_query`,
`audit_export`, `audit_stats`, `target_remember`, `target_recall`,
`target_forget`, `workflow_nfc_badge_pipeline`,
`workflow_wifi_target_to_hashcat`, `workflow_rolljam_lab_demo`,
`workflow_badusb_target_profile`, `workflow_mousejack`,
`workflow_garage_door_triage` (already in MCP — switch to registry as
non-AgentOnly), `workflow_phys_pentest_badge_walk` (same),
`workflow_hw_recon_blackbox_device` (same).

Files: `internal/tools/{workflows,gen,vision,audit,docs,targets,nfcreadsave}.go`.

Most of these handlers delegate to existing `*Agent` methods. Two
options for reusing that logic cleanly:

1. **(Preferred) Move the methods.** Lift the function bodies of
   `a.nfcReadSave`, `a.generatePayloadWithBypass`, `a.runPayload`,
   `a.generateDeployRun`, `a.analyzeImage`, `a.discoverApps`,
   `a.auditQuery`, `a.auditExport`, `a.auditStats`, `a.docsSearch`,
   `a.subghzBruteforceGenerate`, `a.subghzFreqSweep`, `a.subghzBuild`,
   `a.rfidBuild`, `a.irBuild`, `a.nfcBuild`, `a.fileformatRead`,
   `a.fileformatEdit`, `a.fileformatDiff`, `a.listDevices`,
   `a.nrf24ListTargets`, `a.nrf24PayloadBuild`, `a.targetRemember`,
   `a.targetRecall`, `a.targetForget`, `a.validateBadUSB` into
   `internal/tools/*.go` as package-private helpers that take a
   `*Deps`. Leaves `*Agent` as a thin container around Deps + session.
2. **(Fallback) Keep methods on Agent, call via Deps-held closure.**
   Add a field `Deps.AgentHooks` holding func-typed bindings. Avoid
   unless (1) reveals a structural snag.

Workflow handlers need `d.WorkflowConfirm` wiring — the hook mirrors
`a.workflowConfirmHook`. In MCP mode the hook is nil, meaning
auto-approve (matches today's behaviour because MCP never re-registered
those 3 workflows with an interactive gate anyway).

Registry size after Wave 4: full catalog — **~200** specs total.

### Wave 5 — cleanup (task #12)

1. Delete every remaining `s.add()` in `internal/mcp/server.go`. Keep
   only `registerPersonaPrompts` and the helper funcs (`sa`, `na`,
   `ba`, `durationParam`, etc. — still used by the registry adapter).
2. Delete the agent-side `switch name {...}` body in
   `internal/agent/agent.go:dispatch`. The method becomes a
   registry-only lookup:
   ```go
   s, ok := tools.Get(name)
   if !ok { return "", fmt.Errorf("unknown tool: %s", name) }
   return s.Handler(ctx, a.deps(), p)
   ```
3. Delete `buildTools` / `buildGenTools` / `buildMarauderTools` /
   `buildWorkflowTools` / `buildFileFormatTools` (or collapse them into
   a single `buildToolsFromRegistry`).
4. Keep `internal/agent/router.go` as-is — it still consumes
   `ToolGroup(name)`, but now that function can delegate to
   `tools.Get(name).Group` directly.

Registry size: unchanged from Wave 4.

---

## C. Migration template — worked example: `device_info`

Shows how to translate the existing three registrations into one Spec.

### C.1 — Existing registrations (DO NOT TOUCH MANUALLY until §C.4)

- **MCP** (`internal/mcp/server.go:652`):
  ```go
  s.add("device_info", "Get Flipper device information. Read-only.",
      nil, nil,
      func(_ context.Context, _ map[string]interface{}) (string, error) {
          return f.DeviceInfo()
      })
  ```
- **Agent schema** (`internal/agent/tools.go:283`):
  ```go
  tool("system_info",
      "Get Flipper Zero device information: firmware version, hardware revision, uptime, etc.",
      props(),
  ),
  ```
- **Agent dispatch** (`internal/agent/agent.go:1132`):
  ```go
  case "system_info", "device_info":
      return a.flipper.DeviceInfo()
  ```

### C.2 — Risk + Group lookup

- `internal/risk/risk.go:39,64` — both `"device_info"` and
  `"system_info"` are registered at `risk.Low`. Preserve.
- `internal/agent/router.go:88-89` — the names are enumerated in the
  `case` that returns `GroupFlipperSystem`. Preserve.

### C.3 — New file: `internal/tools/system.go`

```go
package tools

import (
    "context"
    "encoding/json"

    "github.com/xunholy/promptzero/internal/risk"
)

func init() {
    Register(Spec{
        Name:        "device_info",
        Aliases:     []string{"system_info"}, // agent-side legacy synonym (§F.4)
        Description: "Get Flipper Zero device information: firmware version, hardware revision, uptime, etc.",
        Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
        Required:    nil,
        Risk:        risk.Low,
        Group:       GroupFlipperSystem,
        AgentOnly:   false,
        Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
            return d.Flipper.DeviceInfo()
        },
    })
}
```

Notes on each field:

- **Name / Aliases.** Choose the MCP-side (firmware-aligned) name as the
  canonical. Aliases catch the agent-side legacy name. Both resolve via
  `tools.Get`.
- **Description.** Pick the richer of the two existing descriptions. The
  agent-side one carries more semantic context, so use it; MCP clients
  benefit from the same prose.
- **Schema / Required.** This tool takes no arguments, so Schema is the
  canonical empty-object shape and Required is nil. For tools with
  arguments, translate each `mcp.WithString("k", mcp.Required(), mcp.Description("..."))`
  into a JSON Schema `{"properties":{"k":{"type":"string","description":"..."}}}` and
  add `"k"` to `Required` if it was marked `mcp.Required()`. Number and
  boolean follow the same pattern with `"type":"integer"` /
  `"type":"number"` / `"type":"boolean"`. `mcp.WithArray` → `"type":"array"`;
  `mcp.WithObject` → `"type":"object"`.
- **Risk.** Copy from `internal/risk/risk.go`'s `toolLevels` map. If the
  name isn't present, the default is `risk.High` (see `Classify`);
  add it explicitly rather than relying on the default.
- **Group.** Copy from `internal/agent/router.go:ToolGroup(name)`. For
  tools that don't match a prefix there, the default is
  `GroupMetaUtil` — set it explicitly.
- **AgentOnly.** Mirror the §A.4 classification.
- **Handler.** Paste the dispatch `case` body verbatim, substituting
  `a.flipper` → `d.Flipper`, `a.marauder` → `d.Marauder`, `a.auditLog`
  → `d.Audit`, `a.generator` → `d.Generator`, `a.vision` → `d.Vision`,
  `a.snapshotMgr` → `d.Snapshot`, `a.sessionID` → `d.SessionID`,
  `a.ragIndex` → `d.RAG`, `a.targetMem` → `d.TargetMem`, and the
  arg-helper calls `str(p,...)` / `intOr(p,...,def)` / `boolOr(p,...,def)`
  / `floatOr(p,...,def)` left as-is (they live in
  `internal/agent/dispatch_helpers.go`; Wave 1 copies those helpers to
  `internal/tools/args.go` and reuses). Until Wave 1 lifts the
  helpers, write the Wave 0 three handlers with inline type assertions.

### C.4 — Remove the three old registrations

In the SAME commit:

1. Delete lines 652–656 from `internal/mcp/server.go` (the
   `s.add("device_info", ...)` block).
2. Delete lines 283–286 from `internal/agent/tools.go` (the
   `tool("system_info", ...)` block). Note: Wave 0 does this even
   though the alias means the agent-side schema would still surface
   under `system_info` — the **adapter** in §C.5 will re-surface it
   based on Spec.Aliases.
3. Delete the case block at `internal/agent/agent.go:1132–1133`.
   The registry short-circuit from §C.5 picks it up.

### C.5 — Adapter wiring (one-time, done in Wave 0)

Two small adapter functions bridge the registry to the two existing
hosts. Wave 0 creates them; subsequent waves populate the registry
only.

**MCP adapter** (new function in `internal/mcp/server.go`, called from
`NewServer` after the existing `registerFlipperTools / ...` chain, or
replacing those registrations entirely in Wave 5):

```go
func (s *Server) registerFromRegistry() {
    for _, spec := range tools.All() {
        if spec.AgentOnly {
            continue
        }
        // Build ToolOptions from spec.Schema.
        opts := optsFromSchema(spec.Schema)
        names := append([]string{spec.Name}, spec.Aliases...)
        for _, name := range names {
            specCopy := spec
            register := func(n string) {
                s.add(n, specCopy.Description, opts, specCopy.Required,
                    func(ctx context.Context, args map[string]interface{}) (string, error) {
                        return specCopy.Handler(ctx, s.deps(), args)
                    })
            }
            register(name)
        }
    }
}

func (s *Server) deps() *tools.Deps {
    return &tools.Deps{
        Flipper:  s.flipper,
        Marauder: s.marauder,
        // MCP does not carry audit/generator/vision/etc.
    }
}
```

`optsFromSchema` walks the JSON Schema and produces the equivalent
`mcp.ToolOption` slice. Keep it small; the shapes we use are `string`,
`integer`, `number`, `boolean`, `array`, `object` at the top-level only.

**Agent adapter** — two changes:

1. `internal/agent/tools.go:buildTools` grows a registry-backed prepass
   that appends a `tool(spec.Name, spec.Description, props(...from
   spec.Schema...), spec.Required...)` entry per Spec (skipping
   AgentOnly: false Specs already covered by the old builders).
   Eventually (Wave 5) the old builders collapse into this prepass.
2. `internal/agent/agent.go:dispatch` becomes:
   ```go
   if s, ok := tools.Get(name); ok {
       return s.Handler(ctx, a.deps(), p)
   }
   switch name { ... existing cases ... }
   ```
   with `a.deps()` wiring every Agent field into the `Deps` bag.

**During Waves 0–4 the registry and the legacy switch coexist.** The
short-circuit above evaluates the registry first; if a Spec is
registered for `name`, the legacy `case` is skipped. Because we remove
the `case` in the same commit as the registry entry, divergence is
impossible.

---

## D. Acceptance criteria — per wave

Every wave's final commit MUST pass the following gates before the
engineer hands the worktree back:

1. **Build clean.** `CGO_ENABLED=1 go build ./...`
2. **Vet clean.** `go vet ./...`
3. **Lint clean.** `PATH="$(go env GOPATH)/bin:$PATH" task lint`
4. **Tests pass with race.** `CGO_ENABLED=1 go test -short -race ./...`
5. **Registry size matches.** `go test -run TestRegistrySize -count=1
   ./internal/tools/...` (Wave 0 adds this test; each wave bumps the
   expected count).
   - Wave 0: 3 Specs
   - Wave 1: 34 Specs (cumulative; 1 AgentOnly: `list_devices`)
   - Wave 2: 89 Specs (cumulative; 3 AgentOnly: +`subghz_bruteforce`,
     +`ir_bruteforce`)
   - Wave 3: ~170 Specs (cumulative; 7 AgentOnly: +4 `nrf24_*`)
   - Wave 4: full catalog (~200 Specs cumulative; ~36 AgentOnly)
   - Wave 5: unchanged from Wave 4; deletion-only.
6. **No duplicate registrations.** The `tools.Register` panic is the
   primary guard; the wave's test must import every new `internal/tools/*.go`
   file so `init()` funcs run.

**Failing acceptance leaves the worktree open.** The engineer diagnoses
and fixes; they do not skip the gate.

---

## E. Hardware gate (orchestrator-only)

Between each wave, the orchestrator runs the four harnesses against a
real Flipper on `/dev/ttyACM0`. Wave engineers must NOT touch the port
— they work against mocks and the race-enabled unit suite.

```bash
# Build once per hardware gate; bin/promptzero is the subject.
CGO_ENABLED=1 go build -o bin/promptzero ./cmd/promptzero

# 1. MCP smoke (23 tools) — proves MCP registration works end-to-end.
bin/hwtest     --bin ./bin/promptzero --port /dev/ttyACM0

# 2. MIFARE workflow walker — 13 phases, exercises the NFC subshell,
#    storage copy/rename/delete, and snapshot hygiene.
bin/mifaretest --bin ./bin/promptzero --port /dev/ttyACM0 --emulate=false

# 3. Web mode — 9 endpoints + WebSocket bridge.
bin/webtest    --bin ./bin/promptzero --port /dev/ttyACM0

# 4. CLI/REPL — PTY-driven, 5 steps.
bin/clitest    --bin ./bin/promptzero --port /dev/ttyACM0
```

A non-zero exit from any harness blocks the next wave. The orchestrator
triages back to the responsible wave engineer via the team task
system.

**Hardware-gate task IDs:** #3 (after Wave 0), #5 (after Wave 1),
#7 (after Wave 2), #9 (after Wave 3), #11 (after Wave 4), #13 (final).

---

## F. Edge cases

### F.1 — Snapshot-before-write

Tools that clobber an existing file on the Flipper SD card MUST capture
a snapshot first so `/rewind` can roll back. Existing agent sites
(reference):

- `agent.go:1206-1218` — `storage_copy` snapshots `dst`; `storage_rename`
  snapshots `src` and `dst`.
- `agent.go:2455 a.fileformatEdit` — snapshots the output path before
  the write.
- Every `*_build` handler (`subghzBuild`, `rfidBuild`, `irBuild`,
  `nfcBuild`) and `generatePayloadWithBypass` — snapshot before the
  final `StorageWrite`.

Under the registry, handlers call `d.SnapshotBeforeWrite(ctx, path)`.
In MCP mode (no snapshot manager), it is a no-op. In agent mode the
session ID is wired so the capture lands under the correct
`snapshot.Manager` tree. Errors are swallowed — never propagate a
snapshot failure as a tool error (the write is the user-visible
action, and snapshot is advisory).

`storage_write` (Wave 0) also calls `d.SnapshotBeforeWrite` to match
the behaviour of `fileformat_edit` — overwriting a file should always
be recoverable.

### F.2 — BadUSB validator gate

`agent.go:1060-1070` — before calling `BadUSBRun`, the agent dispatch
runs the static validator and consults `cfg.Validator.BadUSB.AllowCritical`
/ `.WarnAction`. The registry handler MUST preserve this gate:

```go
if rep, err := runBadUSBValidator(d, path); err == nil {
    if rep.Severity == validator.SeverityCritical && !d.Config.Validator.BadUSB.AllowCritical {
        return "", fmt.Errorf("badusb_run blocked by sandbox validator:\n%s\n...", rep.RenderText())
    }
    if rep.Severity == validator.SeverityWarn && d.Config.Validator.BadUSB.WarnAction == "block" {
        return "", fmt.Errorf("badusb_run blocked (warn-action=block):\n%s", rep.RenderText())
    }
}
return d.Flipper.BadUSBRun(path)
```

MCP mode today omits this gate entirely — registering via the registry
*adds* it, which is a silent behaviour improvement. Document it in the
wave commit message.

### F.3 — `nfc_dump_protocol` Momentum translation

The firmware-dialect translation (`Mifare_Classic` → `mfc` on Momentum,
etc.) lives inside `flipper.NFCDumpProtocol` (pinned by a regression
test since commit `c51cf34`). DO NOT re-implement the translation in
the registry handler — the handler remains a simple
`d.Flipper.NFCDumpProtocol(str, durationParam)`. Noted here only to
prevent a well-meaning wave engineer from adding a second translation
layer.

### F.4 — Synonyms — decision: **Aliases on Spec** (not two Specs)

`system_info` and `device_info` describe the same tool (the agent-side
name vs. the MCP / firmware name). Two options were considered:

1. **Two Specs sharing a Handler.** Simple but duplicates metadata
   (risk, group, description, schema) and makes "what's the canonical
   name?" ambiguous in `/tools` output and audit logs.
2. **One Spec with `Aliases []string`.** The registry surfaces both
   names, but audit / report generation always see the canonical. This
   is the approach taken — see `Spec.Aliases` in `internal/tools/spec.go`
   and `Register`'s alias-collision guards.

Guidance for wave engineers: if a tool has ONE name, use the empty
`Aliases []string{}`. If it has more, put the firmware/MCP-aligned
name as canonical (`Name`) and the agent-legacy name in `Aliases`.
This way existing LLM prompts / agent traces that reference
`system_info` keep working while the canonical string (surfaced in
audit logs and `/tools`) aligns with the firmware verb.

The only current synonym is `device_info` + `system_info`. If new ones
appear mid-migration, follow the same convention.

### F.5 — Capability-gated tools (NFC subshell, JS runtime)

Tools that need the `nfc` CLI subshell (`nfc_subcommand`,
`nfc_raw_frame`, `nfc_apdu`, `nfc_mfu_rdbl`, `nfc_mfu_wrbl`,
`nfc_dump_protocol`) are gated INSIDE the flipper package:

- `internal/flipper/commands.go:160` — `NFCSubcommand` returns a
  capability error when `!caps.HasNFCSubshell` (Xtreme fork).
- Similar gate at `commands.go:421` for the other subshell commands.

The JS runtime gate (`js_run`) lives in `internal/flipper/commands.go`
in the same pattern — `JSRun` short-circuits on forks without a JS
engine.

**The registry handler does nothing special.** It calls the flipper
method as-is and propagates the capability error. Do NOT add a second
layer of capability checks in the registry — they would drift against
the truth source (the flipper package).

### F.6 — Tools with in-handler JSON parsing/formatting

These handlers do more than a plain wrapper call. Preserve the logic
verbatim.

- **`storage_info`** (`agent.go:1118`) — `StorageStat` → `ParseStorageStat`
  → `json.Marshal`. MCP today returns raw; the registry unifies on
  parsed-JSON behaviour for both hosts.
- **`subghz_receive`** (`agent.go:995`) — `SubGHzRx` → `ParseSubGHzReceive`
  → `json.Marshal`.
- **`nfc_detect`** (`agent.go:1024`) — `NFCDetect` → `ParseNFCDetect`
  → `json.Marshal`.
- **`list_apps`** (`agent.go:1081`) — `LoaderListParsed` → `json.Marshal`.
- **`wifi_scan_ap`** (`agent.go:1355`) — `ScanAPParsed` → `json.Marshal`.
- **`wifi_list_aps`** (`agent.go:1394`) — `ListAPsParsed` → `json.Marshal`.
- **`wifi_list_stations`** (`agent.go:1409`) — `ListStationsParsed` →
  `json.Marshal`.
- **`badusb_validate`** (`agent.go:1071`) — `a.validateBadUSB(path)` →
  `json.Marshal`. Lift `validateBadUSB` into a package helper in
  `internal/tools/badusb.go` when Wave 2 runs.
- **`fileformat_read`** (`agent.go:1329`) — reads + parses + marshals.
- **`fileformat_edit`** (`agent.go:1331`) — reads, ApplyEdits, SaveFile,
  optional alternate path, snapshot-before-write, `StorageWrite`.
- **`fileformat_diff`** (`agent.go:1333`) — reads both, `fileformat.Diff`,
  `json.Marshal`.

### F.7 — Post-migration risk registry check

`internal/risk/risk.go:toolLevels` will still be the source of truth
for risk classification. The registry test suite (Wave 0 baseline)
should include a coverage test that every Spec's `Risk` matches
`risk.ClassifyExplicit(spec.Name)` — this catches drift where a wave
engineer copies a Risk value wrong. See the existing agent-package
coverage test (referenced in `internal/risk/risk.go:189-193`) for the
pattern.

### F.8 — What NOT to change

- `internal/risk/risk.go` — unchanged by this refactor.
- `internal/agent/router.go` — unchanged until Wave 5; then
  `ToolGroup` delegates to `tools.Get(name).Group` (small change).
- `internal/persona/` — personas filter on tool names; unchanged.
- The fixes in commit `c51cf34` (the audit fixes: MCP API-key gate,
  indexOfPrompt bug, web-race init bug, nfc_dump_protocol Momentum
  map, nfc_read_save fallback, system_info/device_info synonym,
  storage_write dispatch). **DO NOT REVERT ANY OF THESE.** The registry
  migration preserves all seven fixes by construction — every wave
  engineer copying the existing `case` bodies will bring the fixes
  along with them.

---

*End of runbook.*
