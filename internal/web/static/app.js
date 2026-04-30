/* PromptZero v0.9 — Web UI
 * All agent-originated content is set via textContent / createElement.
 * No innerHTML assignments for agent-supplied data anywhere in this file.
 */

(function () {
  'use strict';

  /* =========================================================================
     Constants
  ========================================================================= */

  // Per-subsystem catalog of likely tools / attacks.
  // Clicking an item prefills the agent input — the user reviews + sends.
  // risk: 'low' | 'med' | 'high' (renders as a badge; affects nothing else)
  var CATEGORY_TOOLS = {
    subghz: {
      title: 'SUB-GHZ',
      items: [
        { label: 'Frequency analyzer',     prompt: 'run sub-ghz frequency analyzer and tell me what is active around me',                       risk: 'low'  },
        { label: 'Scan default presets',   prompt: 'scan sub-ghz on the default preset list and report any captures',                            risk: 'low'  },
        { label: 'Read fixed-code remote', prompt: 'capture the next sub-ghz transmission from a nearby remote and decode it',                   risk: 'low'  },
        { label: 'Save capture to SD',     prompt: 'save the most recent sub-ghz capture to the SD card under /subghz/',                          risk: 'low'  },
        { label: 'Replay saved signal',    prompt: 'list saved sub-ghz files and replay the one I pick',                                          risk: 'med'  },
        { label: 'RAW capture',            prompt: 'start a sub-ghz RAW capture for 10 seconds at 433.92 MHz',                                    risk: 'low'  },
      ],
    },
    rfid: {
      title: '125 kHz RFID',
      items: [
        { label: 'Read tag',               prompt: 'read the 125 kHz rfid tag held to the flipper and identify the format',                     risk: 'low'  },
        { label: 'Save read to SD',        prompt: 'save the rfid tag I just read to the SD card',                                                risk: 'low'  },
        { label: 'Emulate saved tag',      prompt: 'list saved 125 kHz rfid tags and emulate the one I pick',                                    risk: 'med'  },
        { label: 'Write to T5577 blank',   prompt: 'clone the rfid tag I just read onto a T5577 blank held to the flipper',                      risk: 'med'  },
        { label: 'Identify common formats', prompt: 'read the rfid tag and tell me whether it is EM4100, HID Prox, Indala, or something else',  risk: 'low'  },
      ],
    },
    nfc: {
      title: 'NFC',
      items: [
        { label: 'Read tag',               prompt: 'read the nfc tag held to the flipper and report UID, ATQA, SAK, and detected type',         risk: 'low'  },
        { label: 'Save dump',              prompt: 'save a full dump of the nfc tag I just read to the SD card',                                  risk: 'low'  },
        { label: 'Emulate UID',            prompt: 'emulate the UID of the nfc tag I last read',                                                  risk: 'med'  },
        { label: 'Mifare dictionary',      prompt: 'attempt the standard Mifare Classic key dictionary attack against the tag held to the flipper', risk: 'high' },
        { label: 'Mifare nested',          prompt: 'run the Mifare Classic nested attack against the tag, assuming we know one key',              risk: 'high' },
        { label: 'Read NDEF',              prompt: 'read NDEF records from the nfc tag held to the flipper',                                      risk: 'low'  },
      ],
    },
    ir: {
      title: 'INFRARED',
      items: [
        { label: 'Universal TV remote',    prompt: 'launch the IR universal remote and try to power off the TV in front of me',                  risk: 'low'  },
        { label: 'Universal AC remote',    prompt: 'launch the IR universal remote and try to control the air conditioner in front of me',       risk: 'low'  },
        { label: 'Capture IR signal',      prompt: 'capture the next IR signal pointed at the flipper and decode the protocol',                   risk: 'low'  },
        { label: 'Replay captured signal', prompt: 'list saved IR captures and replay the one I pick',                                            risk: 'med'  },
        { label: 'Decode protocol',        prompt: 'identify the protocol (NEC, Sony, RC5, RC6, Samsung, …) of the last captured IR signal',     risk: 'low'  },
      ],
    },
    ibutton: {
      title: 'IBUTTON',
      items: [
        { label: 'Read key',               prompt: 'read the iButton (1-Wire) key touched to the flipper contact',                               risk: 'low'  },
        { label: 'Save key to SD',         prompt: 'save the iButton key I just read to the SD card',                                             risk: 'low'  },
        { label: 'Write to blank',         prompt: 'write the last-read iButton key to the blank touched to the contact',                        risk: 'med'  },
        { label: 'Emulate saved key',      prompt: 'list saved iButton keys and emulate the one I pick',                                          risk: 'med'  },
      ],
    },
    gpio: {
      title: 'GPIO',
      items: [
        { label: 'Read pin states',        prompt: 'read the current state of every GPIO pin on the flipper',                                    risk: 'low'  },
        { label: 'Set pin output',         prompt: 'set GPIO pin <number> to <high|low> as an output',                                            risk: 'med'  },
        { label: 'I2C scan',               prompt: 'scan the I2C bus on the flipper GPIO and list any responding addresses',                     risk: 'low'  },
        { label: 'UART bridge',            prompt: 'open a UART bridge on the flipper GPIO at 115200 baud',                                      risk: 'low'  },
      ],
    },
    badusb: {
      title: 'BAD USB',
      items: [
        { label: 'List saved payloads',    prompt: 'list saved bad-usb (DuckyScript) payloads on the SD card',                                   risk: 'low'  },
        { label: 'Generate hello-world',   prompt: 'generate a tiny DuckyScript that opens a terminal and prints "hello from promptzero"',       risk: 'low'  },
        { label: 'Generate recon script',  prompt: 'generate a DuckyScript that prints basic system info (OS, user, hostname) into a text file', risk: 'med'  },
        { label: 'Validate a payload',     prompt: 'validate a DuckyScript payload — I will paste the contents next',                            risk: 'low'  },
        { label: 'Run saved payload',      prompt: 'run a saved bad-usb payload from the SD card after I confirm',                               risk: 'high' },
      ],
    },
    apps: {
      title: 'APPS',
      items: [
        { label: 'List installed FAPs',    prompt: 'list every installed app (FAP) on the flipper SD card',                                      risk: 'low'  },
        { label: 'Browse apps folder',     prompt: 'show me what is in /apps on the flipper SD card',                                            risk: 'low'  },
        { label: 'Launch app by name',     prompt: 'launch the app named <name> on the flipper',                                                  risk: 'med'  },
      ],
    },
    marauder: {
      title: 'MARAUDER',
      items: [
        { label: 'Scan WiFi APs',          prompt: 'scan for nearby WiFi access points with marauder and list SSID, BSSID, channel, RSSI',      risk: 'low'  },
        { label: 'Scan stations',          prompt: 'scan for WiFi client stations with marauder and list MAC, RSSI, associated AP',              risk: 'low'  },
        { label: 'Probe-request sniff',    prompt: 'sniff WiFi probe requests with marauder for 30 seconds and summarise what you see',          risk: 'low'  },
        { label: 'Beacon spam',            prompt: 'broadcast a short beacon-spam burst with marauder for lab demonstration only',               risk: 'high' },
        { label: 'Deauth (lab only)',      prompt: 'send a deauth burst against the AP I select — lab use only, get my confirmation first',     risk: 'high' },
        { label: 'BLE scan',               prompt: 'scan for nearby BLE devices with marauder and list name, MAC, RSSI',                          risk: 'low'  },
        { label: 'BLE spam',               prompt: 'send a short BLE-spam burst with marauder for lab demonstration only',                       risk: 'high' },
      ],
    },
  };

  // 56 columns x 52 rows — Gengar pixel mascot, derived from the canonical
  // Gen 4 HGSS sprite (PokeAPI) via tools/sprite-conversion. Body pixels map
  // to "on", red eye pixels to "e" (eye, blinkable), white teeth to "d".
  // Values: 1=on, 'd'=dim, 'e'=eye-dim (blinkable), 0=transparent
  var MASCOT_ROWS = [
    [0,0,0,0,0,0,0,0,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,1,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0,1,1,0,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,0,0,0,1,1,0,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,0,0],
    [0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1,1,1,1,1,1,0,0,1,1,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,0,0],
    [0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,1,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0,0],
    [0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0,0],
    [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0],
    [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,'e',1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0],
    [0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,'e','e','e',1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,'e',1,1,0,0,0,0,0,0,0,0,0,0],
    [0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,'e','e','e','e',1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,'e','e',1,1,1,1,0,0,0,0,0,0,0,0],
    [0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,'e','e','e','e','e',1,1,1,1,1,1,1,1,1,1,1,1,1,'e','e','e',1,1,1,1,1,1,1,1,0,0,0,0],
    [0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,'e','e','e','e','e','e',1,1,1,1,1,1,1,1,1,1,1,'e','e','e','e',1,1,1,1,1,1,1,1,1,1,1,0],
    [0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,'e',1,'e','e','e','e',1,1,1,1,1,1,1,1,1,'e','e','e','e',1,1,1,1,1,1,1,1,1,1,1,1,1],
    [0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,'e','e','e','e',1,1,1,1,1,1,1,1,'e',1,'e','e','e',1,1,1,1,1,1,1,1,1,1,1,1,0],
    [0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,'e','e',1,1,1,1,1,1,1,1,1,1,1,1,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,'d',1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,'d','d','d',1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0],
    [0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,'d','d','d',1,'d',1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0],
    [0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,'d','d','d',1,'d','d','d',1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,'d',1,1,'d','d','d',1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,'d',1,'d','d','d',1,1,'d','d','d','d',1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,'d','d','d',1,'d','d','d','d','d','d',1,'d','d',1,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,'d','d',1,'d','d','d','d','d','d',1,'d',1,1,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,'d','d','d','d','d',1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
  ];

  var BOOT_LINES = [
    { text: 'BIOS v2.1.0  Copyright (c) PromptZero Systems', cls: '' },
    { text: 'CPU: ARM Cortex-M33 @ 64MHz              [OK]', cls: 'ok' },
    { text: 'Initializing USB-CDC transport ...        [OK]', cls: 'ok' },
    { text: 'Mounting SD filesystem (FAT32) ...        [OK]', cls: 'ok' },
    { text: 'Loading tool registry ...                 [OK]', cls: 'ok' },
    { text: 'Connecting to Claude API ...              [OK]', cls: 'ok' },
    { text: 'Calibrating RF front-end ...            [WARN]', cls: 'warn' },
    { text: 'Starting WebSocket bridge ...             [OK]', cls: 'ok' },
    { text: 'System ready.', cls: '' },
  ];

  // Actions surfaced in the file preview bar, keyed by content_type.
  var FILE_ACTIONS = {
    'flipper/sub':    [{ label: 'Replay',  prompt: 'replay sub-ghz file %p' }],
    'flipper/nfc':    [{ label: 'Emulate', prompt: 'emulate the nfc dump at %p' }],
    'flipper/rfid':   [{ label: 'Emulate', prompt: 'emulate the rfid dump at %p' }],
    'flipper/ir':     [{ label: 'Send',    prompt: 'send the ir signal at %p' }],
    'flipper/badusb': [{ label: 'Run',     prompt: 'run the BadUSB payload at %p (require my confirmation)' }],
  };

  /* =========================================================================
     State
  ========================================================================= */

  var _token          = '';
  var _ws             = null;
  var _wsBackoff      = 800;
  var _sessionId      = '';
  var _currentTurnId  = null;
  var _phase          = 'Idle';
  var _currentScreen  = 'agent';
  var _cmdHistory     = [];
  var _histIdx        = -1;
  var _savedInput     = '';
  var _confirmPending = null;
  var _costTimer      = null;
  var _deviceTimer    = null;
  var _streamingMsgEl = null;
  var _streamingTurnId = null;
  var _autoScrollPaused = false;
  var _countdownTimer = null;
  var _subscreenEl    = null;
  var _beepCtx        = null;
  var _toolEls        = {};   // (turn_id|name) -> DOM element
  var _personas       = { current: '', list: [] };
  var _marauderAvailable = false; // set from marauder_available in initial status payload

  // Files screen state
  var _fsCwd          = '/ext';   // current directory being shown in tree pane
  var _fsOpenPath     = '';       // last file opened (for ui_context clearing)
  var _fsTreePane     = null;     // left pane element
  var _fsPreviewPane  = null;     // right pane element

  // D-pad mode: 'scrollback' (default) or 'device'
  var _dpadMode = (function () {
    try { return sessionStorage.getItem('promptzero_dpad_mode') || 'scrollback'; } catch (_) { return 'scrollback'; }
  }());

  // Screen mirror constants
  var SCREEN_WIDTH = 128, SCREEN_HEIGHT = 64, SCREEN_FRAME_LEN = 1024;
  var SCREEN_KEEPALIVE_MS = 10000;

  // Screen mirror state
  var _screenState = { active: false, holderId: '', isHolder: false };
  var _screenCanvas = null;
  var _screenStatus = null;
  var _screenStartBtn = null;
  var _screenStopBtn = null;
  var _screenKeepaliveTimer = null;
  var _screenRenderPaused = false;
  var _screenConfirmDismissed = (function () {
    try { return sessionStorage.getItem('promptzero_screen_confirm_dismissed') === '1'; } catch (_) { return false; }
  }());

  /* =========================================================================
     DOM helpers
  ========================================================================= */

  function q(sel)    { return document.querySelector(sel); }
  function qAll(sel) { return document.querySelectorAll(sel); }

  /** Create element with optional class and textContent. */
  function mkEl(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls)             e.className    = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  /** Remove all children without touching innerHTML. */
  function clearEl(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  /* =========================================================================
     Auth bootstrap  (ported from app.js v0.8)
  ========================================================================= */

  function authBootstrap() {
    // 1. URL fragment  #token=xxx
    if (location.hash.indexOf('token=') !== -1) {
      try {
        var p = new URLSearchParams(location.hash.slice(1));
        var ft = p.get('token');
        if (ft) {
          _token = ft;
          try { sessionStorage.setItem('promptzero_token', ft); } catch (_) {}
          history.replaceState(null, '', location.pathname + location.search);
        }
      } catch (_) {}
    }
    // 2. sessionStorage
    if (!_token) {
      try { _token = sessionStorage.getItem('promptzero_token') || ''; } catch (_) {}
    }
    // 3. Ask server whether auth is required; prompt if so and no token yet
    return fetch('api/auth')
      .then(function (r) { return r.ok ? r.json() : { required: false }; })
      .catch(function ()  { return { required: false }; })
      .then(function (info) {
        if (!info.required) {
          _token = '';
          try { sessionStorage.removeItem('promptzero_token'); } catch (_) {}
          return;
        }
        if (!_token) {
          var entered = '';
          try { entered = window.prompt('PromptZero bearer token:') || ''; } catch (_) {}
          _token = entered.trim();
          if (_token) {
            try { sessionStorage.setItem('promptzero_token', _token); } catch (_) {}
          }
        }
      });
  }

  function apiFetch(path, opts) {
    opts = opts || {};
    if (_token) {
      opts.headers = Object.assign({}, opts.headers || {}, {
        'Authorization': 'Bearer ' + _token,
      });
    }
    return fetch(path, opts).then(function (r) {
      if (r.status === 401) {
        try { sessionStorage.removeItem('promptzero_token'); } catch (_) {}
        _token = '';
      }
      return r;
    });
  }

  /* =========================================================================
     Boot sequence
  ========================================================================= */

  function runBoot() {
    return new Promise(function (resolve) {
      var bootEl = document.getElementById('boot');
      var logEl  = document.getElementById('bootLog');
      var barEl  = document.getElementById('bootBar');
      if (!bootEl || !logEl || !barEl) { resolve(); return; }

      var total = BOOT_LINES.length;
      var i = 0;
      var done = false;

      function finish() {
        if (done) return;
        done = true;
        document.removeEventListener('keydown', skipHandler);
        bootEl.classList.add('gone');
        // Resolve after transition completes (or after safety timeout)
        var tid = setTimeout(resolve, 400);
        bootEl.addEventListener('transitionend', function () {
          clearTimeout(tid);
          resolve();
        }, { once: true });
      }

      function skipHandler(e) {
        // Space skips at any point; Enter confirms/continues (only meaningful once ready).
        if (e.key === ' ' || e.code === 'Space') { e.preventDefault(); finish(); return; }
        if (e.key === 'Enter' || e.code === 'Enter' || e.code === 'NumpadEnter') { e.preventDefault(); finish(); }
      }
      document.addEventListener('keydown', skipHandler);

      function markReady() {
        var hint = bootEl.querySelector('.boot-skip');
        if (hint) {
          hint.classList.add('ready');
          // Replace contextual hint: streaming SKIP → ready CONTINUE
          while (hint.firstChild) hint.removeChild(hint.firstChild);
          hint.appendChild(document.createTextNode('PRESS '));
          var kbd = document.createElement('kbd');
          kbd.textContent = 'ENTER';
          hint.appendChild(kbd);
          hint.appendChild(document.createTextNode(' TO CONTINUE'));
        }
        var ready = document.createElement('div');
        ready.className = 'ok';
        ready.textContent = '▸ READY — AWAITING USER             [HOLD]';
        logEl.appendChild(ready);
        logEl.scrollTop = logEl.scrollHeight;
        barEl.classList.add('pulse');
      }

      function tick() {
        if (done) return;
        if (i >= total) { markReady(); return; }   // hold open; wait for Space or Enter
        var line = BOOT_LINES[i++];
        var div = document.createElement('div');
        if (line.cls) div.className = line.cls;
        div.textContent = line.text;
        logEl.appendChild(div);
        logEl.scrollTop = logEl.scrollHeight;
        barEl.style.width = Math.round((i / total) * 100) + '%';
        setTimeout(tick, prefersReducedMotion() ? 8 : 280 + Math.random() * 100);
      }
      tick();
    });
  }

  /* =========================================================================
     Pixel mascot
  ========================================================================= */

  function buildMascot() {
    var m = document.getElementById('mascot');
    if (!m) return;
    for (var r = 0; r < MASCOT_ROWS.length; r++) {
      for (var c = 0; c < MASCOT_ROWS[r].length; c++) {
        var cell = document.createElement('i');
        var v = MASCOT_ROWS[r][c];
        if (v === 1)   cell.classList.add('on');
        else if (v === 'd') cell.classList.add('dim');
        else if (v === 'e') { cell.classList.add('dim'); cell.classList.add('eye'); }
        m.appendChild(cell);
      }
    }
    // Blinking cursor in idle line
    var il = document.getElementById('idleLine');
    if (il) {
      var cur = document.createElement('span');
      cur.className = 'blink-cursor';
      il.appendChild(cur);
    }
  }

  // Layered mascot idle. Each burst is scheduled independently with random
  // jitter so motion never feels metronomic. Bursts are mutually exclusive
  // for transform-based effects (laugh and float both replace the base
  // animation while active); blink and glow are additive (CSS only touches
  // eye cells), so they can fire concurrently with anything else.
  var _mascotTimers = { blink: null, laugh: null, float: null, glow: null };

  function _scheduleMascotEvent(key, minMs, maxMs, durationMs, className) {
    if (prefersReducedMotion()) return;
    var delay = minMs + Math.random() * (maxMs - minMs);
    _mascotTimers[key] = setTimeout(function () {
      var m = document.getElementById('mascot');
      if (m && m.style.display !== 'none') {
        m.classList.add(className);
        setTimeout(function () {
          if (m) m.classList.remove(className);
          _scheduleMascotEvent(key, minMs, maxMs, durationMs, className);
        }, durationMs);
      } else {
        _scheduleMascotEvent(key, minMs, maxMs, durationMs, className);
      }
    }, delay);
  }

  function startMascotIdle() {
    if (!_mascotTimers.blink) _scheduleMascotEvent('blink', 1800, 4500,  280, 'blinking');
    if (!_mascotTimers.glow)  _scheduleMascotEvent('glow',  2500, 6000, 1000, 'glowing');
    if (!_mascotTimers.float) _scheduleMascotEvent('float', 10000, 18000, 1600, 'floating');
    if (!_mascotTimers.laugh) _scheduleMascotEvent('laugh',  8000, 14000,  600, 'laughing');
  }

  function stopMascotIdle() {
    Object.keys(_mascotTimers).forEach(function (k) {
      if (_mascotTimers[k]) { clearTimeout(_mascotTimers[k]); _mascotTimers[k] = null; }
    });
    var m = document.getElementById('mascot');
    if (m) {
      m.classList.remove('blinking');
      m.classList.remove('glowing');
      m.classList.remove('floating');
      m.classList.remove('laughing');
    }
  }

  function showMascot() {
    var m = document.getElementById('mascot');
    var il = document.getElementById('idleLine');
    if (m)  m.style.display  = '';
    if (il) il.style.display = '';
    startMascotIdle();
  }

  function hideMascot() {
    var m = document.getElementById('mascot');
    var il = document.getElementById('idleLine');
    if (m)  m.style.display  = 'none';
    if (il) il.style.display = 'none';
    stopMascotIdle();
  }

  /* =========================================================================
     Web-audio beep
  ========================================================================= */

  function beep(freq, dur) {
    if (prefersReducedMotion()) return;
    try {
      if (!_beepCtx) _beepCtx = new (window.AudioContext || window.webkitAudioContext)();
      var osc  = _beepCtx.createOscillator();
      var gain = _beepCtx.createGain();
      osc.connect(gain);
      gain.connect(_beepCtx.destination);
      osc.type = 'square';
      osc.frequency.value = freq || 880;
      gain.gain.setValueAtTime(0.04, _beepCtx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, _beepCtx.currentTime + (dur || 0.08));
      osc.start(_beepCtx.currentTime);
      osc.stop(_beepCtx.currentTime + (dur || 0.08));
    } catch (_) {}
  }

  /* =========================================================================
     Drawer (mobile menu ≤900px)
  ========================================================================= */

  function setupDrawer() {
    var toggle   = document.getElementById('menuToggle');
    var rail     = document.getElementById('rail');
    var backdrop = document.getElementById('railBackdrop');
    if (!toggle || !rail || !backdrop) return;

    function openRail() {
      rail.classList.add('open');
      backdrop.classList.add('open');
      toggle.setAttribute('aria-expanded', 'true');
    }
    function closeRail() {
      rail.classList.remove('open');
      backdrop.classList.remove('open');
      toggle.setAttribute('aria-expanded', 'false');
    }

    toggle.addEventListener('click', function () {
      rail.classList.contains('open') ? closeRail() : openRail();
    });
    backdrop.addEventListener('click', closeRail);
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && rail.classList.contains('open')) closeRail();
    });
    window.addEventListener('resize', function () {
      if (window.innerWidth > 900) closeRail();
    });
    // Auto-close on item tap when drawer is open
    rail.addEventListener('click', function (e) {
      if (e.target.closest('.rail-item') && window.innerWidth <= 900) closeRail();
    });
  }

  /* =========================================================================
     Rail navigation
  ========================================================================= */

  function setupRailNav() {
    // Marauder panel visibility is server-side gated via marauder_available in the
    // initial status payload. Start hidden; dispatch() reveals it when confirmed.
    qAll('.rail-item[data-route="marauder"]').forEach(function (el) {
      el.style.display = 'none';
    });
    var marPill = document.getElementById('statMarauder');
    if (marPill) marPill.style.display = 'none';
    qAll('.rail-item[data-route]').forEach(function (item) {
      item.addEventListener('click', function () { activateRoute(item.dataset.route); });
      item.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); activateRoute(item.dataset.route); }
      });
    });
  }

  /* =========================================================================
     Rail collapse (icons-only) and per-group toggles
  ========================================================================= */

  function setupRailCollapse() {
    var btn    = document.getElementById('railCollapse');
    var device = document.querySelector('.device');
    var rail   = document.getElementById('rail');
    if (!btn || !device || !rail) return;

    function isMobile() { return window.innerWidth <= 900; }

    function applyCollapsed(collapsed) {
      device.classList.toggle('rail-collapsed', !!collapsed);
      btn.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
      btn.setAttribute('aria-label', collapsed ? 'Expand sidebar' : 'Collapse sidebar');
      btn.title = collapsed ? 'Expand sidebar' : 'Collapse sidebar';
    }

    var stored = '0';
    try { stored = localStorage.getItem('promptzero_rail_collapsed') || '0'; } catch (_) {}
    applyCollapsed(stored === '1');

    btn.addEventListener('click', function () {
      // On mobile this button is hidden, but guard anyway: close drawer.
      if (isMobile()) {
        rail.classList.remove('open');
        var bd = document.getElementById('railBackdrop');
        if (bd) bd.classList.remove('open');
        var mt = document.getElementById('menuToggle');
        if (mt) mt.setAttribute('aria-expanded', 'false');
        return;
      }
      var nowCollapsed = !device.classList.contains('rail-collapsed');
      applyCollapsed(nowCollapsed);
      try { localStorage.setItem('promptzero_rail_collapsed', nowCollapsed ? '1' : '0'); } catch (_) {}
    });
  }

  /* =========================================================================
     Quick Actions popover — shortcut prompts grouped by subsystem.
     Every item loads its prompt into the input for review/edit before
     the user dispatches it.
  ========================================================================= */

  function setupQuickActions() {
    var btn      = document.getElementById('qaToggle');
    var popover  = document.getElementById('qaPopover');
    var inputEl  = document.getElementById('cmd');
    if (!btn || !popover) return;

    var rendered = false;

    function open() {
      if (!rendered) { renderQuickActions(popover, close); rendered = true; }
      popover.hidden = false;
      btn.setAttribute('aria-expanded', 'true');
      var firstItem = popover.querySelector('.qa-item');
      if (firstItem) setTimeout(function () { firstItem.focus(); }, 0);
    }
    function close() {
      popover.hidden = true;
      btn.setAttribute('aria-expanded', 'false');
    }
    function toggle() { popover.hidden ? open() : close(); }

    btn.addEventListener('click', function (e) { e.stopPropagation(); toggle(); });
    document.addEventListener('click', function (e) {
      if (popover.hidden) return;
      if (popover.contains(e.target) || btn.contains(e.target)) return;
      close();
    });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && !popover.hidden) {
        close();
        if (inputEl) inputEl.focus();
      }
    });
  }

  function renderQuickActions(popover, closeFn) {
    clearEl(popover);

    var header = mkEl('div', 'qa-popover-header');
    header.appendChild(mkEl('span', null, 'QUICK ACTIONS'));
    header.appendChild(mkEl('span', null, 'ESC'));
    popover.appendChild(header);

    var hint = mkEl('div', 'qa-popover-hint',
      'Selecting an item loads the prompt for review — edit and TX when ready.');
    popover.appendChild(hint);

    var list = mkEl('div', 'qa-popover-list');
    Object.keys(CATEGORY_TOOLS).forEach(function (key) {
      var cat = CATEGORY_TOOLS[key];
      list.appendChild(mkEl('div', 'qa-cat-title', cat.title));
      cat.items.forEach(function (it) {
        var risk = String(it.risk || 'low').toLowerCase();

        var btn = mkEl('button', 'qa-item');
        btn.type = 'button';
        btn.setAttribute('role', 'menuitem');
        btn.title = it.prompt;
        btn.appendChild(mkEl('span', 'qa-item-label', it.label));

        var pill = mkEl('span', 'qa-item-pill', risk.toUpperCase());
        pill.dataset.risk = risk;
        btn.appendChild(pill);

        btn.addEventListener('click', function () {
          closeFn();
          var inp = document.getElementById('cmd');
          if (inp) { inp.value = it.prompt; }
          showAgentScreen();
          if (inp) { inp.focus(); inp.select(); }
        });
        list.appendChild(btn);
      });
    });
    popover.appendChild(list);
  }

  function setupRailGroups() {
    qAll('.rail-group').forEach(function (group) {
      var header = group.querySelector('.rail-group-header');
      var name   = group.dataset.group || '';
      if (!header || !name) return;

      var key = 'promptzero_rg_' + name + '_collapsed';
      var initial = group.classList.contains('collapsed') ? '1' : '0';
      var stored = initial;
      try { stored = localStorage.getItem(key); } catch (_) {}
      if (stored === null || stored === undefined) stored = initial;
      var collapsed = stored === '1';
      group.classList.toggle('collapsed', collapsed);
      header.setAttribute('aria-expanded', collapsed ? 'false' : 'true');

      header.addEventListener('click', function () {
        var nowCollapsed = !group.classList.contains('collapsed');
        group.classList.toggle('collapsed', nowCollapsed);
        header.setAttribute('aria-expanded', nowCollapsed ? 'false' : 'true');
        try { localStorage.setItem(key, nowCollapsed ? '1' : '0'); } catch (_) {}
      });
    });
  }

  function setActiveRailItem(route) {
    qAll('.rail-item[data-route]').forEach(function (i) {
      i.classList.toggle('active', i.dataset.route === route);
    });
  }

  /* =========================================================================
     Sessions sidebar — list of saved sessions, click to resume.

     The persisted store lives at ~/.promptzero/sessions; the agent
     auto-saves after every turn, so this list mirrors disk on each
     refresh. Resume / new / delete go through HTTP and the server
     broadcasts session_list_changed so peer tabs stay in sync.
  ========================================================================= */

  var _sessions = { active: '', list: [] };

  function setupSessions() {
    var newBtn = document.getElementById('newSessionBtn');
    if (newBtn) {
      newBtn.addEventListener('click', function () {
        beep(660, 0.05);
        apiFetch('api/sessions', { method: 'POST' })
          .then(function (r) { return r.ok ? r.json() : null; })
          .then(function (d) {
            if (!d) return;
            _sessions.active = d.id || '';
            resetConversation();
            showAgentScreen();
            refreshSessions();
          })
          .catch(function () {});
      });
    }
    refreshSessions();
  }

  function refreshSessions() {
    return apiFetch('api/sessions')
      .then(function (r) {
        if (r.status === 503) { hideSessionList(); return null; }
        return r.ok ? r.json() : null;
      })
      .then(function (d) {
        if (!d) return;
        _sessions.active = d.active || '';
        _sessions.list = Array.isArray(d.sessions) ? d.sessions : [];
        renderSessionList();
      })
      .catch(function () {});
  }

  function hideSessionList() {
    var group = document.querySelector('.rail-group[data-group="sessions"]');
    if (group) group.style.display = 'none';
  }

  function renderSessionList() {
    var listEl  = document.getElementById('sessionList');
    var emptyEl = document.getElementById('sessionListEmpty');
    if (!listEl) return;

    // Clear all rows except the empty-state hint (we re-show it below).
    var children = Array.prototype.slice.call(listEl.children);
    children.forEach(function (n) { if (n.id !== 'sessionListEmpty') listEl.removeChild(n); });

    if (!_sessions.list.length) {
      if (emptyEl) emptyEl.style.display = 'block';
      return;
    }
    if (emptyEl) emptyEl.style.display = 'none';

    _sessions.list.forEach(function (s) {
      listEl.appendChild(makeSessionRow(s));
    });
  }

  function makeSessionRow(s) {
    var row = mkEl('div', 'rail-session');
    row.setAttribute('role', 'button');
    row.tabIndex = 0;
    row.dataset.sessionId = s.id;
    if (s.active) row.classList.add('active');

    var dot = mkEl('span', 'dot');
    row.appendChild(dot);

    var titleLine = mkEl('div', 'title-line');
    var title = mkEl('span', 'title', s.title || 'Untitled session');
    titleLine.appendChild(title);
    var meta = mkEl('span', 'meta', formatSessionMeta(s));
    titleLine.appendChild(meta);
    row.appendChild(titleLine);

    var actions = mkEl('div', 'rail-session-actions');
    var rename = mkEl('button', null, '✎');
    rename.title = 'Rename';
    rename.type  = 'button';
    rename.addEventListener('click', function (e) { e.stopPropagation(); promptRename(s); });
    actions.appendChild(rename);
    var del = mkEl('button', null, '×');
    del.title = 'Delete';
    del.type  = 'button';
    del.style.fontSize = '12px';
    del.addEventListener('click', function (e) { e.stopPropagation(); promptDelete(s); });
    actions.appendChild(del);
    row.appendChild(actions);

    function open() { resumeSession(s.id); }
    row.addEventListener('click', open);
    row.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); }
    });
    return row;
  }

  function formatSessionMeta(s) {
    var n = (s.messages || 0);
    var label = (n === 1) ? '1 turn' : n + ' turns';
    var rel = relativeTime(s.updated_at);
    return rel ? (label + ' · ' + rel) : label;
  }

  function relativeTime(iso) {
    if (!iso) return '';
    var t = new Date(iso).getTime();
    if (!t) return '';
    var diff = Math.max(0, Date.now() - t) / 1000;
    if (diff < 60)        return Math.floor(diff) + 's ago';
    if (diff < 3600)      return Math.floor(diff / 60) + 'm ago';
    if (diff < 86400)     return Math.floor(diff / 3600) + 'h ago';
    if (diff < 86400 * 7) return Math.floor(diff / 86400) + 'd ago';
    return new Date(t).toISOString().slice(0, 10);
  }

  function resumeSession(id) {
    if (!id || id === _sessions.active) return;
    beep(660, 0.05);
    apiFetch('api/sessions/' + encodeURIComponent(id) + '/resume', { method: 'POST' })
      .then(function (r) {
        if (!r.ok) { addSysMsg('ERROR: failed to resume session'); return null; }
        return r.json();
      })
      .then(function (d) {
        if (!d) return;
        // Server will also emit session_switched + session_list_changed
        // on the websocket, but optimistically refresh now so the click
        // feels snappy.
        loadSessionTranscript(d.id);
      })
      .catch(function () {});
  }

  function loadSessionTranscript(id) {
    if (!id) return;
    return apiFetch('api/sessions/' + encodeURIComponent(id))
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        if (!d) return;
        _sessions.active = d.id;
        showAgentScreen();
        renderTranscript(d.events || []);
        var sid = document.getElementById('sessionId');
        if (sid) sid.textContent = (d.id || '').slice(0, 8);
        refreshSessions();
      })
      .catch(function () {});
  }

  function promptRename(s) {
    var current = s.title || '';
    var next;
    try { next = window.prompt('Rename session', current); } catch (_) { return; }
    if (next == null) return;
    next = String(next).trim();
    apiFetch('api/sessions/' + encodeURIComponent(s.id), {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title: next }),
    })
      .then(function (r) { if (r.ok) refreshSessions(); })
      .catch(function () {});
  }

  function promptDelete(s) {
    var label = s.title || s.id.slice(0, 8);
    var ok;
    try { ok = window.confirm('Delete session "' + label + '"?\nThis cannot be undone.'); } catch (_) { return; }
    if (!ok) return;
    apiFetch('api/sessions/' + encodeURIComponent(s.id), { method: 'DELETE' })
      .then(function (r) { if (r.ok) refreshSessions(); })
      .catch(function () {});
  }


  function activateRoute(route) {
    beep(660, 0.05);
    setActiveRailItem(route);

    // Mirror persists across route changes by design. The keepalive timer
    // is bound to _screenState.isHolder (set/cleared in onScreenStateMessage),
    // not to whether the device screen is currently visible, so the holder
    // stays alive across Files / Audit / Settings nav. When the user
    // returns to /device, loadDeviceScreen rebinds _screenCanvas to the
    // freshly-mounted canvas and refreshDeviceScreen reads the current
    // state to repaint LIVE/HELD/OFFLINE without losing the underlying
    // RPC stream.

    // Subsystem rail items show a category landing screen with tools/attacks.
    // The marauder route owns its own synthesised TFT panel (handled below);
    // its CATEGORY_TOOLS entry exists only so the items appear in the
    // Quick Actions popover.
    if (route !== 'marauder' && CATEGORY_TOOLS[route]) {
      showScreen('category-' + route);
      setCrumbs(CATEGORY_TOOLS[route].title, 'TOOLS');
      loadCategoryScreen(route);
      return;
    }

    // Leaving the marauder route — release holder and tear down attack timers.
    if (Marauder.isActive() && route !== 'marauder') Marauder.leave();

    if (route === 'marauder' && !_marauderAvailable) { showAgentScreen(); return; }

    switch (route) {
      case 'agent':    showAgentScreen();   break;
      case 'device':   showScreen('device');   setCrumbs('DEVICE', 'MIRROR');    loadDeviceScreen();   break;
      case 'marauder': showScreen('marauder'); setCrumbs('MARAUDER', 'MAIN');    Marauder.enter();     break;
      case 'files':    showScreen('files');    setCrumbs('FILES', 'BROWSE');    loadFilesScreen();    break;
      case 'audit':    showScreen('audit');    setCrumbs('AUDIT',   'LOG');      loadAuditScreen();    break;
      case 'report':   showScreen('report');   setCrumbs('REPORT',  'VALIDATE'); loadReportScreen();   break;
      case 'settings': showScreen('settings'); setCrumbs('SETTINGS','MAIN');     loadSettingsMenu();   break;
      default:         showAgentScreen();   break;
    }
  }

  /* =========================================================================
     Category landing screens — list of likely tools / attacks per subsystem
  ========================================================================= */

  function loadCategoryScreen(route) {
    var cat = CATEGORY_TOOLS[route];
    if (!cat) return;
    var ss = resetSubscreen(cat.title, backToAgent); if (!ss) return;

    var hint = mkEl('p', null, 'RUN dispatches immediately. Items with a risk badge load into the prompt so you can review/edit first.');
    hint.style.cssText = 'color:var(--lcd-pixel-soft);font-size:15px;margin:0 0 10px;';
    ss.appendChild(hint);

    cat.items.forEach(function (it) {
      var risk = String(it.risk || 'low').toLowerCase();
      var hasPlaceholder = /<[^>]+>/.test(it.prompt);
      var direct = (risk === 'low' && !hasPlaceholder);

      var div = mkEl('div', 'rail-item');
      div.tabIndex = 0;
      div.setAttribute('role', 'button');
      div.appendChild(mkEl('span', 'ic', direct ? '▶' : '▶'));

      div.appendChild(mkEl('span', 'label', it.label));

      var badge = mkEl('span', 'badge', direct ? 'RUN' : risk.toUpperCase());
      if (!direct && risk === 'med')  badge.style.color = 'var(--orange-hi)';
      if (!direct && risk === 'high') badge.style.color = 'var(--led-red)';
      div.appendChild(badge);

      div.title = it.prompt;

      var go = direct
        ? function () { showAgentScreen(); submitText(it.prompt); }
        : function () {
            var inp = document.getElementById('cmd');
            if (inp) { inp.value = it.prompt; }
            showAgentScreen();
            if (inp) { inp.focus(); inp.select(); }
          };

      div.addEventListener('click', go);
      div.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); }
      });
      ss.appendChild(div);
    });
  }

  /* =========================================================================
     Screen manager
  ========================================================================= */

  function ensureSubscreen() {
    if (_subscreenEl) return _subscreenEl;
    var lcdInner = q('.lcd-inner');
    if (!lcdInner) return null;
    _subscreenEl = document.createElement('div');
    _subscreenEl.id = 'subscreen';
    _subscreenEl.style.cssText = 'flex:1;min-height:0;overflow-y:auto;overscroll-behavior:contain;' +
      '-webkit-overflow-scrolling:touch;padding-right:6px;scrollbar-width:thin;' +
      'flex-direction:column;display:none;';
    var sb = document.getElementById('scrollback');
    lcdInner.insertBefore(_subscreenEl, sb || null);
    return _subscreenEl;
  }

  function showAgentScreen() {
    // If we were viewing a file, clear the agent's ui_context awareness
    if (_fsOpenPath) {
      sendUIContext('agent', '');
      _fsOpenPath = '';
    }
    _currentScreen = 'agent';
    var sb = document.getElementById('scrollback');
    var ss = ensureSubscreen();
    if (sb) sb.style.display = '';
    if (ss) ss.style.display = 'none';
    setCrumbs('AGENT', 'SESSION', _sessionId ? _sessionId.slice(0, 8) : '—');
    setActiveRailItem('agent');
  }

  function showScreen(name) {
    _currentScreen = name;
    var sb = document.getElementById('scrollback');
    var ss = ensureSubscreen();
    if (sb) sb.style.display = 'none';
    if (ss) { ss.style.display = 'flex'; clearEl(ss); }
  }

  function setCrumbs(c1, c2, c3) {
    var e1 = document.getElementById('crumb1');
    var e2 = document.getElementById('crumb2');
    var e3 = document.getElementById('sessionId');
    if (e1) e1.textContent = c1 || 'AGENT';
    if (e2) e2.textContent = c2 || 'SESSION';
    if (e3) e3.textContent = c3 !== undefined ? c3 : '—';
  }

  /** Append a sub-screen header with a left-aligned back button. */
  function appendSubscreenHeader(container, title, onBack) {
    var header = mkEl('div', 'subscreen-header');
    var back   = mkEl('button', 'subscreen-back', '◀ BACK');
    back.type  = 'button';
    back.setAttribute('aria-label', 'Back');
    back.addEventListener('click', function () { beep(440, 0.04); if (onBack) onBack(); });
    header.appendChild(back);
    if (title) header.appendChild(mkEl('span', 'subscreen-title', title));
    container.appendChild(header);
  }

  /** Shared back targets for sub-screens. */
  function backToAgent()    { showAgentScreen(); }
  function backToSettings() {
    showScreen('settings');
    setCrumbs('SETTINGS', 'MAIN');
    loadSettingsMenu();
    setActiveRailItem('settings');
  }
  function backFromFiles() {
    // Mobile: collapse preview to the tree first.
    if (_fsPreviewPane && _fsPreviewPane.dataset.visible === '1' && window.innerWidth < 900) {
      showFsTreeOnly();
      return;
    }
    // In a subdirectory: walk up one level instead of leaving the screen.
    if (_fsCwd && _fsCwd !== '/ext') {
      var parent = _fsCwd.replace(/\/[^\/]+$/, '') || '/ext';
      if (_fsTreePane) loadFsDir(parent, _fsTreePane, q('.fs-busy-warn'));
      return;
    }
    backToAgent();
  }

  /** Reset a sub-screen and re-append its header so the back button survives reloads. */
  function resetSubscreen(title, onBack) {
    var ss = ensureSubscreen(); if (!ss) return null;
    clearEl(ss);
    appendSubscreenHeader(ss, title, onBack);
    return ss;
  }

  /* =========================================================================
     D-pad
  ========================================================================= */

  function setupDpad() {
    qAll('.dpad button[data-dir]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var dir = btn.dataset.dir;
        var inp = document.getElementById('cmd');
        var sb  = document.getElementById('scrollback');

        // Mirror-mode takes priority: when this session holds the mirror,
        // the CLI input/send endpoint is locked, so route the press through
        // the held RPC session via the screen_input WS frame instead.
        if (_screenState && _screenState.isHolder) {
          beep(dir === 'ok' ? 880 : 660, 0.04);
          sendWs({ type: 'screen_input', button: dir, event_type: 'short' });
          return;
        }

        // Marauder route: route presses to MarauderUI's state machine when the
        // user has the synth-TFT panel open and dpad mode is device. Scroll
        // mode still falls through so the user can scroll the (otherwise
        // empty) scrollback if they want to.
        if (Marauder.isActive() && _dpadMode === 'device') {
          beep(dir === 'ok' ? 880 : 660, 0.04);
          Marauder.handleDpad(dir);
          return;
        }

        if (_dpadMode === 'device') {
          // In device mode (no mirror), forward via the CLI REST endpoint.
          beep(dir === 'ok' ? 880 : 660, 0.04);
          apiFetch('api/input/send', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ button: dir, event_type: 'short' }),
          }).then(function (r) {
            if (r && r.status === 409) {
              showToast('Flipper is mirrored — stop the mirror first to use this.');
            }
          }).catch(function () {});
          return;
        }

        // scrollback mode — original behaviour
        beep(dir === 'ok' ? 880 : 440, 0.04);
        switch (dir) {
          case 'up':
            if (document.activeElement === inp) historyUp();
            else if (sb) sb.scrollTop -= Math.round(sb.clientHeight * 0.35);
            break;
          case 'down':
            if (document.activeElement === inp) historyDown();
            else if (sb) sb.scrollTop += Math.round(sb.clientHeight * 0.35);
            break;
          case 'ok':
            if (inp) { var t = inp.value.trim(); if (t) { submitText(t); inp.value = ''; } }
            break;
          case 'back':
            handleBack();
            break;
        }
      });
    });

    // Keyboard navigation when focus is NOT in the input
    document.addEventListener('keydown', function (e) {
      var tag = (document.activeElement && document.activeElement.tagName) || '';
      var inInput = (tag === 'INPUT' || tag === 'TEXTAREA');

      if (e.key === 'Escape') {
        if (_confirmPending)           { e.preventDefault(); respondConfirm('deny'); return; }
        if (_currentScreen !== 'agent'){ e.preventDefault(); handleBack(); return; }
        if (_phase !== 'Idle')         { e.preventDefault(); cancelTurn(); return; }
      }
      if (!inInput) {
        // Marauder route owns arrow / Enter / Backspace when active so the
        // operator can navigate the synth TFT entirely from the keyboard.
        if (Marauder.isActive()) {
          var dir = (e.key === 'ArrowUp') ? 'up'
                  : (e.key === 'ArrowDown') ? 'down'
                  : (e.key === 'ArrowLeft') ? 'left'
                  : (e.key === 'ArrowRight') ? 'right'
                  : (e.key === 'Backspace' || e.key === 'Escape') ? 'back'
                  : (e.key === 'Enter' && Marauder.view() !== 'fire') ? 'ok'
                  : null;
          if (dir) {
            e.preventDefault();
            Marauder.handleDpad(dir);
            return;
          }
        }
        // Flipper mirror: arrow keys + Enter + Backspace map to the Flipper's
        // d-pad over the held RPC session — same wire frame as the on-screen
        // dpad click. Gated on the device screen so the keys still scroll
        // Files / Audit when the user navigates away mid-mirror.
        if (_screenState && _screenState.isHolder && _currentScreen === 'device') {
          var mdir = (e.key === 'ArrowUp')    ? 'up'
                   : (e.key === 'ArrowDown')  ? 'down'
                   : (e.key === 'ArrowLeft')  ? 'left'
                   : (e.key === 'ArrowRight') ? 'right'
                   : (e.key === 'Enter')      ? 'ok'
                   : (e.key === 'Backspace')  ? 'back'
                   : null;
          if (mdir) {
            e.preventDefault();
            beep(mdir === 'ok' ? 880 : 660, 0.04);
            sendWs({ type: 'screen_input', button: mdir, event_type: 'short' });
            return;
          }
        }
        var sb = document.getElementById('scrollback');
        if (e.key === 'ArrowUp')   { e.preventDefault(); if (sb) sb.scrollTop -= 60; }
        if (e.key === 'ArrowDown') { e.preventDefault(); if (sb) sb.scrollTop += 60; }
      }
    });
  }

  function setupDpadModeToggle() {
    var btn = document.getElementById('dpadModeToggle');
    if (!btn) return;
    applyDpadMode();
    btn.addEventListener('click', function () {
      _dpadMode = (_dpadMode === 'scrollback') ? 'device' : 'scrollback';
      try { sessionStorage.setItem('promptzero_dpad_mode', _dpadMode); } catch (_) {}
      // Distinctive beep: 660 Hz = scroll, 880 Hz = device
      beep(_dpadMode === 'device' ? 880 : 660, 0.1);
      applyDpadMode();
    });
  }

  function applyDpadMode() {
    var dpad = document.getElementById('dpad');
    var btn  = document.getElementById('dpadModeToggle');
    var holder = !!(_screenState && _screenState.isHolder);
    // Body attribute drives the .dpad show/hide rule in app.css. Outside
    // mirror mode the dpad has no useful behaviour (it'd just 409 against
    // the locked CLI input/send) so we hide it entirely.
    document.body.dataset.mirrorHolder = holder ? '1' : '';
    if (dpad) dpad.dataset.mode = holder ? 'mirror' : _dpadMode;
    if (btn) {
      btn.style.display = holder ? 'none' : '';
      btn.textContent = _dpadMode === 'device' ? 'DEVICE' : 'SCROLL';
      btn.setAttribute('aria-pressed', _dpadMode === 'device' ? 'true' : 'false');
    }
  }

  function handleBack() {
    if (_currentScreen === 'agent') return;
    if (_currentScreen === 'device') { backToAgent(); return; }
    if (_currentScreen === 'marauder') { Marauder.leave(); backToAgent(); return; }
    if (_currentScreen === 'files') { backFromFiles(); return; }
    // Settings sub-pages pop to the settings menu first, then to agent.
    if (_currentScreen.indexOf('settings-') === 0) { backToSettings(); return; }
    backToAgent();
  }

  /* =========================================================================
     Command history
  ========================================================================= */

  function setupHistory() {
    var inp = document.getElementById('cmd');
    if (!inp) return;
    inp.addEventListener('keydown', function (e) {
      if (e.key === 'ArrowUp')   { e.preventDefault(); historyUp();   }
      if (e.key === 'ArrowDown') { e.preventDefault(); historyDown(); }
    });
  }

  function historyUp() {
    var inp = document.getElementById('cmd');
    if (!inp || !_cmdHistory.length) return;
    if (_histIdx === -1) { _savedInput = inp.value; _histIdx = _cmdHistory.length - 1; }
    else if (_histIdx > 0) _histIdx--;
    inp.value = _cmdHistory[_histIdx];
    inp.setSelectionRange(inp.value.length, inp.value.length);
  }

  function historyDown() {
    var inp = document.getElementById('cmd');
    if (!inp || _histIdx === -1) return;
    _histIdx++;
    if (_histIdx >= _cmdHistory.length) { _histIdx = -1; inp.value = _savedInput; }
    else inp.value = _cmdHistory[_histIdx];
    inp.setSelectionRange(inp.value.length, inp.value.length);
  }

  /* =========================================================================
     Input form
  ========================================================================= */

  function setupInputForm() {
    var form = document.getElementById('inputForm');
    var inp  = document.getElementById('cmd');
    if (!form || !inp) return;
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      var text = inp.value.trim();
      if (!text) return;
      submitText(text);
      inp.value = '';
    });
  }

  function submitText(text) {
    _histIdx = -1;
    _savedInput = '';
    _cmdHistory.push(text);
    if (_cmdHistory.length > 50) _cmdHistory.shift();
    hideMascot();
    addUserMsg(text, false);
    sendWs({ type: 'text', content: text });
    setPhase('Thinking');
  }

  /* =========================================================================
     WebSocket client  (ported from app.js v0.8)
  ========================================================================= */

  function connect() {
    // Tear down any prior socket before opening to prevent stale-event double-delivery
    if (_ws) {
      try {
        _ws.onopen = null; _ws.onmessage = null;
        _ws.onclose = null; _ws.onerror  = null;
        _ws.close();
      } catch (_) {}
      _ws = null;
    }

    var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    var url   = proto + '//' + location.host + '/ws';
    // Token travels via Sec-WebSocket-Protocol (never in URL — avoids access-log leaks)
    var args  = _token ? ['bearer', _token] : undefined;
    var sock;
    try { sock = args ? new WebSocket(url, args) : new WebSocket(url); }
    catch (_) { scheduleReconnect(); return; }
    _ws = sock;

    sock.onopen = function () {
      if (_ws !== sock) return;
      _wsBackoff = 800;
      setModelTag('ready');
    };
    sock.onclose = function () {
      if (_ws !== sock) return;
      setModelTag('reconnecting…');
      scheduleReconnect();
    };
    sock.onerror = function () { /* handled by onclose */ };
    sock.binaryType = 'arraybuffer';
    sock.onmessage = function (ev) {
      if (_ws !== sock) return;
      if (ev.data instanceof ArrayBuffer) {
        onScreenBinaryFrame(ev.data);
        return;
      }
      var msg;
      try { msg = JSON.parse(ev.data); } catch (_) { return; }
      dispatch(msg);
    };
  }

  function scheduleReconnect() {
    var delay = Math.min(_wsBackoff, 8000);
    _wsBackoff = Math.min(Math.round(_wsBackoff * 1.6), 8000);
    setTimeout(connect, delay);
  }

  function sendWs(obj) {
    if (!_ws || _ws.readyState !== WebSocket.OPEN) return false;
    try { _ws.send(JSON.stringify(obj)); return true; } catch (_) { return false; }
  }

  /* =========================================================================
     WS message dispatch
  ========================================================================= */

  function dispatch(msg) {
    switch (msg.type) {

      case 'status':
        if (msg.content === 'connected') {
          if (msg.session_id) {
            _sessionId = msg.session_id;
            var sid = document.getElementById('sessionId');
            if (sid) sid.textContent = msg.session_id.slice(0, 8);
          }
          _marauderAvailable = !!msg.marauder_available;
          if (_marauderAvailable) {
            qAll('.rail-item[data-route="marauder"]').forEach(function (el) { el.style.display = ''; });
            var marPill2 = document.getElementById('statMarauder');
            if (marPill2) marPill2.style.display = '';
          }
          setModelTag('ready');
        } else if (msg.content === 'conversation reset') {
          resetConversation();
        } else if (msg.content === 'transcribing') {
          setModelTag('transcribing…');
        }
        break;

      case 'transcription':
        addUserMsg(msg.content || '', true);
        break;

      case 'response':
        finalizeStreaming(msg.turn_id, msg.content || '');
        setPhase('Idle');
        break;

      case 'error':
        finalizeStreaming(msg.turn_id, null);
        setPhase('Idle');
        addSysMsg('ERROR: ' + (msg.content || 'unknown error'));
        break;

      case 'text_delta':
        appendDelta(msg.turn_id, msg.content || '');
        break;

      case 'tool_status':
        if (msg.phase === 'start')  addToolStart(msg);
        else if (msg.phase === 'finish') finishTool(msg);
        break;

      case 'confirm_request':
        showConfirm(msg);
        break;

      case 'phase':
        onPhase(msg.verb, msg.turn_id);
        break;

      case 'persona_switched':
        _personas.current = msg.name || '';
        addSysMsg('● persona switched to ' + (msg.name || 'default'));
        break;

      case 'session_list_changed':
        refreshSessions();
        break;

      case 'session_switched':
        // The originating tab already pulled the transcript optimistically
        // and updated _sessions.active; for it this is a no-op replay.
        // Peer tabs reload the now-active conversation here.
        if (msg.fresh) {
          _sessions.active = msg.session_id || '';
          resetConversation();
          var sidEl = document.getElementById('sessionId');
          if (sidEl) sidEl.textContent = (msg.session_id || '').slice(0, 8);
          refreshSessions();
        } else if (msg.session_id && msg.session_id !== _sessions.active) {
          loadSessionTranscript(msg.session_id);
        }
        break;

      case 'screen_state':
        onScreenStateMessage(msg);
        break;

      case 'screen_error':
        onScreenErrorMessage(msg);
        break;

      case 'marauder_status':
      case 'marauder_event':
      case 'marauder_done':
      case 'marauder_error':
        Marauder.onMessage(msg);
        break;
    }
  }

  /* =========================================================================
     Phase
  ========================================================================= */

  function setPhase(phase) {
    _phase = phase;
    var labels = { Idle: 'ready', Thinking: 'thinking…', Running: 'running…', Responding: 'responding…' };
    setModelTag(labels[phase] || phase.toLowerCase() + '…');
  }

  function setModelTag(text) {
    var mt = document.getElementById('modelTag');
    if (mt) mt.textContent = text;
  }

  function onPhase(verb, turnId) {
    if (turnId) _currentTurnId = turnId;
    var v = String(verb || '').toLowerCase();
    var phase = (v === 'idle' || v === 'done' || v === '') ? 'Idle'
              : v.indexOf('running')   === 0              ? 'Running'
              : v.indexOf('respond')   === 0              ? 'Responding'
              :                                             'Thinking';
    setPhase(phase);
  }

  function cancelTurn() {
    sendWs({ type: 'cancel', turn_id: _currentTurnId });
    setPhase('Idle');
    if (_streamingMsgEl) {
      var c = _streamingMsgEl.querySelector('.blink-cursor-text');
      if (c) c.parentNode.removeChild(c);
    }
    _streamingMsgEl  = null;
    _streamingTurnId = null;
    clearConfirm();
  }

  /* =========================================================================
     Transcript replay — given the persisted event stream, rebuild the
     scrollback so a resumed session looks identical to the live one.
     Uses the same helpers as streaming: addUserMsg / makeAgentMsgEl /
     addToolStart / finishTool — the only difference is they fire
     synchronously back-to-back instead of being driven by ws frames.
  ========================================================================= */

  function renderTranscript(events) {
    resetConversation();
    if (!events || !events.length) { setPhase('Idle'); return; }
    hideMascot();
    var sb = document.getElementById('scrollback');
    var inFlightTool = {};   // tool_use_id -> wrap element

    for (var i = 0; i < events.length; i++) {
      var ev = events[i];
      if (!ev || !ev.kind) continue;
      switch (ev.kind) {
        case 'user_text':
          if (!ev.text) break;
          if (sb) {
            var m  = mkEl('div', 'msg user');
            var w  = mkEl('div', 'who', 'U');
            var b  = mkEl('div', 'body');
            var mt = mkEl('div', 'meta'); mt.appendChild(mkEl('span', null, 'YOU'));
            var p  = mkEl('p', null, ev.text);
            b.appendChild(mt); b.appendChild(p);
            m.appendChild(w); m.appendChild(b);
            sb.appendChild(m);
          }
          break;

        case 'assistant_text':
          if (!ev.text) break;
          if (sb) {
            var am  = mkEl('div', 'msg');
            var aw  = mkEl('div', 'who', 'PZ');
            var ab  = mkEl('div', 'body');
            var amt = mkEl('div', 'meta'); amt.appendChild(mkEl('span', null, 'PROMPTZERO'));
            var ap  = mkEl('p', null, ev.text);
            ab.appendChild(amt); ab.appendChild(ap);
            am.appendChild(aw); am.appendChild(ab);
            sb.appendChild(am);
          }
          break;

        case 'tool_use':
          // Synthesize a turn-id-less key so finishTool can pair the
          // matching tool_result. We use the real tool_use_id since the
          // SDK guarantees it's unique within a session.
          var startMsg = {
            turn_id: '',
            name:    ev.name || 'tool',
            input:   ev.input != null ? (typeof ev.input === 'string' ? ev.input : JSON.stringify(ev.input)) : '',
          };
          addToolStart(startMsg);
          // _toolEls keyed under '|name'; remember the wrap by tool_use_id
          // so the matching tool_result can find it without a turn id.
          var key = '|' + (ev.name || 'tool');
          if (_toolEls[key]) {
            inFlightTool[ev.tool_use_id] = _toolEls[key];
            delete _toolEls[key];
          }
          break;

        case 'tool_result':
          var wrap = inFlightTool[ev.tool_use_id];
          delete inFlightTool[ev.tool_use_id];
          if (!wrap) break;
          var indicator = wrap.querySelector('.tool-status-txt');
          if (indicator) indicator.textContent = ev.is_error ? 'failed' : 'done';
          var content = wrap.querySelector('.tool-details-content');
          if (content && (ev.output || ev.is_error)) {
            var tile = mkEl('div', 'tool-result');
            if (ev.output) {
              tile.appendChild(mkEl('span', 'k', ev.is_error ? 'error' : 'output'));
              var v = mkEl('span', 'v', ev.output);
              if (ev.is_error) v.style.color = 'var(--led-red)';
              tile.appendChild(v);
            }
            content.appendChild(tile);
          }
          if (ev.is_error) {
            var d = wrap.querySelector('details.tool-details');
            if (d) d.open = true;
          }
          break;
      }
    }
    if (sb) sb.scrollTop = sb.scrollHeight;
    setPhase('Idle');
  }

  function resetConversation() {
    var sb = document.getElementById('scrollback');
    if (!sb) return;
    // Remove dynamic message nodes; keep mascot + idle-line
    var toRemove = [];
    for (var n = sb.firstChild; n; n = n.nextSibling) {
      if (n.id !== 'mascot' && n.id !== 'idleLine') toRemove.push(n);
    }
    toRemove.forEach(function (n) { sb.removeChild(n); });
    showMascot();
    setPhase('Idle');
    _streamingMsgEl  = null;
    _streamingTurnId = null;
    _currentTurnId   = null;
    _toolEls         = {};
    clearConfirm();
  }

  /* =========================================================================
     Render — message bubbles
     RULE: every string that originates from the agent goes through textContent.
  ========================================================================= */

  function scrollSoon(sb) {
    if (_autoScrollPaused) return;
    requestAnimationFrame(function () { if (sb) sb.scrollTop = sb.scrollHeight; });
  }

  function addUserMsg(text, voice) {
    hideMascot();
    var sb = document.getElementById('scrollback');
    if (!sb) return;

    // A new user message always starts a fresh agent turn. Tear down any
    // lingering streaming bubble so the next text_delta cannot accidentally
    // re-use the previous turn's element (e.g. when the server didn't send
    // a clean `response`/`error` for the prior turn before this prompt).
    if (_streamingMsgEl) {
      var stale = _streamingMsgEl.querySelector('.blink-cursor-text');
      if (stale) stale.parentNode.removeChild(stale);
    }
    _streamingMsgEl  = null;
    _streamingTurnId = null;

    var msg  = mkEl('div', 'msg user');
    var who  = mkEl('div', 'who', 'U');
    var body = mkEl('div', 'body');
    var meta = mkEl('div', 'meta');
    meta.appendChild(mkEl('span', null, voice ? 'YOU · VOICE' : 'YOU'));
    var p = mkEl('p', null, text);   // textContent via mkEl — safe
    body.appendChild(meta);
    body.appendChild(p);
    msg.appendChild(who);
    msg.appendChild(body);
    sb.appendChild(msg);
    scrollSoon(sb);
  }

  function makeAgentMsgEl(turnId) {
    var sb = document.getElementById('scrollback');
    if (!sb) return null;

    var msg  = mkEl('div', 'msg');
    if (turnId) msg.dataset.turnId = turnId;
    var who  = mkEl('div', 'who', 'PZ');
    var body = mkEl('div', 'body');
    var meta = mkEl('div', 'meta');
    meta.appendChild(mkEl('span', null, 'PROMPTZERO'));
    var p    = mkEl('p');
    var caret = mkEl('span', 'blink-cursor-text');
    caret.setAttribute('aria-hidden', 'true');
    p.appendChild(caret);
    body.appendChild(meta);
    body.appendChild(p);
    msg.appendChild(who);
    msg.appendChild(body);
    sb.appendChild(msg);
    scrollSoon(sb);
    return msg;
  }

  function appendDelta(turnId, text) {
    // Re-use existing streaming element if same turn, otherwise start new one
    if (_streamingMsgEl && _streamingTurnId === turnId) {
      var p = _streamingMsgEl.querySelector('.body > p');
      if (p) {
        var caret = p.querySelector('.blink-cursor-text');
        var tn = document.createTextNode(text);  // safe: createTextNode
        if (caret) p.insertBefore(tn, caret);
        else p.appendChild(tn);
      }
    } else {
      if (_streamingMsgEl) {
        var oc = _streamingMsgEl.querySelector('.blink-cursor-text');
        if (oc) oc.parentNode.removeChild(oc);
      }
      _streamingMsgEl  = makeAgentMsgEl(turnId);
      _streamingTurnId = turnId;
      if (_streamingMsgEl && text) {
        var pp = _streamingMsgEl.querySelector('.body > p');
        if (pp) {
          var c2 = pp.querySelector('.blink-cursor-text');
          var tn2 = document.createTextNode(text);
          if (c2) pp.insertBefore(tn2, c2);
          else pp.appendChild(tn2);
        }
      }
    }
    var sb = document.getElementById('scrollback');
    if (sb) scrollSoon(sb);
  }

  function finalizeStreaming(turnId, text) {
    if (_streamingMsgEl && (!turnId || _streamingTurnId === turnId)) {
      var c = _streamingMsgEl.querySelector('.blink-cursor-text');
      if (c) c.parentNode.removeChild(c);
      // If we got a final response string but no delta was streamed, show it
      if (text) {
        var p = _streamingMsgEl.querySelector('.body > p');
        if (p && p.textContent.trim() === '') p.textContent = text;
      }
    } else if (text) {
      var el2 = makeAgentMsgEl(turnId);
      if (el2) {
        var p2 = el2.querySelector('.body > p');
        if (p2) {
          var c2 = p2.querySelector('.blink-cursor-text');
          if (c2) p2.removeChild(c2);
          p2.textContent = text;  // safe: textContent
        }
      }
    }
    _streamingMsgEl  = null;
    _streamingTurnId = null;
  }

  function addSysMsg(text) {
    var sb = document.getElementById('scrollback');
    if (!sb) return;
    var msg  = mkEl('div', 'msg sys');
    var who  = mkEl('div', 'who', '!');
    var body = mkEl('div', 'body');
    var p    = mkEl('p', null, text);  // textContent — safe
    body.appendChild(p);
    msg.appendChild(who);
    msg.appendChild(body);
    sb.appendChild(msg);
    scrollSoon(sb);
  }

  /* =========================================================================
     Tool status
  ========================================================================= */

  function addToolStart(msg) {
    var sb = document.getElementById('scrollback');
    if (!sb) return;

    // A tool call is a hard break in the agent's narration. Whatever
    // text was streaming up to this point belongs to the *pre-tool*
    // reasoning; anything that arrives after this tool finishes is the
    // *post-tool* answer. Finalising the current bubble here forces the
    // next text_delta to open a fresh one — otherwise both segments
    // would visually merge in the pre-tool bubble even though a tool
    // executed between them.
    if (_streamingMsgEl) {
      var oldCaret = _streamingMsgEl.querySelector('.blink-cursor-text');
      if (oldCaret) oldCaret.parentNode.removeChild(oldCaret);
    }
    _streamingMsgEl  = null;
    _streamingTurnId = null;

    var wrap = mkEl('div', 'msg sys tool');
    var key  = (msg.turn_id || '') + '|' + (msg.name || '');
    wrap.dataset.toolKey = key;

    var who  = mkEl('div', 'who', '▶');
    var body = mkEl('div', 'body');

    // Collapsible: <summary> shows the meta row (name + risk + status);
    // input/output live inside .tool-details-content and are hidden by
    // default. Clicking the summary toggles. Native <details> handles
    // a11y (keyboard, screen-reader announcement).
    var details = mkEl('details', 'tool-details');
    var summary = mkEl('summary');
    var meta = mkEl('div', 'meta');

    var chevron = mkEl('span', 'tool-chev', '▸');
    chevron.setAttribute('aria-hidden', 'true');
    meta.appendChild(chevron);

    var nameSpan = mkEl('span', 'tool-name', msg.name || 'tool');
    meta.appendChild(nameSpan);

    // Risk badge — only known enum strings flow through classList
    var risk = String(msg.risk || 'low').toLowerCase();
    if (risk === 'medium' || risk === 'high') {
      var riskEl = mkEl('span', 'risk' + (risk === 'medium' ? ' med' : ' high'));
      riskEl.textContent = risk.toUpperCase();
      meta.appendChild(riskEl);
    }

    var statusSpan = mkEl('span', 'tool-status-txt', 'running…');
    meta.appendChild(statusSpan);

    summary.appendChild(meta);
    details.appendChild(summary);

    var content = mkEl('div', 'tool-details-content');
    if (msg.input) {
      var pre = mkEl('pre', null, fmtJSON(msg.input));  // textContent — safe
      content.appendChild(pre);
    }
    details.appendChild(content);

    body.appendChild(details);
    wrap.appendChild(who);
    wrap.appendChild(body);
    sb.appendChild(wrap);
    _toolEls[key] = wrap;
    scrollSoon(sb);
  }

  function finishTool(msg) {
    var key  = (msg.turn_id || '') + '|' + (msg.name || '');
    var wrap = _toolEls[key];
    delete _toolEls[key];
    if (!wrap) return;

    var indicator = wrap.querySelector('.tool-status-txt');
    var suffix    = msg.duration_ms != null ? ' · ' + (msg.duration_ms / 1000).toFixed(2) + 's' : '';
    if (indicator) indicator.textContent = (msg.err ? 'failed' : 'done') + suffix;

    // Append output/error inside the collapsible body (.tool-details-content),
    // not directly to .body — that keeps the row compact when collapsed.
    var content = wrap.querySelector('.tool-details-content');
    if (content && (msg.output || msg.err)) {
      var tileDiv = mkEl('div', 'tool-result');
      if (msg.output) {
        tileDiv.appendChild(mkEl('span', 'k', 'output'));
        tileDiv.appendChild(mkEl('span', 'v', fmtJSON(msg.output)));  // textContent — safe
      }
      if (msg.err) {
        var ev = mkEl('span', 'v');
        ev.textContent = msg.err;  // textContent — safe
        ev.style.color = 'var(--led-red)';
        tileDiv.appendChild(mkEl('span', 'k', 'error'));
        tileDiv.appendChild(ev);
      }
      content.appendChild(tileDiv);
    }
    // Auto-open on error so the operator sees what failed without clicking.
    if (msg.err) {
      var d = wrap.querySelector('details.tool-details');
      if (d) d.open = true;
    }
    var sb = document.getElementById('scrollback');
    if (sb) scrollSoon(sb);
  }

  /* =========================================================================
     TX preview / confirm
  ========================================================================= */

  function showConfirm(msg) {
    _confirmPending = msg;
    clearTxPreview();

    var sb = document.getElementById('scrollback');
    if (!sb) return;

    var wrap = mkEl('div', 'tx-preview');
    wrap.id  = 'txPreviewWrap';

    var h3    = mkEl('h3');
    var blink = mkEl('span', 'blink');
    h3.appendChild(blink);
    h3.appendChild(document.createTextNode(' CONFIRM TOOL CALL'));
    wrap.appendChild(h3);

    var dl = mkEl('dl');
    appendDlRow(dl, 'TOOL',  msg.tool  || '');   // textContent — safe
    appendDlRow(dl, 'RISK',  (msg.risk || 'medium').toUpperCase());
    if (msg.input) appendDlRow(dl, 'INPUT', fmtJSON(msg.input));  // textContent — safe
    wrap.appendChild(dl);

    // Diff preview: medium-risk file-write tools attach a unified diff
    // so the operator can see what bytes change before approving.
    // Render line-by-line via textContent + per-line classes so we
    // never feed raw markup into innerHTML.
    if (msg.diff) wrap.appendChild(buildDiffBlock(msg.diff));

    var actions = mkEl('div', 'tx-actions');

    var denyBtn = mkEl('button', 'revise', 'DENY [N]');
    denyBtn.type = 'button';
    denyBtn.setAttribute('data-pz-confirm-deny', '');
    denyBtn.addEventListener('click', function () { respondConfirm('deny'); });

    var appBtn = mkEl('button', null, 'APPROVE [A]');
    appBtn.type = 'button';
    appBtn.addEventListener('click', function () { respondConfirm('approve'); });

    var allBtn = mkEl('button', null, 'APPROVE ALL [L]');
    allBtn.type = 'button';
    allBtn.addEventListener('click', function () { respondConfirm('approve_all'); });

    var countdown = mkEl('span', 'countdown', '30s');
    countdown.id = 'txCountdown';

    actions.appendChild(denyBtn);
    actions.appendChild(appBtn);
    actions.appendChild(allBtn);
    actions.appendChild(countdown);
    wrap.appendChild(actions);
    sb.appendChild(wrap);
    scrollSoon(sb);

    // Focus deny (safe default)
    setTimeout(function () { denyBtn.focus(); }, 40);

    // Auto-deny countdown
    var left = 30;
    if (_countdownTimer) clearInterval(_countdownTimer);
    _countdownTimer = setInterval(function () {
      left--;
      countdown.textContent = left + 's';
      if (left <= 0) { clearInterval(_countdownTimer); _countdownTimer = null; respondConfirm('deny'); }
    }, 1000);

    document.addEventListener('keydown', confirmKeyHandler);
  }

  function confirmKeyHandler(e) {
    if (!_confirmPending) { document.removeEventListener('keydown', confirmKeyHandler); return; }
    var tag = (document.activeElement && document.activeElement.tagName) || '';
    if (tag === 'INPUT' || tag === 'TEXTAREA') return;
    var k = e.key.toLowerCase();
    if (k === 'a')                     { e.preventDefault(); respondConfirm('approve');     }
    else if (k === 'l')                { e.preventDefault(); respondConfirm('approve_all'); }
    else if (k === 'n' || k === 'escape') { e.preventDefault(); respondConfirm('deny');  }
  }

  function respondConfirm(decision) {
    if (!_confirmPending) return;
    sendWs({ type: 'confirm_response', confirm_id: _confirmPending.confirm_id, decision: decision });
    clearConfirm();
  }

  function clearConfirm() {
    _confirmPending = null;
    if (_countdownTimer) { clearInterval(_countdownTimer); _countdownTimer = null; }
    document.removeEventListener('keydown', confirmKeyHandler);
    clearTxPreview();
  }

  function clearTxPreview() {
    var prev = document.getElementById('txPreviewWrap');
    if (prev && prev.parentNode) prev.parentNode.removeChild(prev);
  }

  function appendDlRow(dl, label, value) {
    dl.appendChild(mkEl('dt', null, label));
    dl.appendChild(mkEl('dd', null, value));  // textContent via mkEl — safe
  }

  /** Render a unified-diff string into a <pre> with per-line styling.
   *  Each line goes through textContent only — colour comes from CSS
   *  classes keyed off the first character (-, +, @, space). */
  function buildDiffBlock(diffText) {
    var pre = mkEl('pre', 'tx-diff');
    var lines = String(diffText).split('\n');
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      var cls = 'tx-diff-line';
      if (line.indexOf('--- ') === 0 || line.indexOf('+++ ') === 0) {
        cls += ' tx-diff-file';
      } else if (line.charAt(0) === '@') {
        cls += ' tx-diff-hunk';
      } else if (line.charAt(0) === '-') {
        cls += ' tx-diff-del';
      } else if (line.charAt(0) === '+') {
        cls += ' tx-diff-add';
      }
      // mkEl uses textContent — no XSS path even if the diff body
      // contains HTML, script tags, or stray angle brackets.
      pre.appendChild(mkEl('div', cls, line));
    }
    return pre;
  }

  /* =========================================================================
     Status bar — /api/device + /api/debug polling
  ========================================================================= */

  function startDevicePoll() {
    pollDevice();
    // 5 s cadence: the status pills (FLIPPER, MARAUDER, BLE, SD, battery)
    // need to reflect connect/disconnect events within a few seconds of
    // the underlying setup steps completing. The previous 30 s interval
    // meant the Marauder pill could stay grey for half a minute after
    // a successful bridge launch. The endpoint is cached server-side
    // for 5 s already (deviceCacheTTL), so polling at the cache TTL
    // costs at most one extra Flipper round-trip per window.
    _deviceTimer = setInterval(pollDevice, 5000);
  }

  function pollDevice() {
    // While the mirror is held the endpoint always returns 409, which the
    // browser logs as a failed resource load. Skip the request entirely so
    // DevTools stays clean; state arrives via screen_state WS frames.
    if (_screenState && _screenState.active) return;
    apiFetch('api/device')
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (body) { if (body) applyDeviceToStatusBar(body); })
      .catch(function () {});
  }

  // Re-poll the device status as soon as the tab becomes visible again
  // — without this the user can switch tabs before the bridge attaches,
  // come back, and stare at stale "off" pills until the next 5 s tick.
  document.addEventListener('visibilitychange', function () {
    if (document.visibilityState === 'visible') {
      pollDevice();
    }
  });

  function applyDeviceToStatusBar(body) {
    // ── Flipper LED + port label ────────────────────────────────────────────
    var flipperData = body.flipper || {};
    var flipperEl   = document.getElementById('statFlipper');
    if (flipperEl) {
      flipperEl.dataset.state = flipperData.connected ? 'on' : 'off';
      var flipTxt = flipperEl.querySelector('span:last-child');
      if (flipTxt) flipTxt.textContent = 'FLIPPER' + (flipperData.port ? ' · ' + flipperData.port : '');
    }

    // ── Marauder LED + port label ───────────────────────────────────────────
    var marauderData = body.marauder || {};
    var marauderEl   = document.getElementById('statMarauder');
    if (marauderEl) {
      marauderEl.dataset.state = marauderData.connected ? 'on' : 'off';
      var marTxt = marauderEl.querySelector('span:last-child');
      if (marTxt) marTxt.textContent = 'MARAUDER' + (marauderData.port ? ' · ' + marauderData.port : '');
    }

    // ── BLE LED ─────────────────────────────────────────────────────────────
    var bleData = body.ble || {};
    var bleEl   = document.getElementById('statBLE');
    if (bleEl) bleEl.dataset.state = bleData.state || 'off';

    // ── Battery ─────────────────────────────────────────────────────────────
    var bat = body.battery || {};
    // Prefer the new typed `percent` field; fall back to legacy charge_level string
    var pct = (bat.percent !== undefined) ? Number(bat.percent) : parseInt(bat.charge_level, 10);
    if (isFinite(pct) && pct > 0) {
      pct = Math.max(0, Math.min(100, pct));
      var fill  = document.getElementById('battFill');
      var pctEl = document.getElementById('battPct');
      if (fill)  fill.style.width  = pct + '%';
      if (pctEl) pctEl.textContent = pct + '%';
    }

    // ── SD card bars + text ──────────────────────────────────────────────────
    // Prefer new typed sd.{free_bytes,total_bytes}; fall back to storage strings.
    var sdData     = body.sd || {};
    var totalBytes = Number(sdData.total_bytes || (body.storage && body.storage.storage_sdcard_totalSpace) || 0);
    var freeBytes  = Number(sdData.free_bytes  || (body.storage && body.storage.storage_sdcard_freeSpace)  || 0);
    var sdText = document.getElementById('sdText');
    if (sdText) sdText.textContent = totalBytes > 0 ? fmtBytes(freeBytes) + '/' + fmtBytes(totalBytes) : '—';
    var freePct = totalBytes > 0 ? Math.round((freeBytes / totalBytes) * 100) : 100;
    var barsLit = Math.min(4, Math.ceil(freePct / 25));
    qAll('.sd .bars span').forEach(function (b, idx) { b.classList.toggle('off', idx >= barsLit); });
  }

  /* =========================================================================
     Cost pill  — polled every 5 s, surfaced in status-meta when non-zero
  ========================================================================= */

  function startCostPoll() {
    pollCost();
    _costTimer = setInterval(pollCost, 5000);
  }

  function pollCost() {
    apiFetch('api/cost')
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (body) {
        if (!body) return;
        var total  = body.total || {};
        var usd    = Number(total.usd || 0);
        var tokens = Number(total.input_tokens || 0) + Number(total.output_tokens || 0);
        updateSessionInfo(body, total);
        var meta   = q('.status-meta');
        if (!meta) return;
        var pill = document.getElementById('costPill');
        if (usd > 0 || tokens > 0) {
          if (!pill) {
            pill = mkEl('div', 'stat');
            pill.id     = 'costPill';
            pill.style.cursor = 'pointer';
            pill.title  = 'session cost — click to open';
            pill.setAttribute('role', 'button');
            pill.setAttribute('tabindex', '0');
            pill.addEventListener('click', function () {
              showScreen('settings-cost');
              setCrumbs('SETTINGS', 'COST');
              loadCostScreen();
            });
            meta.appendChild(pill);
          }
          pill.textContent = fmtUSD(usd) + ' · ' + fmtTokens(tokens);
        } else if (pill) {
          meta.removeChild(pill);
        }
      })
      .catch(function () {});
  }

  function updateSessionInfo(body, total) {
    var el = document.getElementById('sessionInfo');
    if (!el) return;
    var byModel = Array.isArray(body.by_model) ? body.by_model : [];
    var rawModel = (byModel[0] && byModel[0].model) || '';
    var parts = [];
    var modelLabel = formatModelName(rawModel);
    if (modelLabel) parts.push(modelLabel);
    var cacheTotal = Number(total.cache_read_tokens || 0) + Number(total.cache_creation_tokens || 0);
    if (cacheTotal > 0) {
      var rate = Number(total.cache_hit_rate || 0);
      parts.push('prompt-cache ' + Math.round(rate * 100) + '%');
    }
    if (parts.length === 0) {
      el.hidden = true;
      el.textContent = '';
      return;
    }
    el.hidden = false;
    el.textContent = parts.join(' · ');
  }

  // Convert API model IDs ("claude-opus-4-7", "claude-sonnet-4-6-20251001")
  // into a display form ("claude-opus 4.7"). Falls back to the raw ID.
  function formatModelName(model) {
    if (!model) return '';
    var m = String(model).match(/^(claude-(?:opus|sonnet|haiku))-(\d+)-(\d+)/);
    if (!m) return model;
    return m[1] + ' ' + m[2] + '.' + m[3];
  }

  /* =========================================================================
     Settings screens
  ========================================================================= */

  function loadSettingsMenu() {
    var ss = resetSubscreen('SETTINGS', backToAgent);
    if (!ss) return;

    var items = [
      ['persona', 'PERSONA',    'Switch agent persona'],
      ['rules',   'RULES',      'Reactive automation'],
      ['cost',    'COST',       'Token usage & spend'],
      ['watch',   'FILE WATCH', 'Filesystem triggers'],
      ['debug',   'DEBUG',      'Runtime snapshot'],
      ['about',   'ABOUT',      'Version & build'],
    ];
    items.forEach(function (item) {
      var div = mkEl('div', 'rail-item');
      div.tabIndex = 0;
      div.setAttribute('role', 'button');
      div.appendChild(mkEl('span', 'ic', '▶'));
      div.appendChild(mkEl('span', 'label', item[1]));
      div.appendChild(mkEl('span', 'badge', '▶'));
      if (item[2]) div.title = item[2];
      div.addEventListener('click', function () { openSettingsSubscreen(item[0]); });
      div.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openSettingsSubscreen(item[0]); }
      });
      ss.appendChild(div);
    });
  }

  function openSettingsSubscreen(id) {
    showScreen('settings-' + id);
    var labels = { persona: 'PERSONA', rules: 'RULES', cost: 'COST', watch: 'WATCH', debug: 'DEBUG', about: 'ABOUT' };
    setCrumbs('SETTINGS', labels[id] || id.toUpperCase());
    var loaders = { persona: loadPersonaScreen, rules: loadRulesScreen, cost: loadCostScreen,
                    watch: loadWatchScreen, debug: loadDebugScreen, about: loadAboutScreen };
    if (loaders[id]) loaders[id]();
  }

  /* --- Persona --- */
  function loadPersonaScreen() {
    var ss = resetSubscreen('PERSONA', backToSettings); if (!ss) return;
    ss.appendChild(mkEl('p', null, 'Loading…'));
    apiFetch('api/personas')
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        ss = resetSubscreen('PERSONA', backToSettings); if (!ss) return;
        if (!data) { ss.appendChild(mkEl('p', null, 'Personas not configured.')); return; }
        _personas.current = data.current || '';
        var list = Array.isArray(data.available) ? data.available : [];
        if (!list.length) { ss.appendChild(mkEl('p', null, 'No personas available.')); return; }
        list.forEach(function (p) {
          var div = mkEl('div', 'rail-item' + (p.name === _personas.current ? ' active' : ''));
          div.tabIndex = 0; div.setAttribute('role', 'button');
          div.appendChild(mkEl('span', 'ic', '◆'));
          div.appendChild(mkEl('span', 'label', p.name));          // textContent — safe
          div.appendChild(mkEl('span', 'badge', p.unrestricted ? 'ALL' : (p.tools || 0) + 't'));
          if (p.description) div.title = p.description;
          div.addEventListener('click', function () { doSwitchPersona(p.name); });
          div.addEventListener('keydown', function (e) {
            if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); doSwitchPersona(p.name); }
          });
          ss.appendChild(div);
        });
      })
      .catch(function () {
        ss = resetSubscreen('PERSONA', backToSettings);
        if (ss) ss.appendChild(mkEl('p', null, 'Failed to load personas.'));
      });
  }

  function doSwitchPersona(name) {
    apiFetch('api/personas/switch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: name }),
    })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) { if (data) { _personas.current = data.current || name; loadPersonaScreen(); } })
      .catch(function () {});
  }

  /* --- Rules --- */
  function loadRulesScreen() {
    var ss = resetSubscreen('RULES', backToSettings); if (!ss) return;
    ss.appendChild(mkEl('p', null, 'Loading…'));
    apiFetch('api/rules')
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        ss = resetSubscreen('RULES', backToSettings); if (!ss) return;
        var list = Array.isArray(data) ? data : [];
        if (!list.length) { ss.appendChild(mkEl('p', null, 'No rules loaded.')); return; }
        list.forEach(function (rule) {
          var div = mkEl('div');
          div.style.cssText = 'padding:8px 0;border-bottom:1px solid var(--lcd-pixel-soft);';
          var head = mkEl('div');
          head.style.cssText = 'display:flex;align-items:center;gap:10px;';
          var nm = mkEl('span', null, rule.name);   // textContent — safe
          nm.style.fontFamily = 'var(--mono)';
          var st = mkEl('span', null, rule.enabled ? '● ACTIVE' : '○ PAUSED');
          st.style.color = rule.enabled ? 'var(--led-green)' : 'var(--led-off)';
          head.appendChild(nm); head.appendChild(st);
          if (rule.fire_count) head.appendChild(mkEl('span', null, rule.fire_count + ' fires'));
          div.appendChild(head);
          if (rule.description) div.appendChild(mkEl('p', null, rule.description));  // textContent — safe
          var acts = mkEl('div');
          acts.style.cssText = 'display:flex;gap:8px;margin-top:4px;';
          var togBtn = makeSmallBtn(rule.enabled ? 'PAUSE' : 'RESUME', function () { doToggleRule(rule.name, !rule.enabled); });
          var tstBtn = makeSmallBtn('TEST', function () { doTestRule(rule.name, div); });
          acts.appendChild(togBtn); acts.appendChild(tstBtn);
          div.appendChild(acts);
          ss.appendChild(div);
        });
      })
      .catch(function () {
        ss = resetSubscreen('RULES', backToSettings);
        if (ss) ss.appendChild(mkEl('p', null, 'Rules engine not configured.'));
      });
  }

  function doToggleRule(name, shouldEnable) {
    apiFetch('api/rules/' + encodeURIComponent(name) + '/' + (shouldEnable ? 'resume' : 'pause'), { method: 'POST' })
      .then(function () { loadRulesScreen(); }).catch(function () {});
  }

  function doTestRule(name, parentEl) {
    apiFetch('api/rules/' + encodeURIComponent(name) + '/test', { method: 'POST' })
      .then(function (r) { return r.json(); })
      .then(function (body) {
        var old = parentEl.querySelector('.rule-test-out');
        if (old) parentEl.removeChild(old);
        var pre = mkEl('pre', 'rule-test-out');
        pre.style.cssText = 'background:var(--lcd-pixel);color:var(--lcd-bg);padding:6px;font-family:var(--mono);font-size:12px;margin-top:4px;';
        pre.textContent = Array.isArray(body.actions) ? body.actions.join('\n') : (body.error || 'no actions');
        parentEl.appendChild(pre);
      }).catch(function () {});
  }

  /* --- Cost --- */
  function loadCostScreen() {
    var ss = resetSubscreen('COST', backToSettings); if (!ss) return;
    ss.appendChild(mkEl('p', null, 'Loading…'));
    apiFetch('api/cost')
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (body) {
        ss = resetSubscreen('COST', backToSettings); if (!ss) return;
        if (!body) { ss.appendChild(mkEl('p', null, 'Cost tracker not configured.')); return; }
        var total  = body.total || {};
        var usd    = Number(total.usd || 0);
        var inTok  = Number(total.input_tokens  || 0);
        var outTok = Number(total.output_tokens || 0);
        var big = mkEl('div', null, fmtUSD(usd));
        big.style.cssText = 'font-family:var(--pixel);font-size:16px;color:var(--orange);margin-bottom:6px;';
        ss.appendChild(big);
        ss.appendChild(mkEl('div', null, fmtTokens(inTok + outTok) + ' tokens · ' + fmtTokens(inTok) + ' in · ' + fmtTokens(outTok) + ' out'));
        if (body.offline) {
          var ol = mkEl('div', null, 'OFFLINE ESTIMATE');
          ol.style.color = 'var(--orange-hi)';
          ss.appendChild(ol);
        }
        var byModel = Array.isArray(body.by_model) ? body.by_model : [];
        if (byModel.length) {
          ss.appendChild(mkEl('div', null, 'BY MODEL:'));
          byModel.forEach(function (m) {
            var row = mkEl('div');
            row.style.cssText = 'display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid var(--lcd-pixel-soft);font-family:var(--mono);font-size:14px;';
            row.appendChild(mkEl('span', null, m.model || '(unknown)'));
            row.appendChild(mkEl('span', null, fmtUSD(m.usd) + ' · ' + fmtTokens((m.input_tokens || 0) + (m.output_tokens || 0)) + ' tok'));
            ss.appendChild(row);
          });
        }
      })
      .catch(function () {
        ss = resetSubscreen('COST', backToSettings);
        if (ss) ss.appendChild(mkEl('p', null, 'Failed to load cost.'));
      });
  }

  /* --- Watch --- */
  function loadWatchScreen() {
    var ss = resetSubscreen('WATCH', backToSettings); if (!ss) return;
    ss.appendChild(mkEl('p', null, 'Loading…'));
    apiFetch('api/watch')
      .then(function (r) { return r.json().then(function (b) { return { ok: r.ok, body: b }; }); })
      .then(function (res) {
        ss = resetSubscreen('WATCH', backToSettings); if (!ss) return;
        if (!res.ok) {
          var msg = (res.body && res.body.error) || 'watch unavailable';
          if (msg === 'watcher not configured') msg = 'Watcher not enabled — launch with --watch';
          ss.appendChild(mkEl('p', null, msg));
          return;
        }
        var body = res.body;
        var row = mkEl('div');
        row.style.cssText = 'display:flex;align-items:center;gap:12px;margin-bottom:12px;';
        var pill = mkEl('span', null, body.paused ? 'PAUSED' : 'ACTIVE');
        pill.style.cssText = 'font-family:var(--pixel);font-size:9px;padding:4px 8px;background:' + (body.paused ? 'var(--lcd-pixel-soft)' : 'var(--lcd-pixel)') + ';color:var(--lcd-bg);';
        row.appendChild(pill);
        var paths = Array.isArray(body.paths) ? body.paths : [];
        row.appendChild(mkEl('span', null, paths.length + ' path' + (paths.length === 1 ? '' : 's')));
        var togBtn = makeSmallBtn(body.paused ? 'RESUME' : 'PAUSE', function () {
          apiFetch('api/watch/' + (body.paused ? 'resume' : 'pause'), { method: 'POST' })
            .then(function () { loadWatchScreen(); }).catch(function () {});
        });
        togBtn.style.marginLeft = 'auto';
        row.appendChild(togBtn);
        ss.appendChild(row);

        ss.appendChild(mkEl('div', null, 'RULES:'));
        var rules = Array.isArray(body.rules) ? body.rules : [];
        if (!rules.length) ss.appendChild(mkEl('p', null, 'No rules configured.'));
        else rules.forEach(function (r) {
          var d = mkEl('div');
          d.style.cssText = 'padding:6px 0;border-bottom:1px solid var(--lcd-pixel-soft);';
          var pat = mkEl('div', null, r.pattern || '');
          pat.style.fontFamily = 'var(--mono)';
          d.appendChild(pat);
          d.appendChild(mkEl('div', null, r.prompt || ''));
          ss.appendChild(d);
        });

        ss.appendChild(mkEl('div', null, 'RECENT EVENTS:'));
        var evts = Array.isArray(body.recent_events) ? body.recent_events : [];
        if (!evts.length) ss.appendChild(mkEl('p', null, 'No recent events.'));
        else evts.forEach(function (ev) {
          var d = mkEl('div');
          d.style.cssText = 'padding:4px 0;border-bottom:1px solid var(--lcd-pixel-soft);font-size:14px;';
          d.appendChild(mkEl('div', null, (ev.at ? new Date(ev.at).toLocaleTimeString() : '') + ' · ' + (ev.rule || '')));
          d.appendChild(mkEl('div', null, ev.path || ''));
          if (ev.error) { var ee = mkEl('div', null, ev.error); ee.style.color = 'var(--led-red)'; d.appendChild(ee); }
          ss.appendChild(d);
        });
      })
      .catch(function () {
        ss = resetSubscreen('WATCH', backToSettings);
        if (ss) ss.appendChild(mkEl('p', null, 'Failed to load watch state.'));
      });
  }

  /* --- Debug --- */
  function loadDebugScreen() {
    var ss = resetSubscreen('DEBUG', backToSettings); if (!ss) return;
    ss.appendChild(mkEl('p', null, 'Loading…'));
    apiFetch('api/debug')
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (body) {
        ss = resetSubscreen('DEBUG', backToSettings); if (!ss) return;
        if (!body) { ss.appendChild(mkEl('p', null, 'Debug unavailable.')); return; }
        var sections = [
          ['BUILD',   [ ['version', (body.build   && body.build.version)   || '—'],
                        ['commit',  (body.build   && body.build.commit)    || '—'],
                        ['date',    (body.build   && body.build.date)      || '—'] ]],
          ['RUNTIME', [ ['goroutines', String((body.runtime && body.runtime.goroutines) || 0)],
                        ['heap/sys',   ((body.runtime && body.runtime.heap_mb) || 0) + ' / ' + ((body.runtime && body.runtime.sys_mb) || 0) + ' MB'],
                        ['uptime',     ((body.runtime && body.runtime.uptime_seconds) || 0) + 's'],
                        ['go',         (body.runtime && body.runtime.go_version) || '—'] ]],
          ['STATE',   [ ['persona',     (body.state && body.state.persona)            || 'default'],
                        ['flipper',     (body.state && body.state.flipper_connected)  ? 'online' : 'offline'],
                        ['marauder',    (body.state && body.state.marauder_connected) ? 'online' : 'offline'],
                        ['connections', String((body.state && body.state.active_connections) || 0)] ]],
        ];
        sections.forEach(function (sec) {
          ss.appendChild(mkEl('div', null, sec[0] + ':'));
          var grid = mkEl('div');
          grid.style.cssText = 'display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:6px 0 14px;font-family:var(--mono);font-size:14px;';
          sec[1].forEach(function (kv) {
            var k = mkEl('span', null, kv[0]); k.style.color = 'var(--lcd-pixel-soft)';
            grid.appendChild(k);
            grid.appendChild(mkEl('span', null, kv[1]));
          });
          ss.appendChild(grid);
        });
        var copyBtn = makeSmallBtn('COPY JSON', function () {
          try {
            navigator.clipboard.writeText(JSON.stringify(body, null, 2));
            copyBtn.textContent = 'COPIED';
            setTimeout(function () { copyBtn.textContent = 'COPY JSON'; }, 1500);
          } catch (_) {}
        });
        copyBtn.style.marginTop = '8px';
        ss.appendChild(copyBtn);
      })
      .catch(function () {
        ss = resetSubscreen('DEBUG', backToSettings);
        if (ss) ss.appendChild(mkEl('p', null, 'Debug unavailable.'));
      });
  }

  /* --- About --- */
  function loadAboutScreen() {
    var ss = resetSubscreen('ABOUT', backToSettings); if (!ss) return;
    apiFetch('api/debug')
      .then(function (r) { return r.ok ? r.json() : {}; })
      .catch(function () { return {}; })
      .then(function (body) {
        var build = (body && body.build) || {};
        [['PROMPTZERO', build.version || '—'],
         ['COMMIT',     build.commit  || '—'],
         ['DATE',       build.date    || '—'],
         ['MODULE',     'github.com/xunholy/promptzero'],
         ['LICENSE',    'AGPL-3.0-or-later'],
        ].forEach(function (kv) {
          var row = mkEl('div');
          row.style.cssText = 'display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--lcd-pixel-soft);font-size:15px;';
          var k = mkEl('span', null, kv[0]); k.style.color = 'var(--lcd-pixel-soft)';
          var v = mkEl('span', null, kv[1]); v.style.fontFamily = 'var(--mono)';
          row.appendChild(k); row.appendChild(v);
          ss.appendChild(row);
        });
      });
  }

  /* =========================================================================
     Audit screen
  ========================================================================= */

  function loadAuditScreen() {
    var ss = resetSubscreen('AUDIT LOG', backToAgent); if (!ss) return;
    var notice = mkEl('p', null, 'Audit entries appear as tool calls are made during the session. Tool calls recorded this session:');
    notice.style.cssText = 'color:var(--lcd-pixel-soft);font-size:15px;margin-bottom:10px;';
    ss.appendChild(notice);

    var sb      = document.getElementById('scrollback');
    var toolMsgs = sb ? sb.querySelectorAll('[data-tool-key]') : [];
    if (!toolMsgs.length) {
      ss.appendChild(mkEl('p', null, 'No tool calls yet.'));
      return;
    }
    Array.from(toolMsgs).forEach(function (tm) {
      var key = (tm.dataset.toolKey || '').split('|');
      var name = key[1] || '';
      var d = mkEl('div', null, '▸ ' + name);  // textContent — safe
      d.style.cssText = 'padding:4px 0;border-bottom:1px solid var(--lcd-pixel-soft);font-family:var(--mono);';
      ss.appendChild(d);
    });
  }

  /* =========================================================================
     Report screen  (POST /api/validate)
  ========================================================================= */

  function loadReportScreen() {
    var ss = resetSubscreen('REPORT', backToAgent); if (!ss) return;

    ss.appendChild(mkEl('div', null, 'VALIDATE BADUSB SCRIPT:'));

    var pathLbl = mkEl('label', null, 'Path (optional):');
    pathLbl.htmlFor = 'reportPath';
    pathLbl.style.cssText = 'display:block;margin-top:8px;font-family:var(--pixel);font-size:8px;letter-spacing:2px;';
    ss.appendChild(pathLbl);

    var pathInp = document.createElement('input');
    pathInp.id   = 'reportPath';
    pathInp.type = 'text';
    pathInp.placeholder  = '/path/to/payload.txt';
    pathInp.autocomplete = 'off';
    pathInp.spellcheck   = false;
    pathInp.style.cssText = 'width:100%;background:transparent;border:1px solid var(--lcd-pixel);' +
      'color:var(--lcd-pixel);padding:6px;font-family:var(--mono);font-size:14px;margin-bottom:8px;outline:none;';
    ss.appendChild(pathInp);

    var contLbl = mkEl('label', null, 'Content:');
    contLbl.htmlFor   = 'reportContent';
    contLbl.style.cssText = pathLbl.style.cssText;
    ss.appendChild(contLbl);

    var contArea = document.createElement('textarea');
    contArea.id          = 'reportContent';
    contArea.rows        = 5;
    contArea.placeholder = 'DELAY 500\nSTRING echo hello\nENTER';
    contArea.spellcheck  = false;
    contArea.style.cssText = 'width:100%;background:transparent;border:1px solid var(--lcd-pixel);' +
      'color:var(--lcd-pixel);padding:6px;font-family:var(--mono);font-size:14px;resize:vertical;outline:none;';
    ss.appendChild(contArea);

    var resultDiv = mkEl('div');
    resultDiv.style.marginTop = '12px';

    var runBtn = makeSmallBtn('VALIDATE', function () {
      var path    = pathInp.value.trim();
      var content = contArea.value;
      if (!path && !content) { clearEl(resultDiv); resultDiv.appendChild(mkEl('p', null, 'Enter a path or paste content.')); return; }
      runBtn.textContent = 'VALIDATING…';
      runBtn.disabled    = true;
      clearEl(resultDiv);

      apiFetch('api/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: path, content: content }),
      })
        .then(function (r) { return r.json().then(function (b) { return { ok: r.ok, body: b }; }); })
        .then(function (res) {
          runBtn.textContent = 'VALIDATE';
          runBtn.disabled    = false;
          clearEl(resultDiv);
          if (!res.ok) { resultDiv.appendChild(mkEl('p', null, 'Error: ' + ((res.body && res.body.error) || 'unknown'))); return; }
          renderValidateReport(resultDiv, res.body);
        })
        .catch(function (e) {
          runBtn.textContent = 'VALIDATE';
          runBtn.disabled    = false;
          clearEl(resultDiv);
          resultDiv.appendChild(mkEl('p', null, 'Validate failed: ' + (e.message || e)));
        });
    });
    runBtn.style.marginTop = '8px';
    ss.appendChild(runBtn);
    ss.appendChild(resultDiv);
  }

  function renderValidateReport(container, b) {
    var sumRow = mkEl('div');
    sumRow.style.cssText = 'display:flex;align-items:center;gap:10px;margin-bottom:10px;';

    var risk = (b.overall_risk || 'low').toLowerCase();
    var badge = mkEl('span', null, (b.overall_risk || '').toUpperCase());
    badge.style.cssText = 'font-family:var(--pixel);font-size:8px;padding:3px 6px;background:' +
      (risk === 'critical' || risk === 'high' ? '#8a0d0d' : 'var(--lcd-pixel)') + ';color:var(--lcd-bg);';
    sumRow.appendChild(badge);

    var nm = mkEl('span', null, b.name || '');  // textContent — safe
    nm.style.fontFamily = 'var(--mono)';
    sumRow.appendChild(nm);

    var verdict = mkEl('span', null, b.approved ? 'APPROVED' : 'BLOCKED');
    verdict.style.cssText = 'margin-left:auto;color:' + (b.approved ? 'var(--led-green)' : 'var(--led-red)') + ';font-family:var(--pixel);font-size:9px;';
    sumRow.appendChild(verdict);
    container.appendChild(sumRow);

    var findings = Array.isArray(b.findings) ? b.findings : [];
    if (!findings.length) { container.appendChild(mkEl('p', null, 'No findings — payload looks clean.')); return; }
    findings.forEach(function (f) {
      var d = mkEl('div');
      d.style.cssText = 'padding:6px 0;border-bottom:1px solid var(--lcd-pixel-soft);';
      var head = mkEl('div');
      head.style.cssText = 'display:flex;gap:8px;align-items:center;';
      var sev = mkEl('span', null, (f.severity || '').toUpperCase());
      var sevRisk = (f.severity || '').toLowerCase();
      sev.style.cssText = 'font-family:var(--pixel);font-size:7px;padding:2px 5px;background:' +
        (sevRisk === 'critical' || sevRisk === 'high' ? '#8a0d0d' : 'var(--lcd-pixel)') + ';color:var(--lcd-bg);';
      var ruleEl = mkEl('span', null, f.rule || '');  // textContent — safe
      ruleEl.style.fontFamily = 'var(--mono)';
      var lineEl = mkEl('span', null, 'L' + (f.line || 0));
      lineEl.style.marginLeft = 'auto';
      head.appendChild(sev); head.appendChild(ruleEl); head.appendChild(lineEl);
      d.appendChild(head);
      d.appendChild(mkEl('p', null, f.message || ''));  // textContent — safe
      if (f.excerpt) {
        var pre = mkEl('pre', null, f.excerpt);  // textContent — safe
        pre.style.cssText = 'background:var(--lcd-pixel);color:var(--lcd-bg);padding:4px;font-family:var(--mono);font-size:11px;';
        d.appendChild(pre);
      }
      container.appendChild(d);
    });
  }

  /* =========================================================================
     Files screen — two-pane filesystem browser
     RULE: all path strings from the device go through textContent only.
  ========================================================================= */

  function loadFilesScreen() {
    var ss = resetSubscreen('FILES', backFromFiles);
    if (!ss) return;

    _fsTreePane    = null;
    _fsPreviewPane = null;

    // Busy-warning banner (one-line, no modal)
    var busyWarn = mkEl('div', 'fs-busy-warn');
    busyWarn.style.display = 'none';
    busyWarn.textContent = 'Flipper is busy — close the running app on-device or via the agent.';
    ss.appendChild(busyWarn);

    // Two-pane container
    var panes = mkEl('div', 'fs-panes');
    ss.appendChild(panes);

    var tree = mkEl('div', 'fs-tree-pane');
    _fsTreePane = tree;
    panes.appendChild(tree);

    var preview = mkEl('div', 'fs-preview-pane');
    _fsPreviewPane = preview;
    panes.appendChild(preview);

    _fsCwd = '/ext';
    loadFsDir('/ext', tree, busyWarn);
  }

  function loadFsDir(path, treePane, busyWarn) {
    _fsCwd = path;
    clearEl(treePane);

    var loading = mkEl('p', null, 'Loading…');
    loading.style.color = 'var(--lcd-pixel-soft)';
    treePane.appendChild(loading);

    apiFetch('api/fs/list?path=' + encodeURIComponent(path))
      .then(function (r) {
        if (r.status === 503) {
          busyWarn.style.display = '';
          busyWarn.textContent = 'No Flipper connected — plug it in and the browser will pick it up.';
          clearEl(treePane);
          return null;
        }
        if (r.status === 409) {
          return r.json().catch(function () { return {}; }).then(function (b) {
            if (isMirrorActiveError(r, b)) {
              clearEl(treePane);
              busyWarn.style.display = '';
              busyWarn.textContent = 'Mirror is active — stop the mirror to browse files.';
            }
            return null;
          });
        }
        return r.json().then(function (b) { return { status: r.status, body: b }; });
      })
      .then(function (res) {
        if (!res) return;
        clearEl(treePane);

        if (res.body && res.body.error) {
          var errMsg = String(res.body.error);
          if (errMsg.indexOf('cannot be run while an application is open') !== -1) {
            busyWarn.style.display = '';
            busyWarn.textContent = 'Flipper is busy — close the running app on-device or via the agent.';
          } else {
            treePane.appendChild(mkEl('p', null, 'Error: ' + errMsg));   // textContent — safe
          }
          return;
        }
        busyWarn.style.display = 'none';
        renderFsList(treePane, res.body, busyWarn);
      })
      .catch(function () {
        clearEl(treePane);
        treePane.appendChild(mkEl('p', null, 'Failed to load directory.'));
      });
  }

  function renderFsList(parentEl, listResp, busyWarn) {
    var entries = Array.isArray(listResp.entries) ? listResp.entries : [];
    var currentPath = listResp.path || '/ext';

    // Breadcrumb path header
    var pathRow = mkEl('div', 'fs-path-row');
    var pathEl  = mkEl('span', 'fs-path-text');
    pathEl.textContent = currentPath;   // textContent — safe
    pathRow.appendChild(pathEl);
    parentEl.appendChild(pathRow);

    // Parent / up navigation
    if (listResp.parent && listResp.parent !== currentPath) {
      var upRow = mkEl('div', 'rail-item fs-entry');
      upRow.tabIndex = 0;
      upRow.setAttribute('role', 'button');
      upRow.appendChild(mkEl('span', 'ic', '▴'));
      upRow.appendChild(mkEl('span', 'label', '..'));
      upRow.appendChild(mkEl('span', 'badge', ''));
      var parentPath = listResp.parent;
      upRow.addEventListener('click', function () { loadFsDir(parentPath, _fsTreePane, busyWarn); });
      upRow.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); loadFsDir(parentPath, _fsTreePane, busyWarn); }
      });
      parentEl.appendChild(upRow);
    }

    if (!entries.length) { parentEl.appendChild(mkEl('p', null, '(empty)')); }

    entries.forEach(function (entry) {
      var isDir = entry.type === 'dir';
      var row = mkEl('div', 'rail-item fs-entry');
      row.tabIndex = 0;
      row.setAttribute('role', 'button');
      row.appendChild(mkEl('span', 'ic', isDir ? '▶' : '·'));

      var nameSpan = mkEl('span', 'label');
      nameSpan.textContent = entry.name;   // textContent — safe
      row.appendChild(nameSpan);

      var badge = mkEl('span', 'badge');
      if (!isDir && entry.size != null) badge.textContent = fmtBytes(entry.size);
      else if (isDir) badge.textContent = '▶';
      row.appendChild(badge);

      var entryPath = currentPath.replace(/\/$/, '') + '/' + entry.name;

      if (isDir) {
        row.addEventListener('click', function () { loadFsDir(entryPath, _fsTreePane, busyWarn); });
        row.addEventListener('keydown', function (e) {
          if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); loadFsDir(entryPath, _fsTreePane, busyWarn); }
        });
      } else {
        row.addEventListener('click', function () { openFsFile(entryPath); });
        row.addEventListener('keydown', function (e) {
          if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openFsFile(entryPath); }
        });
      }
      parentEl.appendChild(row);
    });

    if (listResp.truncated) {
      var trunc = mkEl('p', null, '(listing truncated)');
      trunc.style.color = 'var(--lcd-pixel-soft)';
      parentEl.appendChild(trunc);
    }

    // Toolbar: mkdir + upload
    var toolbar = mkEl('div', 'fs-toolbar');
    var mkdirBtn = makeSmallBtn('NEW DIR', function () {
      showFsModal('New directory name:', '', function (name) {
        if (!name) return;
        doFsMkdir(currentPath.replace(/\/$/, '') + '/' + name, function () {
          loadFsDir(currentPath, _fsTreePane, busyWarn);
        });
      });
    });
    toolbar.appendChild(mkdirBtn);

    var uploadInput = document.createElement('input');
    uploadInput.type = 'file';
    uploadInput.style.display = 'none';
    uploadInput.addEventListener('change', function () {
      var file = uploadInput.files && uploadInput.files[0];
      if (!file) return;
      doFsUpload(file, currentPath.replace(/\/$/, '') + '/' + file.name, false, function () {
        loadFsDir(currentPath, _fsTreePane, busyWarn);
      });
    });
    toolbar.appendChild(uploadInput);
    toolbar.appendChild(makeSmallBtn('UPLOAD', function () { uploadInput.click(); }));
    parentEl.appendChild(toolbar);
  }

  function openFsFile(path) {
    if (!_fsPreviewPane) return;

    if (window.innerWidth < 900) { showFsPreviewOnly(); }

    clearEl(_fsPreviewPane);
    _fsPreviewPane.dataset.visible = '1';

    var loading = mkEl('p', null, 'Loading…');
    loading.style.color = 'var(--lcd-pixel-soft)';
    _fsPreviewPane.appendChild(loading);

    if (path !== _fsOpenPath) {
      _fsOpenPath = path;
      sendUIContext('preview', path);
    }

    apiFetch('api/fs/read?path=' + encodeURIComponent(path))
      .then(function (r) {
        if (r.status === 413) {
          return r.json().catch(function () { return {}; }).then(function (b) {
            return { tooLarge: true, size: (b && b.size) || 0 };
          });
        }
        if (r.status === 409) {
          return r.json().catch(function () { return {}; }).then(function (b) {
            return { mirrorActive: isMirrorActiveError(r, b) };
          });
        }
        if (r.status === 503) { return { notConnected: true }; }
        return r.json().then(function (b) { return { ok: r.ok, status: r.status, body: b }; });
      })
      .then(function (res) {
        clearEl(_fsPreviewPane);
        _fsPreviewPane.dataset.visible = '1';

        if (res.notConnected) {
          _fsPreviewPane.appendChild(mkEl('p', null, 'No Flipper connected — plug it in and the browser will pick it up.'));
          return;
        }
        if (res.mirrorActive) {
          _fsPreviewPane.appendChild(mkEl('p', null, 'Flipper is mirrored — stop the mirror first to use this.'));
          return;
        }
        if (res.tooLarge) {
          var msg = mkEl('p');
          msg.textContent = 'File too large to preview' + (res.size ? ' (' + fmtBytes(res.size) + ')' : '') + '.';
          _fsPreviewPane.appendChild(msg);
          var hint = mkEl('p');
          // Build hint without injecting path into innerHTML
          hint.textContent = "Use the agent: 'read the file at " + path + "'";
          _fsPreviewPane.appendChild(hint);
          return;
        }
        if (!res.ok || !res.body) {
          var errMsg2 = (res.body && res.body.error) ? String(res.body.error) : 'Unknown error';
          if (errMsg2.indexOf('cannot be run while an application is open') !== -1) {
            var warn = q('.fs-busy-warn');
            if (warn) { warn.style.display = ''; warn.textContent = 'Flipper is busy — close the running app on-device or via the agent.'; }
          } else {
            _fsPreviewPane.appendChild(mkEl('p', null, 'Error: ' + errMsg2));   // textContent — safe
          }
          return;
        }

        var data = res.body;
        var contentType = data.content_type || '';

        // Build action bar
        var actionDefs = FILE_ACTIONS[contentType] || [];
        var bar = mkEl('div', 'fs-actions');
        actionDefs.forEach(function (action) {
          var btn = makeSmallBtn(action.label, function () {
            var prompt = action.prompt.replace('%p', path);
            showAgentScreen();
            submitText(prompt);
          });
          bar.appendChild(btn);
        });

        // Delete button
        bar.appendChild(makeSmallBtn('DELETE', function () {
          showFsConfirmModal('Delete ' + path + '?', 'DELETE', function () {
            doFsDelete(path, function () {
              clearEl(_fsPreviewPane);
              _fsPreviewPane.dataset.visible = '0';
              loadFsDir(_fsCwd, _fsTreePane, q('.fs-busy-warn'));
            });
          });
        }));

        // Rename button
        bar.appendChild(makeSmallBtn('RENAME', function () {
          showFsModal('New name (same directory):', path.split('/').pop(), function (newName) {
            if (!newName) return;
            var parts = path.split('/');
            parts[parts.length - 1] = newName;
            var dst = parts.join('/');
            doFsRename(path, dst, function () {
              loadFsDir(_fsCwd, _fsTreePane, q('.fs-busy-warn'));
              openFsFile(dst);
            });
          });
        }));
        _fsPreviewPane.appendChild(bar);

        // Path heading
        var pathHead = mkEl('div', 'fs-preview-path');
        pathHead.textContent = path;   // textContent — safe
        _fsPreviewPane.appendChild(pathHead);

        // Content
        var pre = document.createElement('pre');
        pre.className = 'fs-preview-content';
        pre.textContent = data.content || '';   // textContent — safe for both text and base64
        _fsPreviewPane.appendChild(pre);

        if (data.encoding === 'base64') {
          _fsPreviewPane.appendChild(mkEl('div', 'fs-preview-note', 'binary file (base64)'));
        }
      })
      .catch(function () {
        clearEl(_fsPreviewPane);
        _fsPreviewPane.appendChild(mkEl('p', null, 'Failed to load file.'));
      });
  }

  function showFsPreviewOnly() {
    if (_fsTreePane)    _fsTreePane.classList.add('fs-pane-hidden');
    if (_fsPreviewPane) _fsPreviewPane.classList.remove('fs-pane-hidden');
  }

  function showFsTreeOnly() {
    if (_fsTreePane)    _fsTreePane.classList.remove('fs-pane-hidden');
    if (_fsPreviewPane) {
      _fsPreviewPane.classList.add('fs-pane-hidden');
      _fsPreviewPane.dataset.visible = '0';
    }
    if (_fsOpenPath) { sendUIContext('preview', ''); _fsOpenPath = ''; }
  }

  /* ---- Filesystem mutation helpers (no innerHTML) ---- */

  function doFsUpload(file, dest, overwrite, onSuccess) {
    var fd = new FormData();
    fd.append('path', dest);
    fd.append('file', file);
    var url = 'api/fs/upload' + (overwrite ? '?overwrite=true' : '');
    apiFetch(url, { method: 'POST', body: fd })
      .then(function (r) {
        if (r.status === 503) { alert('No Flipper connected.'); return; }
        return r.json().then(function (b) { return { ok: r.ok, body: b }; });
      })
      .then(function (res) {
        if (!res) return;
        if (!res.ok) { alert('Upload failed: ' + ((res.body && res.body.error) || 'unknown')); return; }
        if (onSuccess) onSuccess();
      })
      .catch(function () { alert('Upload failed.'); });
  }

  function doFsDelete(path, onSuccess) {
    apiFetch('api/fs/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: path }),
    })
      .then(function (r) {
        if (r.status === 503) { alert('No Flipper connected.'); return; }
        return r.json().then(function (b) { return { ok: r.ok, body: b }; });
      })
      .then(function (res) {
        if (!res) return;
        if (!res.ok) { alert('Delete failed: ' + ((res.body && res.body.error) || 'unknown')); return; }
        if (onSuccess) onSuccess();
      })
      .catch(function () { alert('Delete failed.'); });
  }

  function doFsMkdir(path, onSuccess) {
    apiFetch('api/fs/mkdir', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: path }),
    })
      .then(function (r) {
        if (r.status === 503) { alert('No Flipper connected.'); return; }
        return r.json().then(function (b) { return { ok: r.ok, body: b }; });
      })
      .then(function (res) {
        if (!res) return;
        if (!res.ok) { alert('Mkdir failed: ' + ((res.body && res.body.error) || 'unknown')); return; }
        if (onSuccess) onSuccess();
      })
      .catch(function () { alert('Mkdir failed.'); });
  }

  function doFsRename(src, dst, onSuccess) {
    apiFetch('api/fs/rename', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ src: src, dst: dst }),
    })
      .then(function (r) {
        if (r.status === 503) { alert('No Flipper connected.'); return; }
        return r.json().then(function (b) { return { ok: r.ok, body: b }; });
      })
      .then(function (res) {
        if (!res) return;
        if (!res.ok) { alert('Rename failed: ' + ((res.body && res.body.error) || 'unknown')); return; }
        if (onSuccess) onSuccess();
      })
      .catch(function () { alert('Rename failed.'); });
  }

  /* ---- Inline modals (no alert/prompt for paths) ---- */

  function showFsModal(label, defaultValue, onConfirm) {
    var ss = ensureSubscreen();
    if (!ss) return;
    var overlay = mkEl('div', 'fs-modal');
    overlay.appendChild(mkEl('label', 'fs-modal-label', label));  // static string — safe
    var inp = document.createElement('input');
    inp.type = 'text';
    inp.className = 'fs-modal-input';
    inp.value = defaultValue || '';
    inp.autocomplete = 'off';
    inp.spellcheck = false;
    overlay.appendChild(inp);
    var btnRow = mkEl('div', 'fs-modal-btns');
    btnRow.appendChild(makeSmallBtn('OK', function () {
      var val = inp.value.trim();
      if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
      if (val) onConfirm(val);
    }));
    btnRow.appendChild(makeSmallBtn('CANCEL', function () {
      if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
    }));
    overlay.appendChild(btnRow);
    ss.appendChild(overlay);
    setTimeout(function () { inp.focus(); inp.select(); }, 30);
  }

  function showFsConfirmModal(message, actionLabel, onConfirm) {
    var ss = ensureSubscreen();
    if (!ss) return;
    var overlay = mkEl('div', 'fs-modal');
    var msg = mkEl('p', 'fs-modal-label');
    msg.textContent = message;   // textContent — safe
    overlay.appendChild(msg);
    var btnRow = mkEl('div', 'fs-modal-btns');
    var doBtn = makeSmallBtn(actionLabel, function () {
      if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
      onConfirm();
    });
    doBtn.style.background = '#8a0d0d';
    doBtn.style.color = '#fff';
    btnRow.appendChild(doBtn);
    btnRow.appendChild(makeSmallBtn('CANCEL', function () {
      if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
    }));
    overlay.appendChild(btnRow);
    ss.appendChild(overlay);
    setTimeout(function () { var c = overlay.querySelector('button:last-child'); if (c) c.focus(); }, 30);
  }

  /* =========================================================================
     WebSocket ui_context helper
  ========================================================================= */

  function sendUIContext(view, path) {
    sendWs({ type: 'ui_context', view: view, path: path || '' });
  }

  /* =========================================================================
     Utility helpers
  ========================================================================= */

  function showToast(msg) {
    if (!msg) return;
    var existing = document.getElementById('pzToast');
    if (existing && existing.parentNode) existing.parentNode.removeChild(existing);
    var t = mkEl('div', 'pz-toast');
    t.id = 'pzToast';
    t.textContent = msg;  // textContent — safe
    document.body.appendChild(t);
    setTimeout(function () {
      t.classList.add('pz-toast-hide');
      setTimeout(function () { if (t.parentNode) t.parentNode.removeChild(t); }, 400);
    }, 4000);
  }

  function isMirrorActiveError(res, body) {
    return res && res.status === 409 && body && body.code === 'mirror_active';
  }

  function makeSmallBtn(label, onclick) {
    var btn = mkEl('button', null, label);
    btn.type = 'button';
    btn.style.cssText = 'font-family:var(--pixel);font-size:8px;letter-spacing:2px;padding:6px 10px;' +
      'background:var(--lcd-pixel);color:var(--lcd-bg);border:none;cursor:pointer;';
    btn.addEventListener('click', onclick);
    return btn;
  }

  function fmtJSON(v) {
    if (v == null || v === '') return '';
    if (typeof v === 'string') {
      var t = v.trim();
      if (t.length && (t[0] === '{' || t[0] === '[')) {
        try { return JSON.stringify(JSON.parse(t), null, 2); } catch (_) { return v; }
      }
      return v;
    }
    try { return JSON.stringify(v, null, 2); } catch (_) { return String(v); }
  }

  function fmtBytes(n) {
    n = Number(n);
    if (!isFinite(n) || n < 0) return '0B';
    var units = ['B', 'K', 'M', 'G', 'T'];
    var i = 0;
    while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
    return (n < 10 ? n.toFixed(1) : Math.round(n)) + units[i];
  }

  function fmtUSD(n) {
    var v = Number(n || 0);
    if (v >= 100) return '$' + v.toFixed(0);
    if (v >= 1)   return '$' + v.toFixed(2);
    return '$' + v.toFixed(v < 0.01 ? 4 : 2);
  }

  function fmtTokens(n) {
    var v = Number(n || 0);
    if (v >= 1e6) return (v / 1e6).toFixed(1) + 'M';
    if (v >= 1e3) return (v / 1e3).toFixed(1) + 'k';
    return String(v);
  }

  function prefersReducedMotion() {
    return !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  }

  /* =========================================================================
     Screen mirror — Device panel
  ========================================================================= */

  function backFromDevice() {
    backToAgent();
  }

  function loadDeviceScreen() {
    var ss = resetSubscreen('DEVICE', backFromDevice);
    if (!ss) return;

    // Sticky banner (mount outside subscreen so it persists across routes)
    updateScreenBanner();

    var panel = mkEl('div', 'screen-panel');

    var canvas = document.createElement('canvas');
    canvas.className = 'screen-canvas offline';
    canvas.width  = 128;
    canvas.height = 64;
    canvas.setAttribute('aria-label', 'Flipper screen mirror');
    panel.appendChild(canvas);
    _screenCanvas = canvas;

    var status = mkEl('div', 'screen-status');
    status.dataset.state = 'offline';
    status.textContent = 'MIRROR OFFLINE';
    panel.appendChild(status);
    _screenStatus = status;

    var btnRow = mkEl('div', 'screen-btn-row');

    var startBtn = mkEl('button', null, 'START MIRROR');
    startBtn.type = 'button';
    startBtn.style.cssText = 'font-family:var(--pixel);font-size:8px;letter-spacing:2px;padding:8px 14px;' +
      'background:var(--lcd-pixel);color:var(--lcd-bg);border:none;cursor:pointer;';
    _screenStartBtn = startBtn;

    var stopBtn = mkEl('button', null, 'STOP MIRROR');
    stopBtn.type = 'button';
    stopBtn.style.cssText = 'font-family:var(--pixel);font-size:8px;letter-spacing:2px;padding:8px 14px;' +
      'background:var(--orange-lo);color:var(--lcd-bg);border:none;cursor:pointer;display:none;';
    _screenStopBtn = stopBtn;

    startBtn.addEventListener('click', function () {
      if (_screenConfirmDismissed) {
        acquireScreen();
      } else {
        showScreenConfirmModal();
      }
    });
    stopBtn.addEventListener('click', function () { releaseScreen(); });

    btnRow.appendChild(startBtn);
    btnRow.appendChild(stopBtn);
    panel.appendChild(btnRow);

    var hint = mkEl('p', 'screen-hint', 'While mirroring, chat and file operations are paused.');
    panel.appendChild(hint);

    ss.appendChild(panel);

    // Apply current mirror state to the freshly built panel
    refreshDeviceScreen();
  }

  function refreshDeviceScreen() {
    if (!_screenCanvas) return;

    if (_screenState.isHolder) {
      _screenCanvas.className = 'screen-canvas';
      setScreenStatus('live', 'LIVE');
      if (_screenStartBtn) _screenStartBtn.style.display = 'none';
      if (_screenStopBtn)  _screenStopBtn.style.display  = '';
    } else if (_screenState.active) {
      // Another session holds the mirror
      _screenCanvas.className = 'screen-canvas offline';
      setScreenStatus('offline', 'HELD BY ANOTHER SESSION');
      if (_screenStartBtn) { _screenStartBtn.style.display = ''; _screenStartBtn.disabled = true; }
      if (_screenStopBtn)  _screenStopBtn.style.display = 'none';
    } else {
      _screenCanvas.className = 'screen-canvas offline';
      setScreenStatus('offline', 'MIRROR OFFLINE');
      if (_screenStartBtn) { _screenStartBtn.style.display = ''; _screenStartBtn.disabled = false; }
      if (_screenStopBtn)  _screenStopBtn.style.display = 'none';
    }
  }

  function setScreenStatus(state, text) {
    if (!_screenStatus) return;
    _screenStatus.dataset.state = state;
    _screenStatus.textContent = text;  // hard-coded strings only — safe
  }

  function showScreenConfirmModal() {
    var ss = ensureSubscreen();
    if (!ss) return;

    // Re-entry guard: the modal is an inline sibling of the START MIRROR
    // button (not a fullscreen overlay), so without this every extra click
    // on START stacks another prompt on top.
    var existing = ss.querySelector('.screen-confirm-modal');
    if (existing) {
      var existingCancel = existing.querySelector('button');
      if (existingCancel) existingCancel.focus();
      return;
    }

    var overlay = mkEl('div', 'fs-modal screen-confirm-modal');

    var h3 = mkEl('h3', null, 'START LIVE SCREEN MIRROR?');
    h3.style.cssText = 'font-family:var(--pixel);font-size:9px;letter-spacing:2px;margin:0 0 12px;';
    overlay.appendChild(h3);

    var lines = [
      'The Flipper switches to RPC mode while mirroring.',
      'Until you stop the mirror:',
      '',
      '▸ Chat with the agent will be paused',
      '▸ File browser operations will be paused',
      '▸ Direct button presses will be paused',
      '',
      'The screen updates in real time.',
      "Stop the mirror when you're done.",
    ];
    lines.forEach(function (line) {
      var p = mkEl('p', null, line);
      p.style.cssText = 'margin:2px 0;font-family:var(--term);font-size:18px;';
      overlay.appendChild(p);
    });

    var cbRow = mkEl('div');
    cbRow.style.cssText = 'display:flex;align-items:center;gap:8px;margin:12px 0 8px;';
    var cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.id   = 'screenDontAsk';
    var cbLabel = mkEl('label');
    cbLabel.htmlFor = 'screenDontAsk';
    cbLabel.textContent = "Don't show this confirmation again this session";
    cbLabel.style.cssText = 'font-family:var(--pixel);font-size:7px;letter-spacing:1px;cursor:pointer;';
    cbRow.appendChild(cb);
    cbRow.appendChild(cbLabel);
    overlay.appendChild(cbRow);

    var btnRow = mkEl('div', 'fs-modal-btns');
    btnRow.style.justifyContent = 'flex-end';

    var cancelBtn = makeSmallBtn('CANCEL', function () {
      if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
    });

    var goBtn = makeSmallBtn('START MIRROR', function () {
      if (cb.checked) {
        _screenConfirmDismissed = true;
        try { sessionStorage.setItem('promptzero_screen_confirm_dismissed', '1'); } catch (_) {}
      }
      if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
      acquireScreen();
    });
    goBtn.style.background = 'var(--orange)';
    goBtn.style.color = '#1a0e00';

    btnRow.appendChild(cancelBtn);
    btnRow.appendChild(goBtn);
    overlay.appendChild(btnRow);

    ss.appendChild(overlay);
    setTimeout(function () { cancelBtn.focus(); }, 30);
  }

  function acquireScreen() {
    setScreenStatus('opening', 'OPENING…');
    sendWs({ type: 'screen_acquire' });
  }

  function releaseScreen() {
    sendWs({ type: 'screen_release' });
  }

  function onScreenStateMessage(msg) {
    var wasActive = _screenState.active;
    _screenState.active   = !!msg.active;
    _screenState.holderId = msg.holder_session_id || '';
    _screenState.isHolder = msg.active && msg.holder_session_id === _sessionId;

    // Start keepalives if we just became the holder.
    if (_screenState.isHolder && !_screenKeepaliveTimer) {
      _screenKeepaliveTimer = setInterval(function () {
        sendWs({ type: 'screen_keepalive' });
      }, SCREEN_KEEPALIVE_MS);
    }
    // Clear keepalives if we lost holder status.
    if (!_screenState.isHolder && _screenKeepaliveTimer) {
      clearInterval(_screenKeepaliveTimer);
      _screenKeepaliveTimer = null;
    }

    // Update persistent banner.
    updateScreenBanner();

    // Refresh Device panel if it is currently visible.
    if (_currentScreen === 'device') refreshDeviceScreen();

    // Refresh dpad mode/badge — mirror-held dpad locks to RPC input.
    applyDpadMode();

    // Show a toast when the mirror stops for a notable reason.
    if (wasActive && !_screenState.active && msg.reason) {
      var reasons = {
        timeout:           'Mirror released — no keepalive received in 30s.',
        transport_lost:    'Mirror released — connection to Flipper lost.',
        holder_disconnect: 'Mirror released — holder disconnected.',
        released:          '',
        open_failed:       'Could not start mirror.',
        taken:             '',
      };
      var txt = reasons[msg.reason];
      if (txt) showToast(txt);
    }

  }

  function onScreenErrorMessage(msg) {
    setScreenStatus('error', 'ERROR');
    showToast((msg.message || 'Screen mirror error') + (msg.code ? ' [' + msg.code + ']' : ''));
  }

  function updateScreenBanner() {
    var existing = document.getElementById('screenBanner');

    if (!_screenState.active) {
      if (existing && existing.parentNode) existing.parentNode.removeChild(existing);
      return;
    }

    var banner = existing;
    if (!banner) {
      banner = mkEl('div', 'screen-banner');
      banner.id = 'screenBanner';
      // Mount inside lcd-inner, before lcd content, so it is sticky within the LCD area.
      var lcdInner = q('.lcd-inner');
      if (!lcdInner) return;
      lcdInner.insertBefore(banner, lcdInner.firstChild);
    }

    // Clear and rebuild banner text (textContent only — no innerHTML)
    clearEl(banner);

    var textSpan = mkEl('span');
    if (_screenState.isHolder) {
      textSpan.textContent = '● MIRRORING — chat and file operations paused';
    } else {
      textSpan.textContent = '◎ Flipper screen mirror is active in another session';
    }
    banner.appendChild(textSpan);

    if (_screenState.isHolder) {
      var stopBtn = mkEl('button', null, 'STOP MIRROR');
      stopBtn.type = 'button';
      stopBtn.addEventListener('click', function () { releaseScreen(); });
      banner.appendChild(stopBtn);
    }
  }

  function onScreenBinaryFrame(buf) {
    if (_screenRenderPaused) return;
    if (!_screenCanvas) return;
    if (buf.byteLength < 1 + SCREEN_FRAME_LEN) return;
    var view = new Uint8Array(buf);
    if (view[0] !== 0x01) return; // unknown format version
    paintScreenFrame(_screenCanvas, view.subarray(1, 1 + SCREEN_FRAME_LEN));
  }

  function paintScreenFrame(canvas, packed) {
    var ctx = canvas.getContext('2d');
    var img = ctx.createImageData(128, 64);
    var data = img.data;
    // ON pixel = --lcd-pixel (#1a0e00), OFF pixel = --lcd-bg (#ff9f1c)
    for (var y = 0; y < 64; y++) {
      for (var x = 0; x < 128; x++) {
        var byte = packed[(y >> 3) * 128 + x];
        var on = (byte >> (y & 7)) & 1;
        var i = (y * 128 + x) * 4;
        if (on) { data[i]=0x1a; data[i+1]=0x0e; data[i+2]=0x00; }
        else    { data[i]=0xff; data[i+1]=0x9f; data[i+2]=0x1c; }
        data[i+3] = 255;
      }
    }
    ctx.putImageData(img, 0, 0);
  }

  document.addEventListener('visibilitychange', function () {
    _screenRenderPaused = (document.visibilityState === 'hidden');
  });

  /* =========================================================================
     Marauder TFT panel — synthesized 320x240 firmware UI
     Driven by parsed CLI events from internal/marauder over WS
     (marauder_acquire / marauder_release / marauder_cmd, see SPEC.md).
     The panel renders into #subscreen when the marauder route is active.
  ========================================================================= */

  var Marauder = (function () {
    'use strict';

    // --------------------------------------------------------------- menu tree
    // Mirrors the firmware menu hierarchy verbatim. Each leaf declares
    // how the panel reacts when "OK" is pressed. Renderers live below.
    var TREE = {
      title: 'MAIN',
      items: [
        { kind: 'menu', label: 'WiFi', title: 'WIFI', items: [
          { kind: 'menu', label: 'Sniffers', title: 'WIFI > SNIFFERS', items: [
            { kind: 'list',  label: 'Beacon Sniff',   cmd: 'sniffbeacon',  evt: 'beacon',     col: 'beacon' },
            { kind: 'list',  label: 'Probe Sniff',    cmd: 'sniffprobe',   evt: 'probe',      col: 'probe'  },
            // Packet Monitor consumes sniffraw's aggregate `packet_rate`
            // events (modeBlock); the chart's series come from the parsed
            // beacon/deauth/probe/eapol/raw fields.
            { kind: 'graph', label: 'Packet Monitor', cmd: 'sniffraw' },
            // Per-line raw frames — backend's sniffraw_lines runs the same
            // device cmd but emits per-line `raw` events (see task #9).
            { kind: 'list',  label: 'Sniff Raw',      cmd: 'sniffraw_lines', evt: 'raw',        col: 'raw'    },
            { kind: 'list',  label: 'Deauth Detector',cmd: 'sniffdeauth',    evt: 'deauth_seen',col: 'deauth' },
          ]},
          { kind: 'menu', label: 'Scanners', title: 'WIFI > SCANNERS', items: [
            { kind: 'list', label: 'Scan APs',      cmd: 'scanap',  evt: 'ap_seen',  col: 'ap'  },
            { kind: 'list', label: 'Scan Stations', cmd: 'scansta', evt: 'sta_seen', col: 'sta' },
          ]},
          { kind: 'menu', label: 'Attacks', title: 'WIFI > ATTACKS', items: [
            { kind: 'attack', label: 'Beacon Spam (Random)', cmd: 'attack_beacon_random' },
            { kind: 'attack', label: 'Beacon Spam (List)',   cmd: 'attack_beacon_list'   },
            { kind: 'attack', label: 'Beacon Spam (AP list)',cmd: 'attack_beacon_ap'     },
            { kind: 'attack', label: 'Rickroll Beacon',      cmd: 'attack_rickroll'      },
            { kind: 'attack', label: 'Probe Flood',          cmd: 'attack_probe'         },
            { kind: 'attack', label: 'Deauth',               cmd: 'attack_deauth'        },
            { kind: 'attack', label: 'Evil Portal',          cmd: 'evilportal_start'     },
          ]},
        ]},
        { kind: 'menu', label: 'Bluetooth', title: 'BT', items: [
          { kind: 'menu', label: 'Sniffers', title: 'BT > SNIFFERS', items: [
            // Backend reads args["target"] (not "t"); empty/all fall through
            // to BT_SCAN_ALL — Apple/Samsung/Flipper need the explicit target.
            { kind: 'list', label: 'BLE Sniff All',    cmd: 'blescan', args: { target: 'all' },     evt: 'ble_seen', col: 'ble' },
            { kind: 'list', label: 'Apple Detector',   cmd: 'blescan', args: { target: 'apple' },   evt: 'ble_seen', col: 'ble' },
            { kind: 'list', label: 'Samsung Detector', cmd: 'blescan', args: { target: 'samsung' }, evt: 'ble_seen', col: 'ble' },
            { kind: 'list', label: 'Flipper Detector', cmd: 'blescan', args: { target: 'flipper' }, evt: 'ble_seen', col: 'ble' },
          ]},
          { kind: 'list', label: 'Wardrive', cmd: 'blewardrive', evt: 'ble_wardrive', col: 'wardrive' },
          { kind: 'menu', label: 'Spam', title: 'BT > SPAM', items: [
            // Backend's blespam target whitelist is apple|google|samsung|windows|flipper|all.
            // The firmware's "Microsoft" payload set is what its `windows` mode emits.
            { kind: 'attack', label: 'Sour Apple',   cmd: 'blespam', args: { target: 'apple' } },
            { kind: 'attack', label: 'Samsung Spam', cmd: 'blespam', args: { target: 'samsung' } },
            { kind: 'attack', label: 'Google Spam',  cmd: 'blespam', args: { target: 'google' } },
            { kind: 'attack', label: 'Windows Spam', cmd: 'blespam', args: { target: 'windows' } },
          ]},
        ]},
        { kind: 'menu', label: 'GPS', title: 'GPS', items: [
          { kind: 'gps',  label: 'GPS Data', cmd: 'gpsdata' },
          { kind: 'list', label: 'NMEA',     cmd: 'nmea',  evt: 'nmea_line', col: 'nmea' },
        ]},
        { kind: 'menu', label: 'Storage', title: 'STORAGE', items: [
          { kind: 'browse', label: 'Browse SD' },
        ]},
        { kind: 'info', label: 'Device Info' },
        { kind: 'leds', label: 'LED', title: 'LED', items: [
          { label: 'Off',     hex: '000000' },
          { label: 'Red',     hex: 'FF0000' },
          { label: 'Green',   hex: '00FF00' },
          { label: 'Blue',    hex: '0000FF' },
          { label: 'White',   hex: 'FFFFFF' },
          { label: 'Rainbow', rainbow: true },
        ]},
      ],
    };

    // --------------------------------------------------------------- column defs
    // Each list-screen kind has a `col` token that picks how rows render.
    var COLUMNS = {
      ap: function (r, p) {
        // p = { ssid, bssid, channel, rssi }
        var ssid = String(p.ssid || '<hidden>').slice(0, 18);
        var ch   = (p.channel != null) ? 'CH' + p.channel : '   ';
        var meta = ch + '  ' + rssiBadge(p.rssi).text;
        r.metaText  = meta;
        r.metaBand  = rssiBadge(p.rssi).band;
        r.label     = ssid;
        r.rssi      = p.rssi;
        r.bars      = rssiBars(p.rssi);
      },
      sta: function (r, p) {
        // p = { mac, rssi, ap }
        var mac = String(p.mac || '').slice(-8);
        r.label = mac + (p.ap ? ' →' + String(p.ap).slice(0, 8) : '');
        r.metaText = rssiBadge(p.rssi).text;
        r.metaBand = rssiBadge(p.rssi).band;
        r.rssi = p.rssi;
        r.bars = rssiBars(p.rssi);
      },
      ble: function (r, p) {
        // p = { name, mac, rssi, mfg }
        var name = String(p.name || p.mac || '<unknown>').slice(0, 18);
        r.label = name;
        r.metaText = (p.mfg ? p.mfg.slice(0,4) + ' ' : '') + rssiBadge(p.rssi).text;
        r.metaBand = rssiBadge(p.rssi).band;
        r.rssi = p.rssi;
        r.bars = rssiBars(p.rssi);
      },
      beacon: function (r, p) {
        var s = String(p.ssid || p.bssid || '...').slice(0, 18);
        r.label = s;
        r.metaText = (p.channel ? 'CH' + p.channel : '') + ' ' + rssiBadge(p.rssi).text;
        r.metaBand = rssiBadge(p.rssi).band;
        r.bars = rssiBars(p.rssi);
      },
      probe: function (r, p) {
        var ssid = String(p.ssid || '<wildcard>').slice(0, 18);
        r.label = ssid;
        r.metaText = String(p.mac || '').slice(-8);
        r.metaBand = 'mid';
      },
      deauth: function (r, p) {
        r.label = String(p.bssid || p.target || '...').slice(0, 18);
        r.metaText = 'cnt ' + (p.count || 1);
        r.metaBand = 'lo';
      },
      raw: function (r, p) {
        // Backend's sniffraw_lines (and nmea) emit {line: "<verbatim>"} —
        // there's no structured meta to surface; let the line fill the row.
        // Fallbacks kept so the row never goes blank if the parser shape
        // ever evolves.
        r.label = String(p.line || p.raw || p.proto || p.summary || 'pkt').slice(0, 44);
        r.metaText = '';
        r.metaBand = 'mid';
      },
      wardrive: function (r, p) {
        r.label = String(p.name || p.mac || '...').slice(0, 18);
        r.metaText = (p.lat && p.lon) ? (Math.round(p.rssi || 0)) + 'dB' : '—';
        r.metaBand = rssiBadge(p.rssi).band;
        r.bars = rssiBars(p.rssi);
      },
      nmea: function (r, p) {
        // Backend uses parsers.ParseRaw — same {line: "<text>"} shape as raw.
        r.label = String(p.line || p.raw || '').slice(0, 44);
        r.metaText = '';
        r.metaBand = 'mid';
      },
    };

    function rssiBadge(rssi) {
      var v = Number(rssi);
      if (!isFinite(v) || v === 0) return { text: '   ', band: 'mid' };
      var band = (v > -60) ? 'hi' : (v > -75) ? 'mid' : 'lo';
      return { text: (v < 0 ? '' : '+') + v.toString().padStart(3, ' '), band: band };
    }
    function rssiBars(rssi) {
      var v = Number(rssi);
      if (!isFinite(v) || v === 0) return 0;
      if (v > -55) return 5;
      if (v > -65) return 4;
      if (v > -75) return 3;
      if (v > -85) return 2;
      return 1;
    }

    // --------------------------------------------------------------- state
    var state = {
      mounted: false,
      panelEl: null,
      viewEl: null,
      crumbEl: null,
      modeEl: null,
      statBat: null,
      statGps: null,
      statTgt: null,
      sideLink: null,
      sidePort: null,
      sideFw: null,
      sideDpad: null,

      stack: [],          // [{ frame, cursor, title, render }]
      view: 'menu',       // 'menu'|'leds'|'list'|'gps'|'graph'|'fire'|'streaming'|'info'|'browse'
      data: null,         // current view's payload buffer

      activeCmd: null,    // { cmd, args, kind } currently streaming
      packetSeries: { beacon: [], deauth: [], probe: [], eapol: [], raw: [], maxLen: 60 },

      hold: { running: false, startMs: 0, raf: 0, fired: false, target: null },

      connected: false,
      port: '',
      firmware: '',
      battery: null,
      gpsSats: 0,
      gpsFix: false,
      target: null,
      stoppedAt: 0,
    };

    // --------------------------------------------------------------- DOM mount
    function mount() {
      if (state.mounted) return state.panelEl;
      var tpl = document.getElementById('marauderPanelTpl');
      if (!tpl || !tpl.content) return null;
      var frag = tpl.content.cloneNode(true);
      var wrap = frag.querySelector('[data-mar-wrap]');
      state.panelEl = wrap;
      state.viewEl  = wrap.querySelector('[data-mar-view]');
      state.crumbEl = wrap.querySelector('[data-mar-crumb]');
      state.modeEl  = wrap.querySelector('[data-mar-stat-mode]');
      state.statBat = wrap.querySelector('[data-mar-stat-bat]');
      state.statGps = wrap.querySelector('[data-mar-stat-gps]');
      state.statTgt = wrap.querySelector('[data-mar-stat-tgt]');
      state.sideLink = wrap.querySelector('[data-mar-link]');
      state.sidePort = wrap.querySelector('[data-mar-port]');
      state.sideFw   = wrap.querySelector('[data-mar-fw]');
      state.sideDpad = wrap.querySelector('[data-mar-dpadmode]');
      state.mounted = true;
      // Re-measure scale on resize
      window.addEventListener('resize', scheduleRescale);
      return state.panelEl;
    }

    var _rescaleRaf = 0;
    function scheduleRescale() {
      if (_rescaleRaf) return;
      _rescaleRaf = requestAnimationFrame(function () {
        _rescaleRaf = 0;
        rescale();
      });
    }
    function rescale() {
      var wrap = state.panelEl;
      if (!wrap || !wrap.parentNode) return;
      var tft = wrap.querySelector('[data-mar-tft]');
      if (!tft) return;
      // Available area = parent's box; the side strip steals ~110px on wide.
      var rect = wrap.getBoundingClientRect();
      var sideW = (window.innerWidth > 720) ? 110 : 0;
      var availW = Math.max(160, rect.width - sideW - 24);
      var availH = Math.max(140, rect.height - 24);
      var s = Math.min(availW / 320, availH / 240);
      // Keep a sane min/max so we don't get pixel slop or absurd zoom.
      s = Math.max(0.6, Math.min(s, 3.5));
      tft.style.setProperty('--mar-scale', s.toFixed(3));
    }

    // --------------------------------------------------------------- enter / leave
    function enter() {
      var ss = ensureSubscreen();
      if (!ss) return;
      clearEl(ss);
      var panel = mount();
      if (!panel) return;
      ss.appendChild(panel);
      // Reset stack to root menu
      state.stack = [{
        view: 'menu',
        items: TREE.items,
        cursor: 0,
        title: TREE.title,
      }];
      state.view = 'menu';
      state.data = null;
      state.target = null;
      state.activeCmd = null;
      // Mark route active so dpad shows + apply device mode if currently scrollback
      document.body.dataset.marauderActive = '1';
      _dpadMode = 'device';
      try { sessionStorage.setItem('promptzero_dpad_mode', _dpadMode); } catch (_) {}
      applyDpadMode();
      // Acquire the holder slot
      sendWs({ type: 'marauder_acquire' });
      render();
      scheduleRescale();
    }

    function leave() {
      stopHold();
      stopActive('stop');
      sendWs({ type: 'marauder_release' });
      document.body.dataset.marauderActive = '';
      applyDpadMode();
    }

    // --------------------------------------------------------------- render
    function render() {
      if (!state.mounted) return;
      // Crumb
      var path = state.stack.map(function (f) { return f.title || f.label; }).join(' › ');
      state.crumbEl.textContent = path || 'MAIN';
      // Mode pill
      var mode = state.view === 'fire' ? 'ARM'
               : state.view === 'streaming' ? 'RUN'
               : state.activeCmd ? 'RUN' : 'IDLE';
      state.modeEl.textContent = mode;
      state.modeEl.dataset.state = mode === 'ARM' ? 'atk' : mode === 'RUN' ? 'run' : '';
      // Status bar fields
      updateStatus();
      // Side strip
      if (state.sideLink) {
        state.sideLink.textContent = state.connected ? 'ONLINE' : 'OFFLINE';
        state.sideLink.dataset.state = state.connected ? 'on' : 'off';
      }
      if (state.sidePort) state.sidePort.textContent = state.port || '—';
      if (state.sideFw)   state.sideFw.textContent   = (state.firmware || '—').slice(0, 14);
      if (state.sideDpad) state.sideDpad.textContent = (_dpadMode === 'device') ? 'DEVICE' : 'SCROLL';

      var view = state.viewEl;
      clearEl(view);
      switch (state.view) {
        case 'menu':       renderMenu(view); break;
        case 'leds':       renderLeds(view); break;
        case 'list':       renderList(view); break;
        case 'gps':        renderGps(view);  break;
        case 'graph':      renderGraph(view); break;
        case 'fire':       renderFire(view); break;
        case 'streaming':  renderStreaming(view); break;
        case 'info':       renderInfo(view); break;
        case 'browse':     renderBrowse(view); break;
        default:           renderPlaceholder(view, 'UNKNOWN VIEW');
      }
    }

    function updateStatus() {
      // Battery: pulled from auto-poll body if we ever store it; for now, use --
      if (state.statBat) {
        state.statBat.textContent = 'BAT ' + (state.battery == null ? '--%' : (state.battery + '%'));
      }
      if (state.statGps) {
        state.statGps.textContent = 'GPS ' + (state.gpsSats || 0) + 'sat';
      }
      if (state.statTgt) {
        state.statTgt.textContent = 'TGT ' + (state.target ? String(state.target).slice(0, 6) : '—');
      }
    }

    // --------------------------------------------------------------- renderers
    function renderPlaceholder(view, label, sub) {
      var p = mkEl('div', 'mar-placeholder');
      p.appendChild(mkEl('div', 'mar-spinner', '◴'));
      p.appendChild(mkEl('strong', null, label || 'WAITING'));
      if (sub) p.appendChild(mkEl('div', null, sub));
      view.appendChild(p);
    }

    function renderMenu(view) {
      var frame = top();
      var list = mkEl('div', 'mar-list');
      frame.items.forEach(function (it, i) {
        var row = mkEl('div', 'mar-row');
        if (i === frame.cursor) row.dataset.selected = '1';
        row.appendChild(mkEl('span', 'mar-row-arrow', i === frame.cursor ? '▸' : ' '));
        row.appendChild(mkEl('span', 'mar-row-label', it.label));
        var meta = '';
        if (it.kind === 'menu' || it.kind === 'leds') meta = '›';
        else if (it.kind === 'attack') meta = '⚠';
        else if (it.kind === 'list')   meta = '◉';
        else if (it.kind === 'graph')  meta = '⇅';
        else if (it.kind === 'gps')    meta = '⊕';
        else if (it.kind === 'browse') meta = '/';
        else if (it.kind === 'info')   meta = 'i';
        row.appendChild(mkEl('span', 'mar-row-meta', meta));
        list.appendChild(row);
      });
      view.appendChild(list);
    }

    function renderLeds(view) {
      var frame = top();
      var grid = mkEl('div', 'mar-leds');
      frame.items.forEach(function (it, i) {
        var sw = mkEl('div', 'mar-led');
        if (i === frame.cursor) sw.dataset.selected = '1';
        if (it.rainbow) {
          sw.dataset.rainbow = '1';
        } else {
          sw.style.setProperty('--swatch', '#' + it.hex);
        }
        sw.appendChild(mkEl('span', null, it.label.toUpperCase()));
        grid.appendChild(sw);
      });
      view.appendChild(grid);
    }

    function renderList(view) {
      var d = state.data || {};
      var rows = d.rows || [];
      if (rows.length === 0) {
        renderPlaceholder(view, d.title || 'SCANNING…', d.cmdLabel || '');
        return;
      }
      var list = mkEl('div', 'mar-list');
      // Show ~14 rows; cursor scrolls window
      var max = 14;
      var start = Math.max(0, Math.min(d.cursor || 0, rows.length - 1) - Math.floor(max / 2));
      start = Math.max(0, Math.min(start, Math.max(0, rows.length - max)));
      for (var i = start; i < Math.min(rows.length, start + max); i++) {
        var r = rows[i];
        var row = mkEl('div', 'mar-row');
        if (i === d.cursor) row.dataset.selected = '1';
        row.appendChild(mkEl('span', 'mar-row-arrow', i === d.cursor ? '▸' : ' '));

        var labelWrap = mkEl('span', 'mar-row-label');
        if (r.bars && r.bars > 0) {
          var bar = mkEl('span', 'mar-rssi-bar');
          bar.dataset.strength = String(r.bars);
          for (var b = 0; b < 5; b++) bar.appendChild(mkEl('i'));
          labelWrap.appendChild(bar);
        }
        labelWrap.appendChild(document.createTextNode(' ' + (r.label || '')));
        row.appendChild(labelWrap);

        var meta = mkEl('span', 'mar-row-meta', r.metaText || '');
        if (r.metaBand) meta.classList.add('mar-rssi-num');
        if (r.metaBand) meta.dataset.band = r.metaBand;
        row.appendChild(meta);
        list.appendChild(row);
      }
      view.appendChild(list);
      // Counter strip in crumb-meta? Use status bar mode pill counter
      // (already shows RUN). Add a tiny floating count in top-right.
      var counter = mkEl('div', 'mar-graph-readout');
      counter.textContent = String(rows.length);
      var sub = mkEl('small', null, 'SEEN');
      counter.appendChild(sub);
      view.appendChild(counter);
    }

    function renderGps(view) {
      var d = state.data || {};
      if (!d.fix && (!d.sats || d.sats === 0)) {
        renderPlaceholder(view, 'GPS NO FIX', 'WAITING FOR SATS');
        return;
      }
      var grid = mkEl('div', 'mar-gps');
      var rows = [
        ['FIX',   d.fix ? 'YES' : 'NO',  String(d.fix ? 1 : 0)],
        ['SATS',  String(d.sats || 0),   ''],
        ['HDOP',  d.hdop != null ? d.hdop.toFixed(2) : '—', ''],
        ['ALT',   d.alt  != null ? (d.alt.toFixed(1) + 'm') : '—', ''],
        ['LAT',   d.lat  != null ? d.lat.toFixed(5)  : '—', ''],
        ['LON',   d.lon  != null ? d.lon.toFixed(5)  : '—', ''],
        ['SPD',   d.speedKn != null ? (d.speedKn.toFixed(1) + 'kn') : '—', ''],
        ['UTC',   d.timeUTC || '—', ''],
      ];
      rows.forEach(function (r) {
        var cell = mkEl('div', 'mar-gps-cell');
        cell.appendChild(mkEl('div', 'mar-gps-label', r[0]));
        var val = mkEl('div', 'mar-gps-val', r[1]);
        if (r[2] !== '') val.dataset.fix = r[2];
        cell.appendChild(val);
        grid.appendChild(cell);
      });
      view.appendChild(grid);
    }

    function renderGraph(view) {
      var W = 320, H = 200;   // view region is ~320 × 213; leave room
      var s = state.packetSeries;
      var seriesNames = ['beacon', 'deauth', 'probe', 'eapol', 'raw'];
      var seriesColors = {
        beacon: 'var(--tft-orange)',
        deauth: 'var(--tft-red)',
        probe:  'var(--tft-amber)',
        eapol:  'var(--tft-green)',
        raw:    'var(--tft-fg-dim)',
      };
      // Determine vertical scale
      var maxVal = 1;
      seriesNames.forEach(function (n) {
        s[n].forEach(function (v) { if (v > maxVal) maxVal = v; });
      });
      var ns = 'http://www.w3.org/2000/svg';
      var svg = document.createElementNS(ns, 'svg');
      svg.setAttribute('class', 'mar-graph');
      svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
      svg.setAttribute('preserveAspectRatio', 'none');
      // Grid
      var grid = document.createElementNS(ns, 'g');
      grid.setAttribute('class', 'mar-graph-grid');
      for (var i = 1; i < 4; i++) {
        var ln = document.createElementNS(ns, 'line');
        ln.setAttribute('x1', 0); ln.setAttribute('x2', W);
        ln.setAttribute('y1', H * i / 4); ln.setAttribute('y2', H * i / 4);
        grid.appendChild(ln);
      }
      svg.appendChild(grid);
      // Traces
      seriesNames.forEach(function (name, idx) {
        var arr = s[name];
        if (!arr || arr.length < 2) return;
        var step = W / (s.maxLen - 1);
        var pts = arr.map(function (v, i) {
          var x = (i + (s.maxLen - arr.length)) * step;
          var y = H - (Math.min(v, maxVal) / maxVal) * (H - 6) - 2;
          return x.toFixed(1) + ',' + y.toFixed(1);
        }).join(' ');
        var glow = document.createElementNS(ns, 'polyline');
        glow.setAttribute('class', 'mar-graph-trace-glow');
        glow.setAttribute('points', pts);
        glow.setAttribute('style', 'stroke:' + seriesColors[name]);
        svg.appendChild(glow);
        var line = document.createElementNS(ns, 'polyline');
        line.setAttribute('class', 'mar-graph-trace');
        line.setAttribute('points', pts);
        line.setAttribute('style', 'stroke:' + seriesColors[name]);
        svg.appendChild(line);
        // Legend
        var lg = document.createElementNS(ns, 'text');
        lg.setAttribute('class', 'mar-graph-legend ' + name);
        lg.setAttribute('x', 4 + idx * 50);
        lg.setAttribute('y', 8);
        lg.textContent = name.toUpperCase();
        svg.appendChild(lg);
      });
      view.appendChild(svg);
      // Big readout: latest beacon count
      var last = (s.beacon[s.beacon.length - 1]) || 0;
      var ro = mkEl('div', 'mar-graph-readout');
      ro.textContent = String(last);
      var sub = mkEl('small', null, 'BCN/s');
      ro.appendChild(sub);
      view.appendChild(ro);
    }

    function renderFire(view) {
      var d = state.data || {};
      var fire = mkEl('div', 'mar-fire');
      if (state.hold.fired) fire.dataset.armed = '1';
      fire.appendChild(mkEl('div', 'mar-fire-cmd', (d.cmd || '').toUpperCase()));
      var argsLine = '';
      if (d.args) {
        argsLine = Object.keys(d.args).map(function (k) { return '-' + k + ' ' + d.args[k]; }).join(' ');
      }
      if (argsLine) fire.appendChild(mkEl('div', 'mar-fire-args', argsLine));

      var ring = mkEl('div', 'mar-fire-ring');
      // SVG ring
      var ns = 'http://www.w3.org/2000/svg';
      var svg = document.createElementNS(ns, 'svg');
      svg.setAttribute('viewBox', '0 0 64 64');
      var bg = document.createElementNS(ns, 'circle');
      bg.setAttribute('class', 'ring-bg');
      bg.setAttribute('cx', 32); bg.setAttribute('cy', 32); bg.setAttribute('r', 28);
      svg.appendChild(bg);
      var fill = document.createElementNS(ns, 'circle');
      fill.setAttribute('class', 'ring-fill');
      fill.setAttribute('cx', 32); fill.setAttribute('cy', 32); fill.setAttribute('r', 28);
      svg.appendChild(fill);
      ring.appendChild(svg);
      var glyph = mkEl('div', 'mar-fire-glyph', state.hold.fired ? '◉' : 'OK');
      ring.appendChild(glyph);
      fire.appendChild(ring);

      var hint = mkEl('div', 'mar-fire-hint');
      hint.appendChild(mkEl('b', null, 'HOLD OK 1.5s'));
      hint.appendChild(document.createTextNode(' TO ARM · BACK TO ABORT'));
      fire.appendChild(hint);

      view.appendChild(fire);
      // Initial ring progress
      ring.style.setProperty('--hold-progress', state.hold.running
        ? Math.min((Date.now() - state.hold.startMs) / 1500, 1).toFixed(3)
        : '0');
    }

    function renderStreaming(view) {
      var d = state.data || {};
      var wrap = mkEl('div', 'mar-stream');
      var head = mkEl('div', 'mar-stream-head');
      head.appendChild(mkEl('span', null, (d.cmd || '').toUpperCase()));
      var counter = mkEl('span', 'mar-stream-counter', String(d.events || 0));
      head.appendChild(counter);
      wrap.appendChild(head);

      var log = mkEl('div', 'mar-stream-log');
      (d.lines || []).slice(-12).reverse().forEach(function (ln) {
        var row = mkEl('div', 'row' + (ln.level ? (' ' + ln.level) : ''), ln.text);
        log.appendChild(row);
      });
      wrap.appendChild(log);

      var stop = mkEl('div', 'mar-stream-stop', 'BACK TO STOP');
      wrap.appendChild(stop);
      view.appendChild(wrap);
    }

    function renderInfo(view) {
      var d = state.data || {};
      var grid = mkEl('div', 'mar-info');
      var rows = [
        ['LINK',     state.connected ? 'ONLINE' : 'OFFLINE'],
        ['PORT',     state.port || '—'],
        ['FIRMWARE', state.firmware || '—'],
        ['BATTERY',  state.battery != null ? (state.battery + '%') : '—'],
        ['GPS SATS', String(state.gpsSats || 0)],
        ['GPS FIX',  state.gpsFix ? 'YES' : 'NO'],
      ];
      rows.forEach(function (r) {
        grid.appendChild(mkEl('div', 'mar-info-key', r[0]));
        grid.appendChild(mkEl('div', 'mar-info-val', r[1]));
      });
      view.appendChild(grid);
    }

    function renderBrowse(view) {
      var d = state.data || {};
      if (!d.entries || d.entries.length === 0) {
        renderPlaceholder(view, 'BROWSING SD', d.path || '/');
        return;
      }
      var list = mkEl('div', 'mar-list');
      d.entries.forEach(function (e, i) {
        var row = mkEl('div', 'mar-row');
        if (i === d.cursor) row.dataset.selected = '1';
        row.appendChild(mkEl('span', 'mar-row-arrow', i === d.cursor ? '▸' : ' '));
        row.appendChild(mkEl('span', 'mar-row-label', e.name));
        row.appendChild(mkEl('span', 'mar-row-meta', e.kind === 'dir' ? '/' : (e.size || '')));
        list.appendChild(row);
      });
      view.appendChild(list);
    }

    // --------------------------------------------------------------- nav helpers
    function top() { return state.stack[state.stack.length - 1] || null; }

    function pushFrame(item) {
      if (item.kind === 'menu') {
        state.stack.push({ view: 'menu', items: item.items, cursor: 0, title: item.title || item.label });
        state.view = 'menu';
        state.data = null;
      } else if (item.kind === 'leds') {
        state.stack.push({ view: 'leds', items: item.items, cursor: 0, title: item.title || 'LED' });
        state.view = 'leds';
        state.data = null;
      } else if (item.kind === 'list') {
        state.stack.push({ view: 'list', title: item.label, leaf: item });
        state.view = 'list';
        state.data = { rows: [], cursor: 0, dedupKeys: {}, evt: item.evt, col: item.col, cmd: item.cmd, cmdLabel: item.label };
        startCmd(item.cmd, 'start', item.args || {});
      } else if (item.kind === 'graph') {
        state.stack.push({ view: 'graph', title: item.label, leaf: item });
        state.view = 'graph';
        state.data = {};
        // reset series
        state.packetSeries = { beacon: [], deauth: [], probe: [], eapol: [], raw: [], maxLen: 60 };
        startCmd(item.cmd, 'start', item.args || {});
      } else if (item.kind === 'gps') {
        state.stack.push({ view: 'gps', title: item.label, leaf: item });
        state.view = 'gps';
        state.data = { sats: state.gpsSats, fix: state.gpsFix };
        startCmd('gpsdata', 'once', {});
      } else if (item.kind === 'attack') {
        state.stack.push({ view: 'fire', title: item.label, leaf: item });
        state.view = 'fire';
        state.data = { cmd: item.cmd, args: item.args || {}, attack: true, label: item.label };
      } else if (item.kind === 'browse') {
        state.stack.push({ view: 'browse', title: item.label, leaf: item });
        state.view = 'browse';
        state.data = { path: '/', entries: [], cursor: 0 };
        startCmd('ls', 'start',{ path: '/' });
      } else if (item.kind === 'info') {
        state.stack.push({ view: 'info', title: item.label, leaf: item });
        state.view = 'info';
        state.data = {};
      } else {
        return;
      }
    }

    function popFrame() {
      if (state.stack.length <= 1) return false;
      stopHold();
      stopActive('stop');
      state.stack.pop();
      var f = top();
      state.view = f.view;
      state.data = (f.view === 'menu' || f.view === 'leds') ? null : state.data;
      // For menu / leds frame, ensure data null
      if (f.view === 'menu' || f.view === 'leds') state.data = null;
      return true;
    }

    function selectCurrent() {
      var f = top();
      if (!f) return;
      if (f.view === 'menu') {
        var it = f.items[f.cursor];
        if (it) pushFrame(it);
      } else if (f.view === 'leds') {
        var it2 = f.items[f.cursor];
        if (it2) {
          if (it2.rainbow) {
            sendWs({ type: 'marauder_cmd', cmd: 'led_rainbow', action: 'once', args: {} });
          } else {
            sendWs({ type: 'marauder_cmd', cmd: 'led_set', action: 'once', args: { hex: it2.hex } });
          }
          showToast('LED → ' + it2.label.toUpperCase());
        }
      } else if (f.view === 'list') {
        // Set target = selected row's identifier
        var d = state.data || {}; var r = (d.rows || [])[d.cursor || 0];
        if (r) state.target = r.label;
      } else if (f.view === 'browse') {
        var d2 = state.data || {}; var e = (d2.entries || [])[d2.cursor || 0];
        if (e && e.kind === 'dir') {
          d2.path = (d2.path === '/' ? '' : d2.path) + '/' + e.name;
          d2.entries = [];
          d2.cursor = 0;
          startCmd('ls', 'start',{ path: d2.path });
        }
      }
    }

    // --------------------------------------------------------------- WS commands
    function startCmd(cmd, action, args) {
      stopActive(null);
      state.activeCmd = { cmd: cmd, args: args, action: action };
      sendWs({ type: 'marauder_cmd', cmd: cmd, action: action || 'start', args: args || {} });
    }

    function stopActive(_reason) {
      if (!state.activeCmd) return;
      // Send stop only for streaming-like actions
      if (state.activeCmd.action === 'start') {
        sendWs({ type: 'marauder_cmd', cmd: state.activeCmd.cmd, action: 'stop', args: state.activeCmd.args || {} });
      }
      state.activeCmd = null;
    }

    // --------------------------------------------------------------- hold-to-fire
    function startHold() {
      if (state.view !== 'fire' || state.hold.running) return;
      state.hold.running = true;
      state.hold.fired = false;
      state.hold.startMs = Date.now();
      var loop = function () {
        if (!state.hold.running) return;
        var p = Math.min((Date.now() - state.hold.startMs) / 1500, 1);
        var ring = state.viewEl && state.viewEl.querySelector('.mar-fire-ring');
        if (ring) ring.style.setProperty('--hold-progress', p.toFixed(3));
        if (p >= 1) {
          state.hold.fired = true;
          fireArmed();
          return;
        }
        state.hold.raf = requestAnimationFrame(loop);
      };
      state.hold.raf = requestAnimationFrame(loop);
      beep(440, 0.06);
    }
    function stopHold() {
      if (!state.hold.running) return;
      cancelAnimationFrame(state.hold.raf);
      state.hold.running = false;
      state.hold.raf = 0;
      state.hold.fired = false;
      state.hold.startMs = 0;
      var ring = state.viewEl && state.viewEl.querySelector('.mar-fire-ring');
      if (ring) ring.style.setProperty('--hold-progress', '0');
    }
    function fireArmed() {
      var d = state.data || {};
      var leaf = top() && top().leaf;
      if (!leaf) { stopHold(); return; }
      // Transition fire frame → streaming frame in place
      var streamFrame = { view: 'streaming', title: leaf.label, leaf: leaf };
      state.stack.pop();
      state.stack.push(streamFrame);
      state.view = 'streaming';
      state.data = {
        cmd: d.cmd, args: d.args || {}, lines: [],
        events: 0, attack: true,
      };
      startCmd(d.cmd, 'start', d.args || {});
      stopHold();
      beep(880, 0.12);
      render();
    }

    // --------------------------------------------------------------- dpad routing
    function handleDpad(dir) {
      // Fire screen: OK is owned by the hold handlers; clicks should be ignored.
      if (state.view === 'fire' && dir === 'ok') return;

      switch (dir) {
        case 'up':    moveCursor(-1); break;
        case 'down':  moveCursor(+1); break;
        case 'left':  popFrame(); break;
        case 'right':
          // Right: same as OK on a menu, but doesn't fire attacks (safer)
          if (state.view === 'menu' || state.view === 'leds' || state.view === 'browse') selectCurrent();
          break;
        case 'ok':    selectCurrent(); break;
        case 'back':  popFrame(); break;
      }
      render();
    }

    function moveCursor(delta) {
      var f = top();
      if (!f) return;
      if (f.view === 'menu' || f.view === 'leds') {
        var n = f.items.length;
        f.cursor = (f.cursor + delta + n) % n;
      } else if (f.view === 'list') {
        var rows = (state.data && state.data.rows) || [];
        if (rows.length === 0) return;
        var c = state.data.cursor || 0;
        state.data.cursor = (c + delta + rows.length) % rows.length;
      } else if (f.view === 'browse') {
        var es = (state.data && state.data.entries) || [];
        if (es.length === 0) return;
        var c2 = state.data.cursor || 0;
        state.data.cursor = (c2 + delta + es.length) % es.length;
      }
    }

    // --------------------------------------------------------------- WS events
    function onMessage(msg) {
      switch (msg.type) {
        case 'marauder_status':
          state.connected = !!msg.connected;
          state.port      = msg.port || '';
          state.firmware  = msg.firmware || '';
          render();
          break;
        case 'marauder_event':
          handleEvent(msg.kind, msg.payload || {});
          break;
        case 'marauder_done':
          if (state.activeCmd && state.activeCmd.cmd === msg.cmd) state.activeCmd = null;
          if (state.view === 'streaming' && state.data) {
            state.data.lines = (state.data.lines || []).concat([{ level: '', text: '✓ done' }]);
          }
          render();
          break;
        case 'marauder_error':
          if (state.view === 'streaming' && state.data) {
            state.data.lines = (state.data.lines || []).concat([{ level: 'err', text: 'ERR: ' + (msg.message || msg.cmd) }]);
          } else {
            showToast('Marauder: ' + (msg.message || msg.cmd || 'error'));
          }
          render();
          break;
      }
    }

    function handleEvent(kind, p) {
      switch (kind) {
        case 'ap_seen':
        case 'sta_seen':
        case 'ble_seen':
        case 'beacon':
        case 'probe':
        case 'deauth_seen':
        case 'raw':
        case 'ble_wardrive':
        case 'nmea_line':
          appendListRow(kind, p);
          // also feed the streaming log so the streaming view gets updates
          appendStreamLine(kind, p);
          break;
        case 'packet_rate':
          ingestPacketRate(p);
          break;
        case 'gps':
          state.gpsSats = p.sats || 0;
          state.gpsFix  = !!p.fix;
          if (state.view === 'gps') {
            state.data = Object.assign(state.data || {}, p);
          }
          break;
        case 'attack_status':
        case 'portal_status':
          if (state.view === 'streaming' && state.data) {
            state.data.lines = (state.data.lines || []).concat([{ level: 'warn', text: shortPayload(p) }]);
            state.data.events = (state.data.events || 0) + 1;
          }
          break;
        case 'ls_entry':
          // Backend's `ls` registry entry runs in modeStream and emits one
          // `ls_entry` event per parsed directory row (parsers.ParseLs).
          // pushFrame('browse') initialises entries=[] so we just append.
          if (state.view === 'browse' && state.data) {
            if (!Array.isArray(state.data.entries)) state.data.entries = [];
            state.data.entries.push(p);
          }
          break;
        case 'led_ack':
        case 'stopped':
          break;
      }
      render();
    }

    function appendListRow(kind, payload) {
      if (state.view !== 'list') return;
      var d = state.data; if (!d) return;
      var col = COLUMNS[d.col] || COLUMNS.ap;
      // raw / nmea are line streams — every emit is a fresh log row, NEVER
      // deduped. Scan-style columns (ap/sta/ble/wardrive) dedup by stable
      // identifier so RSSI updates refresh the existing row in place.
      var lineStream = (d.col === 'raw' || d.col === 'nmea');
      var key = lineStream
        ? ('row-' + (d._seq = (d._seq || 0) + 1))
        : (payload.bssid || payload.mac || payload.ssid || payload.line || JSON.stringify(payload));
      if (!lineStream && d.dedupKeys[key] != null) {
        // update existing row (refresh RSSI/last-seen)
        var idx = d.dedupKeys[key];
        var r = d.rows[idx]; col(r, payload); r._seen = Date.now();
        return;
      }
      var r2 = { _key: key, _seen: Date.now() };
      col(r2, payload);
      d.dedupKeys[key] = d.rows.length;
      d.rows.push(r2);
      // Keep list bounded so we don't hog memory on long scans
      if (d.rows.length > 256) {
        var dropped = d.rows.shift();
        delete d.dedupKeys[dropped._key];
        // re-index
        d.dedupKeys = {};
        d.rows.forEach(function (rw, ix) { d.dedupKeys[rw._key] = ix; });
        if (d.cursor > 0) d.cursor--;
      }
    }

    function appendStreamLine(kind, p) {
      if (state.view !== 'streaming' || !state.data) return;
      state.data.events = (state.data.events || 0) + 1;
      state.data.lines = state.data.lines || [];
      state.data.lines.push({ level: '', text: shortPayload(p) });
      if (state.data.lines.length > 60) state.data.lines.shift();
    }

    function shortPayload(p) {
      if (!p || typeof p !== 'object') return String(p || '');
      if (p.line) return String(p.line).slice(0, 36);
      if (p.ssid) return (p.ssid + ' · RSSI ' + (p.rssi || '')).slice(0, 36);
      if (p.mac)  return (p.mac + ' · RSSI ' + (p.rssi || '')).slice(0, 36);
      if (p.message) return String(p.message).slice(0, 36);
      var ks = Object.keys(p).slice(0, 3);
      return ks.map(function (k) { return k + '=' + p[k]; }).join(' ').slice(0, 36);
    }

    function ingestPacketRate(p) {
      var s = state.packetSeries;
      ['beacon', 'deauth', 'probe', 'eapol', 'raw'].forEach(function (n) {
        var v = Number(p[n] || 0);
        s[n].push(v);
        if (s[n].length > s.maxLen) s[n].shift();
      });
    }

    // --------------------------------------------------------------- public
    return {
      enter: enter,
      leave: leave,
      onMessage: onMessage,
      handleDpad: handleDpad,
      isActive: function () { return document.body.dataset.marauderActive === '1'; },
      view: function () { return state.view; },
      startHold: startHold,
      stopHold: stopHold,
      render: render,
      // Debug helper for stub-WS testing in the browser console:
      _state: state,
      _injectEvent: function (k, p) { handleEvent(k, p || {}); render(); },
    };
  }());

  // Expose for stub-WS debugging from the browser console.
  try { window.MarauderUI = Marauder; } catch (_) {}

  function setupMarauderHoldHandlers() {
    var okBtn = document.querySelector('.dpad button[data-dir="ok"]');
    if (!okBtn) return;
    var press = function (e) {
      if (!Marauder.isActive() || Marauder.view() !== 'fire') return;
      if (e && e.preventDefault) e.preventDefault();
      Marauder.startHold();
    };
    var release = function (e) {
      if (!Marauder.isActive() || Marauder.view() !== 'fire') return;
      if (e && e.preventDefault) e.preventDefault();
      Marauder.stopHold();
      Marauder.render();
    };
    okBtn.addEventListener('mousedown', press);
    okBtn.addEventListener('mouseup', release);
    okBtn.addEventListener('mouseleave', release);
    okBtn.addEventListener('touchstart', press, { passive: false });
    okBtn.addEventListener('touchend', release);
    okBtn.addEventListener('touchcancel', release);

    // Keyboard fallback: hold Space/Enter to arm
    document.addEventListener('keydown', function (e) {
      if (!Marauder.isActive() || Marauder.view() !== 'fire') return;
      if (e.repeat) return;
      if (e.key !== ' ' && e.key !== 'Enter') return;
      e.preventDefault();
      Marauder.startHold();
    });
    document.addEventListener('keyup', function (e) {
      if (!Marauder.isActive() || Marauder.view() !== 'fire') return;
      if (e.key !== ' ' && e.key !== 'Enter') return;
      e.preventDefault();
      Marauder.stopHold();
      Marauder.render();
    });
  }

  /* =========================================================================
     Initialisation
  ========================================================================= */

  function init() {
    buildMascot();
    setupDrawer();
    setupRailNav();
    setupRailCollapse();
    setupRailGroups();
    setupSessions();
    setupQuickActions();
    setupDpad();
    setupDpadModeToggle();
    setupMarauderHoldHandlers();
    setupHistory();
    setupInputForm();

    // Scroll-pause: when user scrolls up >40px from bottom, stop auto-scroll
    var sb = document.getElementById('scrollback');
    if (sb) {
      sb.addEventListener('scroll', function () {
        _autoScrollPaused = (sb.scrollHeight - sb.scrollTop - sb.clientHeight) > 40;
      }, { passive: true });
    }

    setCrumbs('AGENT', 'SESSION');

    runBoot()
      .then(authBootstrap)
      .then(function () {
        connect();
        startDevicePoll();
        startCostPoll();
        // Pre-load personas silently so Settings > Persona is snappy
        apiFetch('api/personas')
          .then(function (r) { return r.ok ? r.json() : null; })
          .then(function (d) { if (d) { _personas.current = d.current || ''; _personas.list = Array.isArray(d.available) ? d.available : []; } })
          .catch(function () {});
      });

    window.addEventListener('beforeunload', function () {
      if (_screenState.isHolder) { try { sendWs({ type: 'screen_release' }); } catch (_) {} }
      if (Marauder.isActive())   { try { sendWs({ type: 'marauder_release' }); } catch (_) {} }
      if (_ws) { try { _ws.close(); } catch (_) {} }
    });
  }

  document.addEventListener('DOMContentLoaded', init);

})();
