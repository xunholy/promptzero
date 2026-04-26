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

  // 11 columns x 9 rows — Flipper dolphin pixel art
  // Values: 1=on, 'd'=dim, 0=transparent
  var MASCOT_ROWS = [
    [0,0,0,0,1,1,0,0,0,0,0],
    [0,0,0,1,1,1,1,0,0,0,0],
    [0,0,1,1,1,1,1,1,1,0,0],
    [0,1,1,'d','d',1,1,1,1,1,0],
    [1,1,1,1,1,1,1,1,1,1,0],
    [0,1,1,1,1,1,'d',1,1,1,0],
    [0,0,1,1,1,1,1,0,1,1,0],
    [0,0,0,1,1,1,0,0,0,1,1],
    [0,0,0,0,1,0,0,0,0,0,0],
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

  function showMascot() {
    var m = document.getElementById('mascot');
    var il = document.getElementById('idleLine');
    if (m)  m.style.display  = '';
    if (il) il.style.display = '';
  }

  function hideMascot() {
    var m = document.getElementById('mascot');
    var il = document.getElementById('idleLine');
    if (m)  m.style.display  = 'none';
    if (il) il.style.display = 'none';
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
    qAll('.rail-item[data-route]').forEach(function (item) {
      item.addEventListener('click', function () { activateRoute(item.dataset.route); });
      item.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); activateRoute(item.dataset.route); }
      });
    });
  }

  function setActiveRailItem(route) {
    qAll('.rail-item[data-route]').forEach(function (i) {
      i.classList.toggle('active', i.dataset.route === route);
    });
  }

  function activateRoute(route) {
    beep(660, 0.05);
    setActiveRailItem(route);

    // Auto-release mirror if navigating away from device screen while holding.
    if (_screenState.isHolder && _currentScreen === 'device' && route !== 'device') {
      releaseScreen();
    }

    // Subsystem rail items show a category landing screen with tools/attacks
    if (CATEGORY_TOOLS[route]) {
      showScreen('category-' + route);
      setCrumbs(CATEGORY_TOOLS[route].title, 'TOOLS');
      loadCategoryScreen(route);
      return;
    }

    switch (route) {
      case 'agent':    showAgentScreen();   break;
      case 'device':   showScreen('device');   setCrumbs('DEVICE', 'MIRROR');    loadDeviceScreen();   break;
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
      '-webkit-overflow-scrolling:touch;padding-right:6px;scrollbar-width:thin;display:none;';
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
    if (ss) { ss.style.display = ''; clearEl(ss); }
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

      case 'screen_state':
        onScreenStateMessage(msg);
        break;

      case 'screen_error':
        onScreenErrorMessage(msg);
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

    var wrap = mkEl('div', 'msg sys');
    var key  = (msg.turn_id || '') + '|' + (msg.name || '');
    wrap.dataset.toolKey = key;

    var who  = mkEl('div', 'who', '▶');
    var body = mkEl('div', 'body');
    var meta = mkEl('div', 'meta');

    var nameSpan = mkEl('span', null, msg.name || 'tool');  // textContent — safe
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
    body.appendChild(meta);

    if (msg.input) {
      var pre = mkEl('pre', null, fmtJSON(msg.input));  // textContent — safe
      body.appendChild(pre);
    }

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

    var body = wrap.querySelector('.body');
    if (body && (msg.output || msg.err)) {
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
      body.appendChild(tileDiv);
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

  /* =========================================================================
     Status bar — /api/device + /api/debug polling
  ========================================================================= */

  function startDevicePoll() {
    pollDevice();
    _deviceTimer = setInterval(pollDevice, 30000);
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
        [['PROMPTZERO', build.version || 'v0.9'],
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

    // Update rail badge
    var badge = document.getElementById('deviceBadge');
    if (badge) badge.textContent = _screenState.active ? '▶' : '▶';
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
     Initialisation
  ========================================================================= */

  function init() {
    buildMascot();
    setupDrawer();
    setupRailNav();
    setupDpad();
    setupDpadModeToggle();
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
      if (_ws) { try { _ws.close(); } catch (_) {} }
    });
  }

  document.addEventListener('DOMContentLoaded', init);

})();
