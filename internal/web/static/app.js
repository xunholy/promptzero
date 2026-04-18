/* PromptZero — Alpine state shell + WS client + dev mock */

(function () {
  'use strict';

  /* ----------------------------------------------------------------------
     Lucide inline icons (stroke 1.75, 16px)
  ---------------------------------------------------------------------- */
  var ICONS = {
    send:    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M13 6l6 6-6 6"/></svg>',
    check:   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12l5 5 9-11"/></svg>',
    x:       '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 6l12 12M18 6L6 18"/></svg>',
    spinner: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 11-9-9"/></svg>',
    battery: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="7" width="16" height="10" rx="1"/><path d="M22 11v2"/></svg>',
  };

  /* ----------------------------------------------------------------------
     Flipper motif loader (lazy fetch, reactive cache)
     Tool name → motif: subghz_* → waveform, rfid_* → antenna,
     nfc_* → chip, wifi_*|*marauder* → dish, else dolphin.
  ---------------------------------------------------------------------- */
  var MOTIFS = ['dolphin', 'subghz-waveform', 'rfid-antenna', 'nfc-chip', 'marauder-dish'];

  function motifFor(toolName) {
    if (!toolName) return 'dolphin';
    var n = String(toolName).toLowerCase();
    if (n.indexOf('subghz') === 0 || n.indexOf('sub_ghz') === 0 || n.indexOf('sub-ghz') === 0) return 'subghz-waveform';
    if (n.indexOf('rfid') === 0) return 'rfid-antenna';
    if (n.indexOf('nfc') === 0)  return 'nfc-chip';
    if (n.indexOf('wifi') === 0 || n.indexOf('marauder') !== -1) return 'marauder-dish';
    return 'dolphin';
  }

  var BRAILLE = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏'];

  var CAPTURE_TOOLS = /^(rfid_read|nfc_detect|ir_receive|subghz_receive|ibutton_read)$/;

  /* User prompt → expected output shape for skeleton placeholder */
  var Q_WORDS = /^\s*(what|how|why|when|where|who|tell me|explain|describe|is|are|does|do|can|should)\b/i;
  var CMD_WORDS = /^\s*(scan|read|detect|transmit|send|write|emulate|replay|sweep|capture|list|show|run|execute|start|stop)\b/i;

  function skeletonShape(text) {
    if (!text) return 'line';
    if (Q_WORDS.test(text)) return 'paragraph';
    if (CMD_WORDS.test(text)) return 'tool';
    return 'line';
  }

  /* Map error content/kind → banner class */
  function classifyError(msg) {
    if (msg && typeof msg.kind === 'string') return msg.kind;
    var s = String((msg && msg.content) || '').toLowerCase();
    if (s.indexOf('cancel') !== -1 || s.indexOf('stopped') !== -1) return 'cancelled';
    if (s.indexOf('flipper') !== -1 || s.indexOf('device') !== -1 || s.indexOf('serial') !== -1 || s.indexOf('disconnect') !== -1) return 'device';
    if (s.indexOf('tool') !== -1) return 'tool';
    return 'api';
  }

  function prefersReducedMotion() {
    return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  }

  function shortId(prefix) {
    var r;
    try { r = crypto.randomUUID().replace(/-/g, ''); }
    catch (_) { r = Math.random().toString(36).slice(2) + Date.now().toString(36); }
    return (prefix || '') + r.slice(0, 8);
  }

  /* ----------------------------------------------------------------------
     Alpine factory
  ---------------------------------------------------------------------- */
  function pzApp() {
    return {
      /* state shape (per spec) */
      connection: 'connecting',
      session: {
        id: shortId(''),
        device: { name: '', fork: '', version: '', battery: null },
        phase: 'Idle',
        verb: 'Thinking',
        turnStartedAt: null,
      },
      feed: [],                /* unified timeline: {id, kind:'user'|'agent'|'tool'|'skeleton'|'disconnect', ...} */
      queuedPrompts: [],
      confirmRequest: null,
      criticalConfirmText: '',
      currentTurnId: null,
      input: '',
      recordingAudio: false,

      /* polish layer state */
      errorBanner: null,               /* {kind:'api'|'tool'|'device'|'cancelled', message, retryTarget?} */
      reconnectToast: false,
      offlineCard: false,
      newMessagesPending: false,
      liveRegionText: '',              /* phase-only announcements */

      /* ui-only */
      copied: false,
      spinnerFrame: BRAILLE[0],
      elapsedLabel: '0.0s',
      motifSvg: Object.create(null),   /* reactive: motif → svg string */
      icons: ICONS,

      /* REPL-parity panels */
      personaUI: { open: false, current: '', list: [] },
      sidebar:   { open: false, tab: 'watch' },
      watchUI:   { loaded: false, error: '', enabled: false, paused: false, paths: [], rules: [], events: [] },
      rulesUI:   { loaded: false, error: '', list: [], testResults: {} },
      costUI:    { loaded: false, error: '', usd: 0, inputTokens: 0, outputTokens: 0, offline: false, byModel: [], modalOpen: false },
      validateUI: { open: false, path: '', content: '', loading: false, error: '', report: null },
      debugUI:   { open: false, loaded: false, error: '', snapshot: null, copied: false },
      deviceUI:  { open: false, loaded: false, error: '', snapshot: null, title: 'DEVICE PROFILE' },

      /* internals */
      _ws: null,
      _wsBackoff: 800,
      _spinnerTimer: null,
      _elapsedTimer: null,
      _heartbeatWatchdog: null,
      _costTimer: null,
      _deviceTimer: null,
      _knownPersonaSwitchIds: [],
      _lastPingAt: 0,
      _reduced: false,
      _autoScrollPaused: false,
      _lastUserPrompt: '',
      _lastToolCall: null,             /* {name, input, turn_id} for 'Retry tool' */
      _disconnectStartedAt: 0,
      _disconnectTimer: null,
      _skeletonIds: [],                /* ids in feed that are skeletons */

      /* ---------- derived ---------- */
      get canSend()         { return !!this.input.trim() && this.connection !== 'offline' && !this.composerDisabled; },
      get composerDisabled(){ return false; /* never disabled: Enter queues during a turn */ },
      get charCountClass() {
        var n = this.input.length;
        if (n > 3500) return 'pz-count-crit';
        if (n > 2000) return 'pz-count-warn';
        return '';
      },
      get placeholder() {
        if (this.connection === 'offline') return 'reconnecting…';
        if (this.session.phase === 'Idle') return 'type a command  ↵';
        return 'queue next turn  ↵';
      },
      get showTicker() { return this.session.phase !== 'Idle'; },
      get sessionPillText() { return '#s-' + (this.session.id || '').slice(0, 6); },
      get firmwareLabel() {
        var fork = this.session.device.fork || '';
        var ver  = this.session.device.version || '';
        if (!fork && !ver) return '—';
        if (!ver) return fork;
        return fork ? fork + ' ' + ver : ver;
      },
      get batteryLabel() {
        var n = this.session.device.battery;
        return (n === null || n === undefined) ? '—' : (n + '%');
      },
      get inlineConfirm()   { return this.confirmRequest && this.confirmRequest.risk !== 'critical' ? this.confirmRequest : null; },
      get criticalConfirm() { return this.confirmRequest && this.confirmRequest.risk === 'critical' ? this.confirmRequest : null; },
      get criticalReady()   { return this.criticalConfirmText.trim().toLowerCase() === 'all'; },
      get connectionGlyph() {
        if (this.connection === 'online')  return '●';
        if (this.connection === 'slow')    return '▲';
        if (this.connection === 'offline') return '✕';
        return '○';
      },

      /* ---------- lifecycle ---------- */
      init() {
        this._reduced = prefersReducedMotion();
        this._loadMotifs();
        this._startSpinner();
        this._startElapsed();
        this._startHeartbeatWatchdog();
        this._installMock();
        this._connect();
        this.loadPersonas();
        this.loadCost();
        this._costTimer = setInterval(() => this.loadCost(), 5000);
        this.loadSessionDevice();
        this._deviceTimer = setInterval(() => this.loadSessionDevice(), 30000);

        document.addEventListener('keydown', (e) => this._globalKey(e));

        /* Scroll-pause detection: if user scrolls up > 40px from bottom, pause auto-scroll. */
        this.$nextTick(() => {
          var el = this.$refs.messages;
          if (el) {
            el.addEventListener('scroll', () => {
              var gap = el.scrollHeight - el.scrollTop - el.clientHeight;
              var paused = gap > 40;
              if (paused !== this._autoScrollPaused) {
                this._autoScrollPaused = paused;
                if (!paused) this.newMessagesPending = false;
              }
            }, { passive: true });
          }
        });

        window.addEventListener('beforeunload', () => {
          if (this._ws) { try { this._ws.close(); } catch (_) {} }
        });

        this.$nextTick(() => this.$refs.composer && this.$refs.composer.focus());
      },

      _globalKey(e) {
        /* Risk-gate shortcuts take precedence when an inline confirm is active
           AND focus is not inside the composer/textarea. */
        if (this.confirmRequest) {
          var tag = (document.activeElement && document.activeElement.tagName) || '';
          var inInput = tag === 'TEXTAREA' || tag === 'INPUT';
          if (!inInput) {
            var k = e.key.toLowerCase();
            if (k === 'y' || k === 'a')        { e.preventDefault(); this.respondConfirm('approve'); return; }
            if (k === 'l')                     { e.preventDefault(); this.respondConfirm('approve_all'); return; }
            if (k === 'n' || e.key === 'Enter'){ e.preventDefault(); this.respondConfirm('deny'); return; }
            if (e.key === 'Escape')            { e.preventDefault(); this.respondConfirm('deny'); return; }
          }
        }
        if (e.key === 'Escape' && this.session.phase !== 'Idle') {
          e.preventDefault();
          this.cancelTurn();
        }
      },

      _loadMotifs() {
        MOTIFS.forEach((name) => {
          fetch('icons/' + name + '.svg')
            .then((r) => (r.ok ? r.text() : ''))
            .then((svg) => { this.motifSvg[name] = svg; })
            .catch(() => { this.motifSvg[name] = ''; });
        });
      },

      toolMotifSvg(toolName) {
        return this.motifSvg[motifFor(toolName)] || '';
      },

      statusIcon(status) {
        if (status === 'ok')  return ICONS.check;
        if (status === 'err') return ICONS.x;
        return ICONS.spinner;
      },

      /* ---------- WebSocket ---------- */
      _connect() {
        var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        var url = proto + '//' + location.host + '/ws';
        try { this._ws = new WebSocket(url); }
        catch (_) { this._onWsDown(); return; }

        this._ws.onopen = () => {
          var wasDown = this.connection !== 'online';
          this.connection = 'online';
          this._wsBackoff = 800;
          this._lastPingAt = Date.now();
          this._clearDisconnectBanner();
          this.offlineCard = false;
          if (wasDown) this._showReconnectToast();
        };
        this._ws.onclose = () => this._onWsDown();
        this._ws.onerror = () => { /* handled via onclose */ };
        this._ws.onmessage = (ev) => {
          var msg;
          try { msg = JSON.parse(ev.data); } catch (_) { return; }
          this._dispatch(msg);
        };
      },

      _onWsDown() {
        if (this.connection === 'offline') return;  /* already handling */
        this.connection = 'offline';
        /* In-thread banner only during an active turn */
        if (this.session.phase !== 'Idle') this._startDisconnectCountdown();
        if (!this._disconnectStartedAt) this._disconnectStartedAt = Date.now();
        this._scheduleReconnect();
      },

      _scheduleReconnect() {
        /* 30s budget before persistent offline card replaces the banner */
        if (Date.now() - this._disconnectStartedAt > 30000) {
          this._clearDisconnectBanner();
          this.offlineCard = true;
          return;
        }
        var delay = Math.min(this._wsBackoff, 8000);
        this._wsBackoff = Math.min(Math.round(this._wsBackoff * 1.6), 8000);
        setTimeout(() => this._connect(), delay);
      },

      _showReconnectToast() {
        this.reconnectToast = true;
        setTimeout(() => { this.reconnectToast = false; }, 2000);
      },

      _startDisconnectCountdown() {
        /* Insert an in-thread banner inside the active agent message with a live countdown. */
        if (this.feed.some((f) => f.kind === 'disconnect')) return;
        var banner = {
          id: shortId('d-'), kind: 'disconnect',
          secondsLeft: 3, turn_id: this.currentTurnId,
        };
        this.feed.push(banner);
        if (this._disconnectTimer) clearInterval(this._disconnectTimer);
        this._disconnectTimer = setInterval(() => {
          var b = this.feed.find((f) => f.kind === 'disconnect');
          if (!b) { clearInterval(this._disconnectTimer); this._disconnectTimer = null; return; }
          b.secondsLeft = Math.max(0, b.secondsLeft - 1);
        }, 1000);
      },

      _clearDisconnectBanner() {
        this._disconnectStartedAt = 0;
        if (this._disconnectTimer) { clearInterval(this._disconnectTimer); this._disconnectTimer = null; }
        this.feed = this.feed.filter((f) => f.kind !== 'disconnect');
      },

      _clientReconnect() {
        /* Manual reconnect (from offline card or device-error banner). */
        this.offlineCard = false;
        this._disconnectStartedAt = 0;
        this._wsBackoff = 800;
        try { if (this._ws) this._ws.close(); } catch (_) {}
        this._connect();
      },

      _startHeartbeatWatchdog() {
        this._heartbeatWatchdog = setInterval(() => {
          if (this.connection !== 'online') return;
          var lag = Date.now() - (this._lastPingAt || Date.now());
          if (lag > 15000 && this.connection === 'online') this.connection = 'slow';
        }, 2000);
      },

      _send(obj) {
        if (!this._ws || this._ws.readyState !== WebSocket.OPEN) return false;
        try { this._ws.send(JSON.stringify(obj)); return true; } catch (_) { return false; }
      },

      /* ---------- reducer ---------- */
      _dispatch(msg) {
        switch (msg.type) {
          case 'status':
            if (msg.content === 'connected')          { this.connection = 'online'; if (msg.session_id) this.session.id = msg.session_id; }
            else if (msg.content === 'thinking')      { this._setPhase('Thinking', 'Thinking'); }
            else if (msg.content === 'transcribing')  { this._setPhase('Responding', 'Transcribing'); }
            else if (msg.content === 'conversation reset') { this._resetConversation('Conversation reset.'); }
            break;

          case 'transcription':
            this._addUser(msg.content, { voice: true });
            break;

          case 'response': {
            this._dropSkeletons();
            var existing = null;
            for (var i = this.feed.length - 1; i >= 0; i--) {
              var f = this.feed[i];
              if (f.kind !== 'agent') continue;
              if (msg.turn_id && f.turn_id !== msg.turn_id) continue;
              existing = f; break;
            }
            if (existing) {
              existing.streaming = false;
              if (!existing.text && msg.content) existing.text = msg.content;
            } else {
              this._addAgent(msg.content, msg.turn_id || null, { streaming: false });
            }
            this._setPhase('Idle', 'Idle');
            break;
          }

          case 'error': {
            this._dropSkeletons();
            var kind = classifyError(msg);
            this.errorBanner = {
              kind: kind,
              message: msg.content || 'error',
              canRetryTool: kind === 'tool' && !!this._lastToolCall,
            };
            this._setPhase('Idle', 'Idle');
            break;
          }

          case 'text_delta':
            this._dropSkeletons();
            this._appendDelta(msg.turn_id, msg.content || '');
            break;

          case 'tool_status':
            this._dropSkeletons();
            if (msg.phase === 'start') {
              this._lastToolCall = { name: msg.name, input: msg.input, turn_id: msg.turn_id };
              this._addTool({
                turn_id: msg.turn_id, name: msg.name,
                input: msg.input, risk: msg.risk || 'low',
                status: 'running', startedAt: Date.now(),
              });
            } else {
              this._finishTool(msg);
            }
            break;

          case 'confirm_request':
            this.confirmRequest = {
              confirm_id: msg.confirm_id,
              tool: msg.tool,
              input: msg.input,
              risk: msg.risk || 'medium',
            };
            this.criticalConfirmText = '';
            /* Focus Deny (safe default) when the card mounts. */
            this.$nextTick(() => {
              var btn = document.querySelector('[data-pz-confirm-deny]');
              if (btn) btn.focus();
            });
            break;

          case 'phase':
            this._onPhase(msg.verb, msg.turn_id);
            break;

          case 'ping':
            this._lastPingAt = Date.now();
            if (this.connection === 'slow') this.connection = 'online';
            this._send({ type: 'pong', t: msg.t });
            break;

          case 'persona_switched':
            this.personaUI.current = msg.name || '';
            if (msg.switch_id) {
              var idx = this._knownPersonaSwitchIds.indexOf(msg.switch_id);
              if (idx !== -1) {
                this._knownPersonaSwitchIds.splice(idx, 1);
                break;
              }
            }
            this._addAgent('● ' + (msg.content || ('persona switched to ' + msg.name)), null, { streaming: false, system: true });
            break;
        }
      },

      /* ---------- feed helpers ---------- */
      _addUser(text, extras) {
        this.feed.push(Object.assign({
          id: shortId('u-'), kind: 'user', text: text, turn_id: null,
        }, extras || {}));
        this._scrollSoon();
      },

      _addAgent(text, turnId, extras) {
        this.feed.forEach((f) => { if (f.kind === 'agent') f.streaming = false; });
        this.feed.push(Object.assign({
          id: shortId('a-'), kind: 'agent', text: text || '',
          streaming: !!(extras && extras.streaming),
          turn_id: turnId || null,
        }, extras || {}));
        this._scrollSoon();
      },

      _addTool(t) {
        this.feed.push(Object.assign({
          id: shortId('t-'), kind: 'tool',
          status: 'running', durationMs: 0, input: null, output: null, err: null, risk: 'low',
        }, t));
        this._scrollSoon();
      },

      _appendDelta(turnId, content) {
        var last = this.feed[this.feed.length - 1];
        if (last && last.kind === 'agent' && last.turn_id === turnId) {
          last.text = (last.text || '') + content;
          last.streaming = true;
        } else {
          this._addAgent(content, turnId, { streaming: true });
        }
      },

      _finishTool(msg) {
        for (var i = this.feed.length - 1; i >= 0; i--) {
          var t = this.feed[i];
          if (t.kind !== 'tool') continue;
          if (t.status !== 'running') continue;
          if (msg.name && t.name !== msg.name) continue;
          if (msg.turn_id && t.turn_id && t.turn_id !== msg.turn_id) continue;
          t.status = msg.err ? 'err' : 'ok';
          t.durationMs = msg.duration_ms != null ? msg.duration_ms : (Date.now() - (t.startedAt || Date.now()));
          t.output = msg.output;
          t.err = msg.err;
          /* Capture-success glitch: only on success, only for capture tools. */
          if (!msg.err && CAPTURE_TOOLS.test(String(t.name || '')) && !this._reduced) {
            t.glitch = true;
            setTimeout(() => { t.glitch = false; }, 320);
          }
          return;
        }
      },

      _addSkeleton(shape, turnId) {
        var skel = { id: shortId('s-'), kind: 'skeleton', shape: shape, turn_id: turnId };
        this.feed.push(skel);
        this._skeletonIds.push(skel.id);
        this._scrollSoon();
      },

      _dropSkeletons() {
        if (!this._skeletonIds.length) return;
        this.feed = this.feed.filter((f) => f.kind !== 'skeleton');
        this._skeletonIds = [];
      },

      _onPhase(verb, turnId) {
        if (turnId) this.currentTurnId = turnId;
        var v = String(verb || '').toLowerCase();
        var phase;
        if (v === 'idle' || v === 'done' || v === '')         phase = 'Idle';
        else if (v.indexOf('running') === 0)                  phase = 'Running';
        else if (v.indexOf('respond') === 0)                  phase = 'Responding';
        else                                                  phase = 'Thinking';
        var wasIdle = this.session.phase === 'Idle';
        this._setPhase(phase, verb || phase);
        /* Announce phase change (and only phase change) to screen readers. */
        this.liveRegionText = phase === 'Idle' ? 'Idle' : (verb || phase);
        /* When a new turn begins and no content has streamed yet, insert a skeleton. */
        if (wasIdle && phase !== 'Idle') {
          var shape = skeletonShape(this._lastUserPrompt);
          this._addSkeleton(shape, turnId || this.currentTurnId);
        }
        if (phase === 'Idle') {
          this._dropSkeletons();
          this.feed.forEach((f) => { if (f.kind === 'agent') f.streaming = false; });
          this._flushQueue();
        }
      },

      _setPhase(phase, verb) {
        var wasIdle = this.session.phase === 'Idle';
        this.session.phase = phase;
        this.session.verb = verb || phase;
        if (wasIdle && phase !== 'Idle') this.session.turnStartedAt = Date.now();
        if (phase === 'Idle')            this.session.turnStartedAt = null;
      },

      _resetConversation(note) {
        this.feed = [];
        this.queuedPrompts = [];
        this.confirmRequest = null;
        this.errorBanner = null;
        this._skeletonIds = [];
        this.currentTurnId = null;
        this._setPhase('Idle', 'Idle');
        if (note) this._addAgent(note, null, { streaming: false, system: true });
      },

      _flushQueue() {
        if (!this.queuedPrompts.length) return;
        var next = this.queuedPrompts.shift();
        if (next) this._submitText(next);
      },

      _scrollSoon() {
        this.$nextTick(() => {
          var el = this.$refs.messages;
          if (!el) return;
          if (this._autoScrollPaused) {
            this.newMessagesPending = true;
            return;
          }
          el.scrollTop = el.scrollHeight;
        });
      },

      scrollToLatest() {
        var el = this.$refs.messages;
        if (!el) return;
        this._autoScrollPaused = false;
        this.newMessagesPending = false;
        el.scrollTop = el.scrollHeight;
      },

      /* ---------- composer actions ---------- */
      onKeyDown(ev) {
        if (ev.key === 'Enter' && !ev.shiftKey && !ev.isComposing) {
          ev.preventDefault();
          this.onEnter();
        } else if (ev.key === 'Backspace' && this.input === '' && this.queuedPrompts.length > 0) {
          ev.preventDefault();
          this.queuedPrompts.pop();
        }
      },
      onEnter() {
        var text = this.input.trim();
        if (!text) return;
        if (this.session.phase !== 'Idle') {
          this.queuedPrompts.push(text);
          this.input = '';
          return;
        }
        this._submitText(text);
        this.input = '';
      },
      submit() {
        this.onEnter();
      },
      _submitText(text) {
        this._lastUserPrompt = text;
        this.errorBanner = null;
        this._addUser(text);
        this._send({ type: 'text', content: text });
        this._setPhase('Thinking', 'Thinking');
      },
      cancelTurn() {
        if (this.session.phase === 'Idle') return;
        this._send({ type: 'cancel', turn_id: this.currentTurnId });
        this.feed.forEach((f) => { if (f.kind === 'agent') f.streaming = false; });
        this._dropSkeletons();
        /* If there was a pending confirm, drop it when the user cancels the turn. */
        this.confirmRequest = null;
        this._setPhase('Idle', 'Idle');
      },
      reset() {
        this._send({ type: 'reset' });
        this._resetConversation('Conversation reset.');
      },
      respondConfirm(decision) {
        if (!this.confirmRequest) return;
        if (this.confirmRequest.risk === 'critical' && decision === 'approve' && !this.criticalReady) return;
        this._send({ type: 'confirm_response', confirm_id: this.confirmRequest.confirm_id, decision: decision });
        this.confirmRequest = null;
        this.criticalConfirmText = '';
        this.$nextTick(() => this.$refs.composer && this.$refs.composer.focus());
      },

      /* ---------- error recovery ---------- */
      dismissError() { this.errorBanner = null; },
      retryLastPrompt() {
        if (!this._lastUserPrompt) { this.errorBanner = null; return; }
        var text = this._lastUserPrompt;
        this.errorBanner = null;
        this._send({ type: 'text', content: text });
        this._setPhase('Thinking', 'Thinking');
      },
      retryLastTool() {
        var t = this._lastToolCall;
        if (!t) { this.errorBanner = null; return; }
        this.errorBanner = null;
        this._send({ type: 'retry_tool', name: t.name, input: t.input, turn_id: t.turn_id });
      },
      triggerReconnect() {
        this.errorBanner = null;
        this._clientReconnect();
      },
      copySession() {
        try {
          navigator.clipboard.writeText(this.session.id);
          this.copied = true;
          setTimeout(() => (this.copied = false), 1400);
        } catch (_) {}
      },

      /* ---------- spinners / elapsed ---------- */
      _startSpinner() {
        if (this._reduced) { this.spinnerFrame = BRAILLE[0]; return; }
        var i = 0;
        this._spinnerTimer = setInterval(() => {
          if (!this.showTicker) return;
          i = (i + 1) % BRAILLE.length;
          this.spinnerFrame = BRAILLE[i];
        }, 100);
      },
      _startElapsed() {
        this._elapsedTimer = setInterval(() => {
          if (this.session.turnStartedAt) {
            var s = (Date.now() - this.session.turnStartedAt) / 1000;
            this.elapsedLabel = s < 10 ? s.toFixed(1) + 's' : Math.round(s) + 's';
          } else {
            this.elapsedLabel = '0.0s';
          }
        }, 500);
      },

      /* ---------- tool card formatters ---------- */
      toolDurationLabel(item) {
        if (item.status === 'running' && item.startedAt) {
          return ((Date.now() - item.startedAt) / 1000).toFixed(1) + 's';
        }
        if (item.durationMs != null) {
          var s = item.durationMs / 1000;
          return s < 10 ? s.toFixed(2) + 's' : Math.round(s) + 's';
        }
        return '';
      },
      formatJSON(obj) {
        if (obj == null || obj === '') return '';
        if (typeof obj === 'string') {
          var t = obj.trim();
          if (t.length && (t[0] === '{' || t[0] === '[')) {
            try { return JSON.stringify(JSON.parse(t), null, 2); } catch (_) { /* fall through */ }
          }
          return obj;
        }
        try { return JSON.stringify(obj, null, 2); } catch (_) { return String(obj); }
      },

      /* ---------- persona switcher (REPL /persona parity) ---------- */
      loadPersonas() {
        fetch('api/personas')
          .then((r) => (r.ok ? r.json() : null))
          .then((data) => {
            if (!data) return;
            this.personaUI.current = data.current || '';
            this.personaUI.list = Array.isArray(data.available) ? data.available : [];
          })
          .catch(() => { /* panel stays empty; hide in UI */ });
      },
      togglePersonaMenu() {
        if (!this.personaUI.open) this.loadPersonas();
        this.personaUI.open = !this.personaUI.open;
      },
      switchPersona(name) {
        if (!name || name === this.personaUI.current) { this.personaUI.open = false; return; }
        fetch('api/personas/switch', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: name }),
        })
          .then((r) => (r.ok ? r.json() : Promise.reject(r)))
          .then((data) => {
            this.personaUI.current = data.current || name;
            if (data.switch_id) {
              this._knownPersonaSwitchIds.push(data.switch_id);
              if (this._knownPersonaSwitchIds.length > 8) this._knownPersonaSwitchIds.shift();
            }
            this.personaUI.open = false;
          })
          .catch(() => {
            this.errorBanner = { kind: 'api', message: 'persona switch failed' };
          });
      },

      /* ---------- sidebar tabs (Watch / Rules) ---------- */
      toggleSidebar() {
        this.sidebar.open = !this.sidebar.open;
        if (this.sidebar.open) this._refreshSidebarTab();
      },
      selectSidebarTab(tab) {
        this.sidebar.tab = tab;
        this._refreshSidebarTab();
      },
      _refreshSidebarTab() {
        if (this.sidebar.tab === 'watch') this.loadWatch();
        else if (this.sidebar.tab === 'rules') this.loadRules();
      },

      /* ---------- watch panel (REPL /watch parity) ---------- */
      loadWatch() {
        fetch('api/watch')
          .then((r) => r.json().then((body) => ({ ok: r.ok, body: body })))
          .then(({ ok, body }) => {
            this.watchUI.loaded = true;
            if (!ok) { this.watchUI.error = body.error || 'watch unavailable'; return; }
            this.watchUI.error = '';
            this.watchUI.enabled = !!body.enabled;
            this.watchUI.paused = !!body.paused;
            this.watchUI.paths = Array.isArray(body.paths) ? body.paths : [];
            this.watchUI.rules = Array.isArray(body.rules) ? body.rules : [];
            this.watchUI.events = Array.isArray(body.recent_events) ? body.recent_events : [];
          })
          .catch((e) => { this.watchUI.loaded = true; this.watchUI.error = String(e); });
      },
      watchPause()  { this._watchToggle('api/watch/pause',  true);  },
      watchResume() { this._watchToggle('api/watch/resume', false); },
      _watchToggle(url, paused) {
        fetch(url, { method: 'POST' })
          .then((r) => { if (r.ok) this.watchUI.paused = paused; })
          .catch(() => {});
      },

      /* ---------- rules panel (REPL /rules parity) ---------- */
      loadRules() {
        fetch('api/rules')
          .then((r) => r.json().then((body) => ({ ok: r.ok, body: body })))
          .then(({ ok, body }) => {
            this.rulesUI.loaded = true;
            if (!ok) { this.rulesUI.error = (body && body.error) || 'rules unavailable'; return; }
            this.rulesUI.error = '';
            this.rulesUI.list = Array.isArray(body) ? body : [];
          })
          .catch((e) => { this.rulesUI.loaded = true; this.rulesUI.error = String(e); });
      },
      toggleRule(r) {
        var target = r.enabled ? 'pause' : 'resume';
        fetch('api/rules/' + encodeURIComponent(r.name) + '/' + target, { method: 'POST' })
          .then((resp) => { if (resp.ok) r.enabled = !r.enabled; })
          .catch(() => {});
      },
      testRule(name) {
        fetch('api/rules/' + encodeURIComponent(name) + '/test', { method: 'POST' })
          .then((r) => r.json())
          .then((body) => {
            var text = Array.isArray(body.actions) ? body.actions.join('\n') : (body.error || 'no actions');
            this.rulesUI.testResults = Object.assign({}, this.rulesUI.testResults, { [name]: text });
          })
          .catch((e) => {
            this.rulesUI.testResults = Object.assign({}, this.rulesUI.testResults, { [name]: String(e) });
          });
      },

      /* ---------- debug snapshot (REPL /debug parity) ---------- */
      openDebug() {
        this.debugUI.open = true;
        this.loadDebug();
      },
      closeDebug() {
        this.debugUI.open = false;
        this.debugUI.copied = false;
      },
      loadDebug() {
        this.debugUI.loaded = false;
        this.debugUI.error = '';
        fetch('api/debug')
          .then((r) => r.json().then((body) => ({ ok: r.ok, body: body })))
          .then(({ ok, body }) => {
            this.debugUI.loaded = true;
            if (!ok) { this.debugUI.error = (body && body.error) || 'debug unavailable'; return; }
            this.debugUI.snapshot = body;
          })
          .catch((e) => { this.debugUI.loaded = true; this.debugUI.error = String(e); });
      },
      get debugText() {
        if (!this.debugUI.snapshot) return '';
        try { return JSON.stringify(this.debugUI.snapshot, null, 2); }
        catch (_) { return String(this.debugUI.snapshot); }
      },
      copyDebug() {
        var text = this.debugText;
        if (!text) return;
        var reset = () => { setTimeout(() => { this.debugUI.copied = false; }, 1500); };
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text)
            .then(() => { this.debugUI.copied = true; reset(); })
            .catch(() => { this._fallbackCopy(text); });
          return;
        }
        this._fallbackCopy(text);
      },
      _fallbackCopy(text) {
        try {
          var ta = document.createElement('textarea');
          ta.value = text;
          ta.setAttribute('readonly', '');
          ta.style.position = 'fixed';
          ta.style.opacity = '0';
          document.body.appendChild(ta);
          ta.select();
          document.execCommand('copy');
          document.body.removeChild(ta);
          this.debugUI.copied = true;
          setTimeout(() => { this.debugUI.copied = false; }, 1500);
        } catch (_) { /* noop */ }
      },

      /* ---------- device profile modal (full device_info surface) ---------- */
      openDevice() {
        this.deviceUI.open = true;
        if (this._deviceTimer) { clearInterval(this._deviceTimer); }
        this._deviceTimer = setInterval(() => this.loadSessionDevice(), 30000);
        this.loadDevice();
      },
      closeDevice() {
        this.deviceUI.open = false;
      },
      loadDevice() {
        this.deviceUI.loaded = false;
        this.deviceUI.error = '';
        fetch('api/device')
          .then((r) => r.json().then((body) => ({ ok: r.ok, body: body })))
          .then(({ ok, body }) => {
            this.deviceUI.loaded = true;
            if (!ok) { this.deviceUI.error = (body && body.error) || 'device info unavailable'; return; }
            /* Ensure every section is present as an object so x-text dereferences don't throw. */
            var sections = ['firmware', 'hardware', 'radio', 'battery', 'storage', 'system'];
            sections.forEach((k) => { if (!body[k] || typeof body[k] !== 'object') body[k] = {}; });
            this.deviceUI.snapshot = body;
            this._applyDeviceToSession(body);
            /* Title: "DEVICE · <name> · <fork>" */
            var name = (body.hardware && body.hardware.hardware_name) || 'flipper';
            var fork = (body.firmware && body.firmware.firmware_origin_fork) || 'stock';
            this.deviceUI.title = 'DEVICE · ' + name + ' · ' + fork;
          })
          .catch((e) => { this.deviceUI.loaded = true; this.deviceUI.error = String(e); });
      },
      /* Background refresh for the header chips + battery indicator. Shares
         the /api/device endpoint with the modal so a single round-trip
         drives both surfaces. Silent on failure — we'd rather show empty
         chips than a banner for every transient serial hiccup. */
      loadSessionDevice() {
        fetch('api/device')
          .then((r) => (r.ok ? r.json() : null))
          .then((body) => { if (body) this._applyDeviceToSession(body); })
          .catch(() => {});
      },
      _applyDeviceToSession(body) {
        if (!body) return;
        var hw = body.hardware || {};
        var fw = body.firmware || {};
        var bat = body.battery || {};
        if (hw.hardware_name) this.session.device.name = hw.hardware_name;
        if (fw.firmware_origin_fork) this.session.device.fork = fw.firmware_origin_fork.toUpperCase();
        if (fw.firmware_version) this.session.device.version = fw.firmware_version;
        var n = parseInt(bat.charge_level, 10);
        if (isFinite(n)) this.session.device.battery = Math.max(0, Math.min(100, n));
      },
      get deviceChargePct() {
        var b = this.deviceUI.snapshot && this.deviceUI.snapshot.battery;
        if (!b) return 0;
        var n = parseInt(b.charge_level, 10);
        return isFinite(n) ? Math.max(0, Math.min(100, n)) : 0;
      },
      get deviceStorageUsedPct() {
        var s = this.deviceUI.snapshot && this.deviceUI.snapshot.storage;
        if (!s) return 0;
        var total = Number(s.storage_sdcard_totalSpace || 0);
        var free  = Number(s.storage_sdcard_freeSpace  || 0);
        if (!total || total <= 0) return 0;
        var used = Math.max(0, total - free);
        return Math.min(100, Math.round((used / total) * 100));
      },
      get deviceRawText() {
        var raw = this.deviceUI.snapshot && this.deviceUI.snapshot.raw;
        if (!raw || typeof raw !== 'object') return '(empty)';
        var keys = Object.keys(raw).sort();
        if (keys.length === 0) return '(empty)';
        var lines = new Array(keys.length);
        for (var i = 0; i < keys.length; i++) {
          lines[i] = keys[i] + ': ' + raw[keys[i]];
        }
        return lines.join('\n');
      },
      get deviceStorageLabel() {
        var s = this.deviceUI.snapshot && this.deviceUI.snapshot.storage;
        if (!s) return '—';
        var total = Number(s.storage_sdcard_totalSpace || 0);
        var free  = Number(s.storage_sdcard_freeSpace  || 0);
        if (!total) return 'no SD card detected';
        var used = Math.max(0, total - free);
        return this._fmtBytes(used) + ' used · ' + this._fmtBytes(total) + ' total';
      },
      get deviceSdFreeLabel() {
        var s = this.deviceUI.snapshot && this.deviceUI.snapshot.storage;
        if (!s) return '—';
        var total = Number(s.storage_sdcard_totalSpace || 0);
        var free  = Number(s.storage_sdcard_freeSpace  || 0);
        if (!total) return '—';
        return this._fmtBytes(free) + ' / ' + this._fmtBytes(total);
      },
      get deviceIntFreeLabel() {
        var s = this.deviceUI.snapshot && this.deviceUI.snapshot.storage;
        if (!s) return '—';
        var total = Number(s.storage_internal_totalSpace || 0);
        var free  = Number(s.storage_internal_freeSpace  || 0);
        if (!total) return '—';
        return this._fmtBytes(free) + ' / ' + this._fmtBytes(total);
      },
      _val(v) { return (v != null && v !== '') ? v : '—'; },
      formatVoltage(mv) {
        var n = Number(mv);
        if (!isFinite(n) || n <= 0) return '—';
        return (n / 1000).toFixed(2) + ' V';
      },
      formatCurrent(ma) {
        if (ma === undefined || ma === null || ma === '') return '—';
        var n = Number(ma);
        if (!isFinite(n)) return '—';
        return n.toFixed(0) + ' mA';
      },
      _fmtBytes(n) {
        n = Number(n);
        if (!isFinite(n) || n <= 0) return '0 B';
        var units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
        var i = 0;
        while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
        return n.toFixed(n >= 100 ? 0 : n >= 10 ? 1 : 2) + ' ' + units[i];
      },

      /* ---------- validate modal (REPL /validate parity) ---------- */
      openValidateModal() {
        this.validateUI.open = true;
        this.validateUI.error = '';
        this.validateUI.report = null;
      },
      closeValidateModal() {
        this.validateUI.open = false;
      },
      runValidate() {
        var path = (this.validateUI.path || '').trim();
        var content = this.validateUI.content || '';
        if (!path && !content) {
          this.validateUI.error = 'enter a path or paste script content';
          return;
        }
        this.validateUI.loading = true;
        this.validateUI.error = '';
        this.validateUI.report = null;
        fetch('api/validate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ path: path, content: content }),
        })
          .then((r) => r.json().then((body) => ({ ok: r.ok, body: body })))
          .then(({ ok, body }) => {
            if (!ok) { this.validateUI.error = (body && body.error) || 'validate failed'; return; }
            this.validateUI.report = body;
          })
          .catch((e) => { this.validateUI.error = String(e); })
          .finally(() => { this.validateUI.loading = false; });
      },

      /* ---------- cost pill (REPL /cost parity) ---------- */
      loadCost() {
        fetch('api/cost')
          .then((r) => r.json().then((body) => ({ ok: r.ok, body: body })))
          .then(({ ok, body }) => {
            this.costUI.loaded = true;
            if (!ok) {
              this.costUI.error = (body && body.error) || 'cost tracker unavailable';
              return;
            }
            this.costUI.error = '';
            var total = (body && body.total) || {};
            this.costUI.usd          = Number(total.usd || 0);
            this.costUI.inputTokens  = Number(total.input_tokens || 0);
            this.costUI.outputTokens = Number(total.output_tokens || 0);
            this.costUI.offline      = !!body.offline;
            this.costUI.byModel      = Array.isArray(body.by_model) ? body.by_model : [];
          })
          .catch((e) => { this.costUI.loaded = true; this.costUI.error = String(e); });
      },
      toggleCostModal() {
        if (!this.costUI.modalOpen) this.loadCost();
        this.costUI.modalOpen = !this.costUI.modalOpen;
      },
      formatTokens(n) {
        var v = Number(n || 0);
        if (v >= 1e6) return (v / 1e6).toFixed(v >= 1e7 ? 0 : 1) + 'M';
        if (v >= 1e3) return (v / 1e3).toFixed(v >= 1e4 ? 0 : 1) + 'k';
        return String(v);
      },
      formatUSD(n) {
        var v = Number(n || 0);
        if (v >= 100) return '$' + v.toFixed(0);
        if (v >= 1)   return '$' + v.toFixed(2);
        return '$' + v.toFixed(v < 0.01 ? 4 : 2);
      },
      get costPillText() {
        var tokens = this.costUI.inputTokens + this.costUI.outputTokens;
        return this.formatUSD(this.costUI.usd) + ' · ' + this.formatTokens(tokens) + ' tok';
      },
      get costPillVisible() {
        return this.costUI.loaded && !this.costUI.error;
      },

      /* ---------- shared formatters ---------- */
      shortTime(iso) {
        if (!iso) return '';
        try {
          var d = new Date(iso);
          return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
        } catch (_) { return String(iso); }
      },

      /* ---------- dev mock console (localhost only) ---------- */
      _installMock() {
        var host = location.hostname;
        var isLocal = host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '';
        if (!isLocal) return;
        var self = this;
        window.pzMock = {
          fire: function (type, payload) {
            self._dispatch(Object.assign({ type: type }, payload || {}));
          },
          queue: function (arr) { arr.forEach((m, i) => setTimeout(() => self._dispatch(m), i * 80)); },
          demo: function () {
            var t = 'turn-' + Math.random().toString(36).slice(2, 6);
            self._lastUserPrompt = 'scan 433 mhz';
            self._dispatch({ type: 'phase', verb: 'Thinking', turn_id: t });
            setTimeout(() => self._dispatch({ type: 'text_delta', turn_id: t, content: 'Sweeping 433.92 MHz for a capture. ' }), 200);
            setTimeout(() => self._dispatch({ type: 'tool_status', phase: 'start', name: 'subghz_receive', turn_id: t, input: { freq: 433920000, modulation: 'OOK' }, risk: 'medium' }), 500);
            setTimeout(() => self._dispatch({ type: 'phase', verb: 'Running subghz_receive', turn_id: t }), 550);
            setTimeout(() => self._dispatch({ type: 'tool_status', phase: 'finish', name: 'subghz_receive', turn_id: t, duration_ms: 842, output: 'OOK capture: 0xDEADBEEF (18 edges)' }), 1400);
            setTimeout(() => self._dispatch({ type: 'phase', verb: 'Responding', turn_id: t }), 1450);
            setTimeout(() => self._dispatch({ type: 'text_delta', turn_id: t, content: 'Got a clean capture — waveform saved.' }), 1500);
            setTimeout(() => self._dispatch({ type: 'phase', verb: 'Idle', turn_id: t }), 1900);
          },
          confirm: function (risk) {
            self._dispatch({ type: 'confirm_request', confirm_id: 'c-' + Math.random().toString(36).slice(2, 6),
              tool: 'subghz_transmit', input: { freq: 433920000, payload: '0xDEADBEEF' }, risk: risk || 'high' });
          },
          err: function (kind) {
            var map = {
              api: 'Anthropic API call failed: 529 overloaded',
              tool: 'Tool error: subghz_transmit failed (device busy)',
              device: 'Flipper disconnected from serial port',
              cancelled: 'Turn cancelled by user',
            };
            self._dispatch({ type: 'error', kind: kind || 'api', content: map[kind || 'api'] });
          },
          disconnect: function () {
            self._onWsDown();
          },
        };
        try {
          console.info('%c[pzMock]', 'color:#FF8200', 'dev console ready — pzMock.demo() for a scripted turn, pzMock.fire(type, payload) for raw events');
        } catch (_) {}
      },
    };
  }

  window.pzApp = pzApp;
})();
