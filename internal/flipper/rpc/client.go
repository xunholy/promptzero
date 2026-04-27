package rpc

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/xunholy/promptzero/internal/flipper/rpc/pb"
	"github.com/xunholy/promptzero/internal/flipper/transport"
)

// Client is a typed RPC client over a Flipper transport. The transport must
// already be dialled; Client takes exclusive ownership of it for the session.
//
// Call sequence: NewClient → Open → (Ping / StartScreenStream) → Close.
// A Client is not safe for concurrent use across Open/Close; Ping and
// StartScreenStream may not be called concurrently with each other.
type Client struct {
	tx     transport.Transport
	open   atomic.Bool
	mu     sync.Mutex
	nextID atomic.Uint32
}

// NewClient wraps tx. The transport must be dialled. On USB CDC the
// transport is in text-CLI mode at construction time and Open transitions
// it to RPC; on BLE the firmware is permanently in RPC mode and Open
// must be called with WithSkipStartRPCSession so the text-CLI preamble
// is not sent (those bytes would be misinterpreted by the BLE-side
// protobuf decoder).
func NewClient(tx transport.Transport) *Client {
	return &Client{tx: tx}
}

// OpenOption configures one Open call. Currently the only knob is
// whether to send the text-CLI "start_rpc_session\r" preamble — needed
// on USB CDC, harmful on BLE where the transport is RPC-only from the
// firmware's perspective.
type OpenOption func(*openConfig)

type openConfig struct {
	skipStartRPCSession bool
}

// WithSkipStartRPCSession suppresses the "start_rpc_session\r" text
// preamble Open normally writes. Use this on transports where the
// firmware is already in RPC mode at the time the transport opens —
// notably BLE Serial, where applications/services/bt/bt_service/bt.c
// pipes inbound bytes straight into rpc_session_feed (no text CLI
// path exists on BLE). Sending the preamble on those transports
// poisons the protobuf decoder with leading garbage bytes; the Ping
// handshake that follows will time out.
func WithSkipStartRPCSession() OpenOption {
	return func(c *openConfig) { c.skipStartRPCSession = true }
}

// Open transitions the Flipper from CLI mode to RPC mode by writing
// "start_rpc_session\r" to the transport. After this call, the byte
// stream is framed protobuf and the transport must not be used for CLI.
//
// The firmware echoes the command back as CLI bytes before switching to
// RPC mode. The amount of echo varies between firmware versions and
// transient device state (a freshly opened CLI vs one that just emitted
// a notification). Open handles this by:
//  1. Draining for an initial silence window (~250 ms).
//  2. Sending a Ping and trying to read its response; if the read fails to
//     parse, drain again and retry. Each Ping carries a fresh command_id
//     so a stale RPC response from earlier (rare) can be discarded.
//
// Up to 5 attempts; total handshake budget ~3 s. Returns a wrapped error
// describing the last failure if every attempt fails.
//
// Pass WithSkipStartRPCSession to skip the text preamble + initial drain;
// the Ping retry loop runs unchanged.
func (c *Client) Open(ctx context.Context, opts ...OpenOption) error {
	cfg := openConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}
	if c.open.Swap(true) {
		return ErrAlreadyOpen
	}
	if !cfg.skipStartRPCSession {
		if _, err := c.tx.Write([]byte("start_rpc_session\r")); err != nil {
			c.open.Store(false)
			return fmt.Errorf("rpc: open: %w", err)
		}
		c.drainCLIEcho(250 * time.Millisecond)
	} else {
		// Skip-handshake path doesn't go through drainCLIEcho, which is
		// where the transport read timeout normally gets set to 500 ms.
		// Without this, the Ping retry loop's per-attempt context
		// timeout can't fire — readFramed blocks in transport.Read with
		// no deadline and ctx.Err() is checked only between calls.
		_ = c.tx.SetReadTimeout(500 * time.Millisecond)
	}

	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		pingCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		err := c.Ping(pingCtx)
		cancel()
		if err == nil {
			return nil
		}
		lastErr = err
		// CLI bytes still in the buffer poisoned the read — drain and retry.
		// Harmless when WithSkipStartRPCSession was set: the drain just
		// consumes any spurious bytes the firmware may have emitted.
		c.drainCLIEcho(150 * time.Millisecond)
	}
	c.open.Store(false)
	return fmt.Errorf("rpc: handshake ping failed after retries: %w", lastErr)
}

// drainCLIEcho consumes bytes for the supplied window. Uses a short
// transport read deadline so we exit promptly when the wire goes silent.
func (c *Client) drainCLIEcho(window time.Duration) {
	_ = c.tx.SetReadTimeout(50 * time.Millisecond)
	defer func() { _ = c.tx.SetReadTimeout(500 * time.Millisecond) }()

	deadline := time.Now().Add(window)
	buf := make([]byte, 256)
	for time.Now().Before(deadline) {
		n, err := c.tx.Read(buf)
		if err != nil {
			return
		}
		if n == 0 {
			// Brief silence — give the firmware a moment more in case more
			// echo is on the way, then check again. If still silent we exit
			// on the next iteration when the read deadline elapses.
			time.Sleep(20 * time.Millisecond)
		}
	}
}

// Close ends the RPC session by sending a StopSession message followed by
// a Ctrl+C byte so the firmware returns to CLI mode.
func (c *Client) Close() error {
	if !c.open.Swap(false) {
		return nil // already closed
	}
	id := c.commandID()
	_ = writeFramed(c.tx, &pb.Main{
		CommandId: id,
		Content:   &pb.Main_StopSession{StopSession: &pb.StopSession{}},
	})
	// Ctrl+C breaks out of RPC mode on the firmware side if StopSession
	// was not acknowledged in time.
	_, _ = c.tx.Write([]byte("\x03"))
	return nil
}

// Ping sends a PingRequest and waits for the matching PingResponse.
func (c *Client) Ping(ctx context.Context) error {
	if !c.open.Load() {
		return ErrSessionClosed
	}
	id := c.commandID()
	req := &pb.Main{
		CommandId: id,
		Content: &pb.Main_SystemPingRequest{
			SystemPingRequest: &pb.PingRequest{},
		},
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := writeFramed(c.tx, req); err != nil {
		return err
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		m, err := readFramed(c.tx)
		if err != nil {
			return err
		}
		if m.CommandId == id {
			if _, ok := m.Content.(*pb.Main_SystemPingResponse); ok {
				return nil
			}
			return fmt.Errorf("rpc: ping: unexpected response type %T", m.Content)
		}
	}
}

// DeviceInfo issues a DeviceInfoRequest and accumulates the streamed
// (key, value) pairs that come back. The firmware emits one
// DeviceInfoResponse per attribute (firmware_version, hardware_model,
// battery_level, …) with has_next=true on every one except the last.
// The result preserves the firmware's emission order, which matches
// the textual `device info` CLI output downstream parsers expect.
func (c *Client) DeviceInfo(ctx context.Context) ([]struct{ Key, Value string }, error) {
	if !c.open.Load() {
		return nil, ErrSessionClosed
	}
	id := c.commandID()
	req := &pb.Main{
		CommandId: id,
		Content: &pb.Main_SystemDeviceInfoRequest{
			SystemDeviceInfoRequest: &pb.DeviceInfoRequest{},
		},
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := writeFramed(c.tx, req); err != nil {
		return nil, err
	}

	out := make([]struct{ Key, Value string }, 0, 32)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		m, err := readFramed(c.tx)
		if err != nil {
			return nil, err
		}
		if m.CommandId != id {
			// Stale response from a previous command_id (rare with the
			// per-Open ID counter; defensive only).
			continue
		}
		resp, ok := m.Content.(*pb.Main_SystemDeviceInfoResponse)
		if !ok {
			return nil, fmt.Errorf("rpc: device info: unexpected response type %T", m.Content)
		}
		out = append(out, struct{ Key, Value string }{
			Key:   resp.SystemDeviceInfoResponse.GetKey(),
			Value: resp.SystemDeviceInfoResponse.GetValue(),
		})
		if !m.HasNext {
			return out, nil
		}
	}
}

// PowerInfo mirrors DeviceInfo for the power_info RPC verb. The
// firmware streams one PowerInfoResponse per attribute (charge level,
// usb_voltage, charging state, etc.) terminated by has_next=false.
func (c *Client) PowerInfo(ctx context.Context) ([]struct{ Key, Value string }, error) {
	if !c.open.Load() {
		return nil, ErrSessionClosed
	}
	id := c.commandID()
	req := &pb.Main{
		CommandId: id,
		Content: &pb.Main_SystemPowerInfoRequest{
			SystemPowerInfoRequest: &pb.PowerInfoRequest{},
		},
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := writeFramed(c.tx, req); err != nil {
		return nil, err
	}

	out := make([]struct{ Key, Value string }, 0, 16)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		m, err := readFramed(c.tx)
		if err != nil {
			return nil, err
		}
		if m.CommandId != id {
			continue
		}
		resp, ok := m.Content.(*pb.Main_SystemPowerInfoResponse)
		if !ok {
			return nil, fmt.Errorf("rpc: power info: unexpected response type %T", m.Content)
		}
		out = append(out, struct{ Key, Value string }{
			Key:   resp.SystemPowerInfoResponse.GetKey(),
			Value: resp.SystemPowerInfoResponse.GetValue(),
		})
		if !m.HasNext {
			return out, nil
		}
	}
}

// --- Application / Loader ---

// AppStart issues an AppStartRequest (proto: app_start_request) — the
// RPC equivalent of the `loader open <name> [args]` CLI verb. The firmware
// replies with the generic Empty oneof carrying a CommandStatus; OK
// indicates the app launched, ERROR_APP_CANT_START / ERROR_APP_SYSTEM_LOCKED
// surface as a non-nil error reflecting the status enum.
//
// Note on args: the proto defines a single args string. Multi-token CLI
// argument lists must be joined by the caller (with spaces) before
// invocation — the firmware feeds the string verbatim into the app's
// argument hook with no further splitting.
func (c *Client) AppStart(ctx context.Context, name, args string) error {
	if !c.open.Load() {
		return ErrSessionClosed
	}
	id := c.commandID()
	req := &pb.Main{
		CommandId: id,
		Content: &pb.Main_AppStartRequest{
			AppStartRequest: &pb.StartRequest{Name: name, Args: args},
		},
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := writeFramed(c.tx, req); err != nil {
		return err
	}
	return c.awaitAck(ctx, id, "app_start")
}

// AppExit issues an AppExitRequest (proto: app_exit_request) — the RPC
// equivalent of the `loader close` CLI verb. Returns when the firmware
// acknowledges; non-OK status (typically ERROR_APP_NOT_RUNNING when no
// app is open, or ERROR_APP_CMD_ERROR when the app refuses the exit
// request) surfaces as a non-nil error so callers can distinguish a
// clean close from a refusal.
func (c *Client) AppExit(ctx context.Context) error {
	if !c.open.Load() {
		return ErrSessionClosed
	}
	id := c.commandID()
	req := &pb.Main{
		CommandId: id,
		Content: &pb.Main_AppExitRequest{
			AppExitRequest: &pb.AppExitRequest{},
		},
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := writeFramed(c.tx, req); err != nil {
		return err
	}
	return c.awaitAck(ctx, id, "app_exit")
}

// --- Storage ---

// storageWriteChunkSize is the maximum number of file bytes packed into one
// Main message during StorageWrite. The Flipper firmware accepts roughly
// 1 KiB per Main on USB, but BLE Serial caps inbound frames much tighter
// (the BLE characteristic max payload is 244 bytes on Flipper-side after
// L2CAP overhead). Keeping every Main under ~480 bytes of file payload
// leaves headroom for the WriteRequest envelope (path, command_id, varint
// prefix) and stays comfortably below the BLE MTU when the transport is
// BLE Serial. Picked once here so USB and BLE share one chunking policy.
const storageWriteChunkSize = 480

// StorageList issues a StorageListRequest for path. The firmware streams
// one StorageListResponse per chunk of directory entries — each response
// carries a slice of File entries — terminated by has_next=false. The
// returned slice preserves the firmware's emission order, which matches
// the textual `storage list` CLI output downstream parsers expect.
//
// includeMd5 is forwarded as ListRequest.include_md5; pass false for the
// CLI-equivalent listing (the CLI never asks for md5 on a `storage list`)
// and true if the caller wants per-entry md5sum populated for free.
func (c *Client) StorageList(ctx context.Context, path string, includeMd5 bool) ([]*pb.File, error) {
	if !c.open.Load() {
		return nil, ErrSessionClosed
	}
	id := c.commandID()
	req := &pb.Main{
		CommandId: id,
		Content: &pb.Main_StorageListRequest{
			StorageListRequest: &pb.ListRequest{Path: path, IncludeMd5: includeMd5},
		},
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := writeFramed(c.tx, req); err != nil {
		return nil, err
	}

	out := make([]*pb.File, 0, 32)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		m, err := readFramed(c.tx)
		if err != nil {
			return nil, err
		}
		if m.CommandId != id {
			continue
		}
		if err := storageStatusErr(m.CommandStatus, "storage list"); err != nil {
			return nil, err
		}
		resp, ok := m.Content.(*pb.Main_StorageListResponse)
		if ok {
			out = append(out, resp.StorageListResponse.GetFile()...)
		}
		// Empty/last frame may carry no list payload (oneof Empty); only
		// has_next gates the loop.
		if !m.HasNext {
			return out, nil
		}
	}
}

// StorageRead issues a StorageReadRequest for path. The firmware may
// stream large files across multiple StorageReadResponse messages with
// has_next=true on every one except the final; the file bytes from each
// chunk are appended in order. Returns the assembled byte slice.
func (c *Client) StorageRead(ctx context.Context, path string) ([]byte, error) {
	if !c.open.Load() {
		return nil, ErrSessionClosed
	}
	id := c.commandID()
	req := &pb.Main{
		CommandId: id,
		Content: &pb.Main_StorageReadRequest{
			StorageReadRequest: &pb.ReadRequest{Path: path},
		},
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := writeFramed(c.tx, req); err != nil {
		return nil, err
	}

	var out []byte
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		m, err := readFramed(c.tx)
		if err != nil {
			return nil, err
		}
		if m.CommandId != id {
			continue
		}
		if err := storageStatusErr(m.CommandStatus, "storage read"); err != nil {
			return nil, err
		}
		if resp, ok := m.Content.(*pb.Main_StorageReadResponse); ok {
			if file := resp.StorageReadResponse.GetFile(); file != nil {
				out = append(out, file.GetData()...)
			}
		}
		if !m.HasNext {
			return out, nil
		}
	}
}

// StorageWrite issues one or more StorageWriteRequest messages to write
// data to path on the Flipper SD card. The firmware truncates the target
// on the first chunk and appends subsequent chunks, so a single logical
// write may span multiple Main messages — each carries the same path and
// has_next=true on every Main except the last one. Empty payloads still
// send one terminating Main (has_next=false) so the firmware closes the
// file.
//
// Reads exactly one acknowledgement Main from the firmware after the
// final has_next=false frame; CommandStatus on that Main reports success
// or storage error class.
func (c *Client) StorageWrite(ctx context.Context, path string, data []byte) error {
	if !c.open.Load() {
		return ErrSessionClosed
	}
	id := c.commandID()
	c.mu.Lock()
	defer c.mu.Unlock()

	// Slice data into chunks of ≤ storageWriteChunkSize bytes; emit at
	// least one Main even when data is empty so the firmware has a frame
	// to terminate on.
	total := len(data)
	for offset := 0; ; {
		end := offset + storageWriteChunkSize
		if end > total {
			end = total
		}
		hasNext := end < total
		chunk := data[offset:end]
		req := &pb.Main{
			CommandId: id,
			HasNext:   hasNext,
			Content: &pb.Main_StorageWriteRequest{
				StorageWriteRequest: &pb.WriteRequest{
					Path: path,
					File: &pb.File{Data: chunk},
				},
			},
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := writeFramed(c.tx, req); err != nil {
			return err
		}
		if !hasNext {
			break
		}
		offset = end
	}

	// Read the terminating ack. The firmware replies with a single Main
	// (Empty content) carrying CommandStatus and has_next=false.
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		m, err := readFramed(c.tx)
		if err != nil {
			return err
		}
		if m.CommandId != id {
			continue
		}
		if err := storageStatusErr(m.CommandStatus, "storage write"); err != nil {
			return err
		}
		if !m.HasNext {
			return nil
		}
	}
}

// StorageDelete issues a StorageDeleteRequest for path. recursive=true
// allows non-empty directories to be deleted (mirrors the firmware's
// Recursive flag — equivalent to the `storage remove` CLI's `-r`).
// Returns nil on CommandStatus_OK; wraps any storage error class.
func (c *Client) StorageDelete(ctx context.Context, path string, recursive bool) error {
	if !c.open.Load() {
		return ErrSessionClosed
	}
	id := c.commandID()
	req := &pb.Main{
		CommandId: id,
		Content: &pb.Main_StorageDeleteRequest{
			StorageDeleteRequest: &pb.DeleteRequest{Path: path, Recursive: recursive},
		},
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := writeFramed(c.tx, req); err != nil {
		return err
	}
	return c.awaitAck(ctx, id, "storage delete")
}

// StorageMkdir issues a StorageMkdirRequest for path. Returns nil on
// CommandStatus_OK; wraps any storage error class.
func (c *Client) StorageMkdir(ctx context.Context, path string) error {
	if !c.open.Load() {
		return ErrSessionClosed
	}
	id := c.commandID()
	req := &pb.Main{
		CommandId: id,
		Content: &pb.Main_StorageMkdirRequest{
			StorageMkdirRequest: &pb.MkdirRequest{Path: path},
		},
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := writeFramed(c.tx, req); err != nil {
		return err
	}
	return c.awaitAck(ctx, id, "storage mkdir")
}

// StorageStat issues a StorageStatRequest for path and returns the
// resulting *File (Type, Name, Size, Md5Sum). On non-OK CommandStatus
// the firmware-side error code is wrapped into the returned error so the
// caller can distinguish ERROR_STORAGE_NOT_EXIST from other failures.
func (c *Client) StorageStat(ctx context.Context, path string) (*pb.File, error) {
	if !c.open.Load() {
		return nil, ErrSessionClosed
	}
	id := c.commandID()
	req := &pb.Main{
		CommandId: id,
		Content: &pb.Main_StorageStatRequest{
			StorageStatRequest: &pb.StatRequest{Path: path},
		},
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := writeFramed(c.tx, req); err != nil {
		return nil, err
	}

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		m, err := readFramed(c.tx)
		if err != nil {
			return nil, err
		}
		if m.CommandId != id {
			continue
		}
		if err := storageStatusErr(m.CommandStatus, "storage stat"); err != nil {
			return nil, err
		}
		resp, ok := m.Content.(*pb.Main_StorageStatResponse)
		if !ok {
			return nil, fmt.Errorf("rpc: storage stat: unexpected response type %T", m.Content)
		}
		return resp.StorageStatResponse.GetFile(), nil
	}
}

// StorageInfo issues a StorageInfoRequest for path and returns the
// (totalSpace, freeSpace) byte counts the firmware reports. The CLI
// `storage info` block is reconstructed from these fields by the
// caller-side helpers in commands.go.
func (c *Client) StorageInfo(ctx context.Context, path string) (totalSpace, freeSpace uint64, err error) {
	if !c.open.Load() {
		return 0, 0, ErrSessionClosed
	}
	id := c.commandID()
	req := &pb.Main{
		CommandId: id,
		Content: &pb.Main_StorageInfoRequest{
			StorageInfoRequest: &pb.InfoRequest{Path: path},
		},
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := writeFramed(c.tx, req); err != nil {
		return 0, 0, err
	}

	for {
		if cerr := ctx.Err(); cerr != nil {
			return 0, 0, cerr
		}
		m, rerr := readFramed(c.tx)
		if rerr != nil {
			return 0, 0, rerr
		}
		if m.CommandId != id {
			continue
		}
		if serr := storageStatusErr(m.CommandStatus, "storage info"); serr != nil {
			return 0, 0, serr
		}
		resp, ok := m.Content.(*pb.Main_StorageInfoResponse)
		if !ok {
			return 0, 0, fmt.Errorf("rpc: storage info: unexpected response type %T", m.Content)
		}
		return resp.StorageInfoResponse.GetTotalSpace(), resp.StorageInfoResponse.GetFreeSpace(), nil
	}
}

// StorageRename issues a StorageRenameRequest moving oldPath → newPath.
// Returns nil on CommandStatus_OK; wraps any storage error class. Works
// across files and directories on the same filesystem.
func (c *Client) StorageRename(ctx context.Context, oldPath, newPath string) error {
	if !c.open.Load() {
		return ErrSessionClosed
	}
	id := c.commandID()
	req := &pb.Main{
		CommandId: id,
		Content: &pb.Main_StorageRenameRequest{
			StorageRenameRequest: &pb.RenameRequest{OldPath: oldPath, NewPath: newPath},
		},
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := writeFramed(c.tx, req); err != nil {
		return err
	}
	return c.awaitAck(ctx, id, "storage rename")
}

// StorageMD5 issues a StorageMd5SumRequest for path and returns the
// 32-character lowercase-hex digest the firmware computes. Wraps any
// non-OK CommandStatus into a typed error so callers can detect a
// missing file (ERROR_STORAGE_NOT_EXIST) without sniffing strings.
func (c *Client) StorageMD5(ctx context.Context, path string) (string, error) {
	if !c.open.Load() {
		return "", ErrSessionClosed
	}
	id := c.commandID()
	req := &pb.Main{
		CommandId: id,
		Content: &pb.Main_StorageMd5SumRequest{
			StorageMd5SumRequest: &pb.Md5SumRequest{Path: path},
		},
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := writeFramed(c.tx, req); err != nil {
		return "", err
	}

	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		m, err := readFramed(c.tx)
		if err != nil {
			return "", err
		}
		if m.CommandId != id {
			continue
		}
		if err := storageStatusErr(m.CommandStatus, "storage md5"); err != nil {
			return "", err
		}
		resp, ok := m.Content.(*pb.Main_StorageMd5SumResponse)
		if !ok {
			return "", fmt.Errorf("rpc: storage md5: unexpected response type %T", m.Content)
		}
		return resp.StorageMd5SumResponse.GetMd5Sum(), nil
	}
}

// awaitAck reads framed messages until one matches commandID, then
// returns nil for CommandStatus_OK or a wrapped error for any storage
// error class. Used by RPC verbs that respond with a single Empty Main
// (mkdir, delete, rename, write).
func (c *Client) awaitAck(ctx context.Context, commandID uint32, opName string) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		m, err := readFramed(c.tx)
		if err != nil {
			return err
		}
		if m.CommandId != commandID {
			continue
		}
		if err := storageStatusErr(m.CommandStatus, opName); err != nil {
			return err
		}
		if !m.HasNext {
			return nil
		}
	}
}

// storageStatusErr maps a non-OK CommandStatus into a Go error annotated
// with the RPC verb name. CommandStatus_OK returns nil. The status enum's
// String() form is used so callers logging the error get the firmware's
// canonical name (e.g. "ERROR_STORAGE_NOT_EXIST").
func storageStatusErr(s pb.CommandStatus, op string) error {
	if s == pb.CommandStatus_OK {
		return nil
	}
	return fmt.Errorf("rpc %s: %s", op, s.String())
}

// Reboot sends a SystemRebootRequest with the supplied mode. The
// firmware reboots immediately on receipt and does NOT emit a response
// Main — the connection is torn down on every transport (USB CDC: the
// device re-enumerates; BLE: the GATT link drops). Reboot therefore
// returns as soon as the bytes are written; any subsequent read on the
// transport will fail with EOF or a transport-disconnect error, which
// is the expected steady state.
//
// Mode is one of pb.RebootRequest_OS, _DFU, or _UPDATE.
func (c *Client) Reboot(ctx context.Context, mode pb.RebootRequest_RebootMode) error {
	if !c.open.Load() {
		return ErrSessionClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	id := c.commandID()
	req := &pb.Main{
		CommandId: id,
		Content: &pb.Main_SystemRebootRequest{
			SystemRebootRequest: &pb.RebootRequest{Mode: mode},
		},
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return writeFramed(c.tx, req)
}

// GPIOSetPinMode issues a gpio_set_pin_mode request and waits for the
// Empty acknowledgement. Used to switch a pin to INPUT (read mode) or
// OUTPUT (write mode). Non-OK CommandStatus values
// (ERROR_GPIO_MODE_INCORRECT, ERROR_GPIO_UNKNOWN_PIN_MODE, …) are
// surfaced as errors annotated with the verb name.
func (c *Client) GPIOSetPinMode(ctx context.Context, pin pb.GpioPin, mode pb.GpioPinMode) error {
	if !c.open.Load() {
		return ErrSessionClosed
	}
	id := c.commandID()
	req := &pb.Main{
		CommandId: id,
		Content: &pb.Main_GpioSetPinMode{
			GpioSetPinMode: &pb.SetPinMode{Pin: pin, Mode: mode},
		},
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := writeFramed(c.tx, req); err != nil {
		return err
	}
	return c.awaitAck(ctx, id, "gpio set_pin_mode")
}

// GPIOWritePin issues a gpio_write_pin request and waits for the Empty
// acknowledgement. value is treated as a boolean by the firmware
// (0 = LOW, anything else = HIGH); we forward it unchanged so callers
// retain visibility. Non-OK CommandStatus is surfaced as an error.
func (c *Client) GPIOWritePin(ctx context.Context, pin pb.GpioPin, value uint32) error {
	if !c.open.Load() {
		return ErrSessionClosed
	}
	id := c.commandID()
	req := &pb.Main{
		CommandId: id,
		Content: &pb.Main_GpioWritePin{
			GpioWritePin: &pb.WritePin{Pin: pin, Value: value},
		},
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := writeFramed(c.tx, req); err != nil {
		return err
	}
	return c.awaitAck(ctx, id, "gpio write_pin")
}

// GPIOReadPin issues a gpio_read_pin request and returns the digital
// value the firmware reports on the pin (0 / 1). Non-OK CommandStatus
// is surfaced as an error.
func (c *Client) GPIOReadPin(ctx context.Context, pin pb.GpioPin) (uint32, error) {
	if !c.open.Load() {
		return 0, ErrSessionClosed
	}
	id := c.commandID()
	req := &pb.Main{
		CommandId: id,
		Content: &pb.Main_GpioReadPin{
			GpioReadPin: &pb.ReadPin{Pin: pin},
		},
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := writeFramed(c.tx, req); err != nil {
		return 0, err
	}

	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		m, err := readFramed(c.tx)
		if err != nil {
			return 0, err
		}
		if m.CommandId != id {
			continue
		}
		if err := storageStatusErr(m.CommandStatus, "gpio read_pin"); err != nil {
			return 0, err
		}
		resp, ok := m.Content.(*pb.Main_GpioReadPinResponse)
		if !ok {
			return 0, fmt.Errorf("rpc gpio read_pin: unexpected response type %T", m.Content)
		}
		return resp.GpioReadPinResponse.GetValue(), nil
	}
}

// DesktopIsLocked issues a desktop_is_locked_request. The firmware
// answers with an Empty message and uses CommandStatus to communicate
// state: OK means the desktop is locked, ERROR means it is unlocked.
// Any other CommandStatus is surfaced as an error so callers can spot
// firmware regressions rather than silently misreporting state.
func (c *Client) DesktopIsLocked(ctx context.Context) (bool, error) {
	if !c.open.Load() {
		return false, ErrSessionClosed
	}
	id := c.commandID()
	req := &pb.Main{
		CommandId: id,
		Content: &pb.Main_DesktopIsLockedRequest{
			DesktopIsLockedRequest: &pb.IsLockedRequest{},
		},
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := writeFramed(c.tx, req); err != nil {
		return false, err
	}

	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		m, err := readFramed(c.tx)
		if err != nil {
			return false, err
		}
		if m.CommandId != id {
			continue
		}
		switch m.CommandStatus {
		case pb.CommandStatus_OK:
			return true, nil
		case pb.CommandStatus_ERROR:
			return false, nil
		default:
			return false, fmt.Errorf("rpc desktop is_locked: %s", m.CommandStatus)
		}
	}
}

// DesktopUnlock issues a desktop_unlock_request and waits for the Empty
// acknowledgement. The firmware returns CommandStatus_OK whether or not
// the desktop was already unlocked, so callers can use this method
// idempotently.
func (c *Client) DesktopUnlock(ctx context.Context) error {
	if !c.open.Load() {
		return ErrSessionClosed
	}
	id := c.commandID()
	req := &pb.Main{
		CommandId: id,
		Content: &pb.Main_DesktopUnlockRequest{
			DesktopUnlockRequest: &pb.UnlockRequest{},
		},
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := writeFramed(c.tx, req); err != nil {
		return err
	}
	return c.awaitAck(ctx, id, "desktop unlock")
}

// PropertyGet issues a property_get_request and accumulates the
// streamed (key, value) pairs the firmware emits. The firmware replies
// with one PropertyGetResponse per matching property; the supplied key
// acts as a prefix filter (an empty string returns every exposed
// property). The stream is terminated by a frame with has_next == false.
// A non-OK CommandStatus on any frame aborts and is surfaced as an
// error.
//
// Result order is preserved exactly as the firmware emitted it.
func (c *Client) PropertyGet(ctx context.Context, key string) ([]struct{ Key, Value string }, error) {
	if !c.open.Load() {
		return nil, ErrSessionClosed
	}
	id := c.commandID()
	req := &pb.Main{
		CommandId: id,
		Content: &pb.Main_PropertyGetRequest{
			PropertyGetRequest: &pb.GetRequest{Key: key},
		},
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := writeFramed(c.tx, req); err != nil {
		return nil, err
	}

	out := make([]struct{ Key, Value string }, 0, 16)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		m, err := readFramed(c.tx)
		if err != nil {
			return nil, err
		}
		if m.CommandId != id {
			continue
		}
		if err := storageStatusErr(m.CommandStatus, "property get"); err != nil {
			return nil, err
		}
		resp, ok := m.Content.(*pb.Main_PropertyGetResponse)
		if !ok {
			return nil, fmt.Errorf("rpc property get: unexpected response type %T", m.Content)
		}
		out = append(out, struct{ Key, Value string }{
			Key:   resp.PropertyGetResponse.GetKey(),
			Value: resp.PropertyGetResponse.GetValue(),
		})
		if !m.HasNext {
			return out, nil
		}
	}
}

// StartScreenStream sends a StartScreenStreamRequest and returns a channel on
// which ScreenFrame values are delivered as they arrive. The goroutine driving
// the channel exits when ctx is cancelled or the transport returns a disconnect
// error, at which point the channel is closed.
//
// Call StopScreenStream to cleanly terminate the stream.
func (c *Client) StartScreenStream(ctx context.Context) (<-chan ScreenFrame, error) {
	if !c.open.Load() {
		return nil, ErrSessionClosed
	}
	id := c.commandID()
	req := &pb.Main{
		CommandId: id,
		Content: &pb.Main_GuiStartScreenStreamRequest{
			GuiStartScreenStreamRequest: &pb.StartScreenStreamRequest{},
		},
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := writeFramed(c.tx, req); err != nil {
		return nil, err
	}

	ch := make(chan ScreenFrame)
	go c.readScreenFrames(ctx, ch)
	return ch, nil
}

// readScreenFrames is the goroutine that reads framed messages and delivers
// ScreenFrame values. Non-ScreenFrame messages (such as the initial ack) are
// dropped. The channel is closed when ctx is done or a transport error occurs.
func (c *Client) readScreenFrames(ctx context.Context, ch chan ScreenFrame) {
	defer close(ch)
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		m, err := readFramed(c.tx)
		if err != nil {
			// io.EOF or disconnect — close cleanly.
			return
		}
		sf, ok := m.Content.(*pb.Main_GuiScreenFrame)
		if !ok {
			continue
		}
		frame := decodeFrame(sf.GuiScreenFrame)
		select {
		case ch <- frame:
		case <-ctx.Done():
			return
		}
	}
}

// StopScreenStream sends a StopScreenStreamRequest. The channel returned by
// StartScreenStream will be closed once the firmware acknowledges.
func (c *Client) StopScreenStream(ctx context.Context) error {
	if !c.open.Load() {
		return ErrSessionClosed
	}
	id := c.commandID()
	req := &pb.Main{
		CommandId: id,
		Content: &pb.Main_GuiStopScreenStreamRequest{
			GuiStopScreenStreamRequest: &pb.StopScreenStreamRequest{},
		},
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return writeFramed(c.tx, req)
}

// SendInput dispatches a single button event to the firmware via
// Gui.SendInputEventRequest. Used while a screen stream is active so the
// operator can drive the device without yielding the RPC session back to
// CLI. The button is one of: up, down, left, right, ok, back; the event
// is one of: press, release, short, long, repeat.
func (c *Client) SendInput(ctx context.Context, button, event string) error {
	if !c.open.Load() {
		return ErrSessionClosed
	}
	keyVal, ok := inputKeyOf(button)
	if !ok {
		return fmt.Errorf("rpc: unknown input button %q", button)
	}
	typVal, ok := inputTypeOf(event)
	if !ok {
		return fmt.Errorf("rpc: unknown input event type %q", event)
	}
	req := &pb.Main{
		CommandId: c.commandID(),
		Content: &pb.Main_GuiSendInputEventRequest{
			GuiSendInputEventRequest: &pb.SendInputEventRequest{Key: keyVal, Type: typVal},
		},
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return writeFramed(c.tx, req)
}

func inputKeyOf(s string) (pb.InputKey, bool) {
	switch s {
	case "up":
		return pb.InputKey_UP, true
	case "down":
		return pb.InputKey_DOWN, true
	case "left":
		return pb.InputKey_LEFT, true
	case "right":
		return pb.InputKey_RIGHT, true
	case "ok":
		return pb.InputKey_OK, true
	case "back":
		return pb.InputKey_BACK, true
	}
	return 0, false
}

func inputTypeOf(s string) (pb.InputType, bool) {
	switch s {
	case "press":
		return pb.InputType_PRESS, true
	case "release":
		return pb.InputType_RELEASE, true
	case "short":
		return pb.InputType_SHORT, true
	case "long":
		return pb.InputType_LONG, true
	case "repeat":
		return pb.InputType_REPEAT, true
	}
	return 0, false
}

func (c *Client) commandID() uint32 {
	return c.nextID.Add(1)
}

// ensure Client satisfies io.Closer.
var _ io.Closer = (*Client)(nil)
