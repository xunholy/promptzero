package rpc

import "errors"

var (
	// ErrAlreadyOpen indicates that the RPC session is already open.
	ErrAlreadyOpen = errors.New("rpc: already open")
	// ErrSessionClosed indicates that the RPC session has been closed.
	ErrSessionClosed = errors.New("rpc: session closed")
	// ErrFrameTimeout indicates that a frame timeout has occurred.
	ErrFrameTimeout = errors.New("rpc: frame timeout")
)
