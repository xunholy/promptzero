package rpc

import "errors"

// ErrAlreadyOpen indicates that the RPC session is already open.
// ErrSessionClosed indicates that the RPC session has been closed.
// ErrFrameTimeout indicates that a frame timeout has occurred.
var (
	ErrAlreadyOpen   = errors.New("rpc: already open")
	ErrSessionClosed = errors.New("rpc: session closed")
	ErrFrameTimeout  = errors.New("rpc: frame timeout")
)
