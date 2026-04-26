package rpc

import "errors"

var (
	ErrAlreadyOpen   = errors.New("rpc: already open")
	ErrSessionClosed = errors.New("rpc: session closed")
	ErrFrameTimeout  = errors.New("rpc: frame timeout")
)
