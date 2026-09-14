// Package sniff defines the extension point by which an embedder identifies the
// application-layer protocol of a TCP flow from the client's leading bytes,
// before the flow is dialed.
//
// The stack owns the mechanism — reading bytes under a bound, recording the
// result on the flow's metadata, and replaying those bytes into the proxy pipe
// — and knows nothing about any specific protocol. A Sniffer supplied by the
// embedder holds all protocol knowledge. This keeps protocol coverage growing
// in the embedder without further changes to the stack.
package sniff

import "time"

// Status is a Sniffer's verdict on the bytes seen so far. It is an explicit
// enum rather than a sentinel error so the contract does not depend on error
// identity across a module boundary.
type Status int

const (
	// More means the bytes so far are consistent with a protocol but not yet
	// sufficient to decide; the stack should read more (bounded by Budget) and
	// call Sniff again.
	More Status = iota
	// NotApplicable means nothing will match; the stack stops sniffing.
	NotApplicable
	// Matched means the flow is identified; proto, and host when the protocol
	// carries one, are meaningful.
	Matched
)

// Sniffer identifies a flow from its client-originated leading bytes. An
// implementation must be a pure function of data: no I/O, no per-flow state,
// and it must never panic on malformed or adversarial input.
type Sniffer interface {
	// Sniff inspects the accumulated leading bytes and returns the protocol
	// label and host (either may be empty) together with the verdict.
	Sniff(data []byte) (proto, host string, status Status)

	// Budget bounds the stack's read loop: the most bytes it will buffer before
	// giving up, and the wall-clock time it will wait for them.
	Budget() (maxBytes int, timeout time.Duration)
}
