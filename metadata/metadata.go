package metadata

import (
	"net"
	"net/netip"
)

// Metadata contains metadata of transport protocol sessions.
type Metadata struct {
	Network Network    `json:"network"`
	SrcIP   netip.Addr `json:"sourceIP"`
	MidIP   netip.Addr `json:"dialerIP"`
	DstIP   netip.Addr `json:"destinationIP"`
	SrcPort uint16     `json:"sourcePort"`
	MidPort uint16     `json:"dialerPort"`
	DstPort uint16     `json:"destinationPort"`

	// Host is the hostname the flow is trying to reach, when a Sniffer read one
	// from the client's leading bytes (e.g. TLS SNI, HTTP Host, DNS question).
	// Empty when no sniffing ran or the protocol carried no name.
	Host string `json:"host,omitempty"`
	// Protocol is the application-layer protocol a Sniffer identified, e.g.
	// "tls", "http", "dns". Empty when no sniffing ran or nothing matched.
	Protocol string `json:"protocol,omitempty"`
	// SniffOutcome records how sniffing classified the flow, for an embedder's
	// admission policy and for observability: "matched" (identified),
	// "unrecognized" (enough leading bytes seen, no protocol matched),
	// "indeterminate" (no classifiable bytes in time, e.g. server-speaks-first).
	// Empty when sniffing did not run.
	SniffOutcome string `json:"sniffOutcome,omitempty"`
}

func (m *Metadata) DestinationAddrPort() netip.AddrPort {
	return netip.AddrPortFrom(m.DstIP, m.DstPort)
}

func (m *Metadata) DestinationAddress() string {
	return m.DestinationAddrPort().String()
}

func (m *Metadata) SourceAddrPort() netip.AddrPort {
	return netip.AddrPortFrom(m.SrcIP, m.SrcPort)
}

func (m *Metadata) SourceAddress() string {
	return m.SourceAddrPort().String()
}

func (m *Metadata) Addr() net.Addr {
	return &Addr{metadata: m}
}

func (m *Metadata) TCPAddr() *net.TCPAddr {
	if m.Network != TCP || !m.DstIP.IsValid() {
		return nil
	}
	return net.TCPAddrFromAddrPort(m.DestinationAddrPort())
}

func (m *Metadata) UDPAddr() *net.UDPAddr {
	if m.Network != UDP || !m.DstIP.IsValid() {
		return nil
	}
	return net.UDPAddrFromAddrPort(m.DestinationAddrPort())
}

// Addr implements the net.Addr interface.
type Addr struct {
	metadata *Metadata
}

func (a *Addr) Metadata() *Metadata {
	return a.metadata
}

func (a *Addr) Network() string {
	return a.metadata.Network.String()
}

func (a *Addr) String() string {
	return a.metadata.DestinationAddress()
}
