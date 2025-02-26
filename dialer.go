package dns

import (
	"context"
	"net"
	"net/netip"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type DefaultDialer struct {
	dialer        N.Dialer
	client        *Client
	fallbackDelay time.Duration
}

func NewDefaultDialer(dialer N.Dialer, client *Client, fallbackDelay time.Duration) N.Dialer {
	return &DefaultDialer{dialer, client, fallbackDelay}
}

func (d *DefaultDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if destination.IsIP() {
		return d.dialer.DialContext(ctx, network, destination)
	}
	destination.Fqdn = d.client.GetExactDomainFromHosts(ctx, destination.Fqdn, false)
	if addresses := d.client.GetAddrsFromHosts(ctx, destination.Fqdn, d.client.strategy, false); len(addresses) > 0 {
		if d.client.strategy == DomainStrategyAsIS {
			return N.DialSerial(ctx, d.dialer, network, destination, addresses)
		}
		return N.DialParallel(ctx, d.dialer, network, destination, addresses, d.client.strategy == DomainStrategyPreferIPv6, d.fallbackDelay)
	}
	return d.dialer.DialContext(ctx, network, destination)
}

func (d *DefaultDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if destination.IsIP() {
		return d.dialer.ListenPacket(ctx, destination)
	}
	destination.Fqdn = d.client.GetExactDomainFromHosts(ctx, destination.Fqdn, false)
	if addresses := d.client.GetAddrsFromHosts(ctx, destination.Fqdn, d.client.strategy, false); len(addresses) > 0 {
		conn, _, err := N.ListenSerial(ctx, d.dialer, destination, addresses)
		return conn, err
	}
	return d.dialer.ListenPacket(ctx, destination)
}

type DialerWrapper struct {
	DefaultDialer
	transport Transport
	strategy  DomainStrategy
}

func NewDialerWrapper(dialer N.Dialer, client *Client, transport Transport, strategy DomainStrategy, fallbackDelay time.Duration) N.Dialer {
	defaultDialer := DefaultDialer{dialer, client, fallbackDelay}
	return &DialerWrapper{defaultDialer, transport, strategy}
}

func (d *DialerWrapper) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if destination.IsIP() {
		return d.dialer.DialContext(ctx, network, destination)
	}
	destination.Fqdn = d.client.GetExactDomainFromHosts(ctx, destination.Fqdn, false)
	strategy := d.client.strategy
	if d.strategy != DomainStrategyAsIS {
		strategy = d.strategy
	}
	var addresses []netip.Addr
	if addresses = d.client.GetAddrsFromHosts(ctx, destination.Fqdn, strategy, false); len(addresses) == 0 {
		var err error
		addresses, err = d.client.Lookup(ctx, d.transport, destination.Fqdn, QueryOptions{
			Strategy: strategy,
		}, false)
		if err != nil {
			return nil, err
		}
	}
	if strategy == DomainStrategyAsIS {
		return N.DialSerial(ctx, d.dialer, network, destination, addresses)
	}
	return N.DialParallel(ctx, d.dialer, network, destination, addresses, strategy == DomainStrategyPreferIPv6, d.fallbackDelay)
}

func (d *DialerWrapper) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if destination.IsIP() {
		return d.dialer.ListenPacket(ctx, destination)
	}
	destination.Fqdn = d.client.GetExactDomainFromHosts(ctx, destination.Fqdn, false)
	strategy := d.client.strategy
	if d.strategy != DomainStrategyAsIS {
		strategy = d.strategy
	}
	var addresses []netip.Addr
	if addresses = d.client.GetAddrsFromHosts(ctx, destination.Fqdn, strategy, false); len(addresses) == 0 {
		var err error
		addresses, err = d.client.Lookup(ctx, d.transport, destination.Fqdn, QueryOptions{
			Strategy: strategy,
		}, false)
		if err != nil {
			return nil, err
		}
	}
	conn, _, err := N.ListenSerial(ctx, d.dialer, destination, addresses)
	return conn, err
}

func (d *DialerWrapper) Upstream() any {
	return d.dialer
}
