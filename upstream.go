package dns

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"os"
	"sync"

	"github.com/miekg/dns"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

var _ Transport = (*BaseTransport)(nil)

type BaseTransport struct {
	name      string
	upstreams []Upstream
}

func (t *BaseTransport) Name() string {
	return t.name
}

func (t *BaseTransport) Start() error {
	for _, upstream := range t.upstreams {
		if err := upstream.Start(); err != nil {
			return err
		}
	}
	return nil
}

func (t *BaseTransport) Reset() {
	for _, upstream := range t.upstreams {
		upstream.Reset()
	}
}

func (t *BaseTransport) Close() error {
	for _, upstream := range t.upstreams {
		if err := upstream.Close(); err != nil {
			return err
		}
	}
	return nil
}

func (t *BaseTransport) Raw() bool {
	return true
}

type exchangeResult struct {
	msg *dns.Msg
	err error
}

func (t *BaseTransport) Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
	fastClose, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	results := make(chan exchangeResult, len(t.upstreams))
	for _, upstream := range t.upstreams {
		wg.Add(1)
		go func(upstream Upstream) {
			msg, err := upstream.Exchange(fastClose, message)
			results <- exchangeResult{msg, err}
			wg.Done()
		}(upstream)
	}
	defer func() {
		go func() {
			wg.Wait()
			close(results)
		}()
	}()
	var result *exchangeResult
	for i := 0; i < len(t.upstreams); i++ {
		res := <-results
		if result == nil || res.err == nil || !errors.Is(res.err, context.DeadlineExceeded) {
			result = &res
		}
		if res.err == nil || errors.Is(res.err, context.DeadlineExceeded) {
			break
		}
	}
	return result.msg, result.err
}

func (t *BaseTransport) Lookup(ctx context.Context, domain string, strategy DomainStrategy) ([]netip.Addr, error) {
	return nil, os.ErrInvalid
}

type Upstream interface {
	Start() error
	Reset()
	Close() error
	Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error)
	Lookup(ctx context.Context, domain string, strategy DomainStrategy) ([]netip.Addr, error)
}

type UpstreamOptions struct {
	Context context.Context
	Logger  logger.ContextLogger
	Dialer  N.Dialer
	Address string
}

func baseTransportConstructor(options TransportOptions) (Transport, error) {
	var ups []Upstream
	for _, address := range options.Address {
		serverURL, _ := url.Parse(address)
		var scheme string
		if serverURL != nil {
			scheme = serverURL.Scheme
		}
		constructor := upstreams[scheme]
		upstream, err := constructor(UpstreamOptions{
			Context: options.Context,
			Logger:  options.Logger,
			Dialer:  options.Dialer,
			Address: address,
		})
		if err != nil {
			return nil, err
		}
		ups = append(ups, upstream)
	}
	return &BaseTransport{
		name:      options.Name,
		upstreams: ups,
	}, nil
}
