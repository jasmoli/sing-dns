package dns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"

	"github.com/miekg/dns"
)

const (
	DefaultTTL     = 600
	DefaultTimeout = 10 * time.Second
)

var (
	ErrNoRawSupport           = E.New("no raw query support by current transport")
	ErrNotCached              = E.New("not cached")
	ErrResponseRejected       = E.New("response rejected")
	ErrResponseRejectedCached = E.Extend(ErrResponseRejected, "cached")
)

type Hosts struct {
	CNAMEHosts map[string]string
	IPv4Hosts  map[string][]netip.Addr
	IPv6Hosts  map[string][]netip.Addr
}

func NewHosts(hostsMap map[string][]string) (*Hosts, error) {
	if len(hostsMap) == 0 {
		return nil, nil
	}
	hosts := Hosts{
		CNAMEHosts: make(map[string]string),
		IPv4Hosts:  make(map[string][]netip.Addr),
		IPv6Hosts:  make(map[string][]netip.Addr),
	}
	for domain, addrs := range hostsMap {
		var ipv4Addr, ipv6Addr []netip.Addr
		for _, addr := range addrs {
			SAddr := M.ParseSocksaddr(addr)
			if SAddr.Port != 0 {
				return nil, E.New("hosts cannot containing port")
			}
			if SAddr.IsFqdn() {
				if len(addrs) > 1 {
					return nil, E.New("CNAME hosts can only be used alone")
				}
				hosts.CNAMEHosts[domain] = SAddr.Fqdn
			} else if SAddr.IsIPv4() {
				ipv4Addr = append(ipv4Addr, SAddr.Addr)
			} else if SAddr.IsIPv6() {
				if SAddr.Addr.Is4In6() {
					ipv4Addr = append(ipv4Addr, netip.AddrFrom4(SAddr.Addr.As4()))
				} else {
					ipv6Addr = append(ipv6Addr, SAddr.Addr)
				}
			}
		}
		if len(ipv4Addr) > 0 {
			hosts.IPv4Hosts[domain] = ipv4Addr
		}
		if len(ipv6Addr) > 0 {
			hosts.IPv6Hosts[domain] = ipv6Addr
		}
	}
	return &hosts, nil
}

type Client struct {
	timeout          time.Duration
	disableCache     bool
	disableExpire    bool
	independentCache bool
	hosts            *Hosts
	rdrc             RDRCStore
	initRDRCFunc     func() RDRCStore
	logger           logger.ContextLogger
	cache            freelru.Cache[dns.Question, *dns.Msg]
	transportCache   freelru.Cache[transportCacheKey, *dns.Msg]
}

type RDRCStore interface {
	LoadRDRC(transportName string, qName string, qType uint16) (rejected bool)
	SaveRDRC(transportName string, qName string, qType uint16) error
	SaveRDRCAsync(transportName string, qName string, qType uint16, logger logger.Logger)
}

type transportCacheKey struct {
	dns.Question
	transportName string
}

type ClientOptions struct {
	Timeout          time.Duration
	DisableCache     bool
	DisableExpire    bool
	IndependentCache bool
	CacheCapacity    uint32
	Hosts            *Hosts
	RDRC             func() RDRCStore
	Logger           logger.ContextLogger
}

func NewClient(options ClientOptions) *Client {
	client := &Client{
		timeout:          options.Timeout,
		disableCache:     options.DisableCache,
		disableExpire:    options.DisableExpire,
		independentCache: options.IndependentCache,
		hosts:            options.Hosts,
		initRDRCFunc:     options.RDRC,
		logger:           options.Logger,
	}
	if client.timeout == 0 {
		client.timeout = DefaultTimeout
	}
	cacheCapacity := options.CacheCapacity
	if cacheCapacity < 1024 {
		cacheCapacity = 1024
	}
	if !client.disableCache {
		if !client.independentCache {
			client.cache = common.Must1(freelru.NewSharded[dns.Question, *dns.Msg](cacheCapacity, maphash.NewHasher[dns.Question]().Hash32))
		} else {
			client.transportCache = common.Must1(freelru.NewSharded[transportCacheKey, *dns.Msg](cacheCapacity, maphash.NewHasher[transportCacheKey]().Hash32))
		}
	}
	return client
}

func (c *Client) Start() {
	if c.initRDRCFunc != nil {
		c.rdrc = c.initRDRCFunc()
	}
}

func (c *Client) SearchCNAMEHosts(ctx context.Context, message *dns.Msg) (*dns.Msg, []dns.RR) {
	if c.hosts == nil || len(message.Question) == 0 {
		return nil, nil
	}
	question := message.Question[0]
	domain := fqdnToDomain(question.Name)
	cname, hasHosts := c.hosts.CNAMEHosts[domain]
	if !hasHosts || (question.Qtype != dns.TypeCNAME && question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA) {
		return nil, nil
	}
	var records []dns.RR
	for {
		if c.logger != nil {
			c.logger.DebugContext(ctx, "match CNAME hosts: ", domain, " => ", cname)
		}
		domain = cname
		records = append(records, &dns.CNAME{
			Hdr: dns.RR_Header{
				Name:     question.Name,
				Rrtype:   dns.TypeCNAME,
				Class:    dns.ClassINET,
				Ttl:      1,
				Rdlength: uint16(len(dns.Fqdn(cname))),
			},
			Target: dns.Fqdn(cname),
		})
		cname, hasHosts = c.hosts.CNAMEHosts[domain]
		if !hasHosts {
			break
		}
	}
	if question.Qtype != dns.TypeCNAME {
		message.Question[0].Name = dns.Fqdn(domain)
		return nil, records
	}
	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:       message.Id,
			Response: true,
			Rcode:    dns.RcodeSuccess,
		},
		Question: []dns.Question{question},
		Answer:   records,
	}, nil
}

func (c *Client) printIPHostsLog(ctx context.Context, domain string, addrs []netip.Addr, nolog bool) {
	if nolog || c.logger == nil {
		return
	}
	logString := addrs[0].String()
	versionStr := "IPv4"
	if addrs[0].Is6() {
		versionStr = "IPv6"
	}
	if len(addrs) > 1 {
		logString = strings.Join(common.Map(addrs, func(addr netip.Addr) string {
			return addr.String()
		}), ", ")
		logString = "[" + logString + "]"
	}
	c.logger.DebugContext(ctx, "match ", versionStr, " hosts: ", domain, " => ", logString)
}

func (c *Client) SearchIPHosts(ctx context.Context, message *dns.Msg, strategy DomainStrategy) *dns.Msg {
	if c.hosts == nil || len(message.Question) == 0 {
		return nil
	}
	question := message.Question[0]
	if question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA {
		return nil
	}
	domain := fqdnToDomain(question.Name)
	ipv4Addrs, hasIPv4 := c.hosts.IPv4Hosts[domain]
	ipv6Addrs, hasIPv6 := c.hosts.IPv6Hosts[domain]
	response := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:       message.Id,
			Response: true,
			Rcode:    dns.RcodeSuccess,
		},
		Question: []dns.Question{question},
	}
	if !hasIPv4 && !hasIPv6 {
		return nil
	}
	switch question.Qtype {
	case dns.TypeA:
		if !hasIPv4 {
			return nil
		}
		if strategy == DomainStrategyUseIPv6 {
			if c.logger != nil {
				c.logger.DebugContext(ctx, "strategy rejected")
			}
			break
		}
		c.printIPHostsLog(ctx, domain, ipv4Addrs, false)
		for _, addr := range ipv4Addrs {
			record := addr.AsSlice()
			response.Answer = append(response.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:     question.Name,
					Rrtype:   dns.TypeA,
					Class:    dns.ClassINET,
					Ttl:      1,
					Rdlength: uint16(len(record)),
				},
				A: record,
			})
		}
	case dns.TypeAAAA:
		if !hasIPv6 {
			return nil
		}
		if strategy == DomainStrategyUseIPv4 {
			if c.logger != nil {
				c.logger.DebugContext(ctx, "strategy rejected")
			}
			break
		}
		c.printIPHostsLog(ctx, domain, ipv6Addrs, false)
		for _, addr := range ipv6Addrs {
			record := addr.AsSlice()
			response.Answer = append(response.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:     question.Name,
					Rrtype:   dns.TypeAAAA,
					Class:    dns.ClassINET,
					Ttl:      1,
					Rdlength: uint16(len(record)),
				},
				A: addr.AsSlice(),
			})
		}
	default:
		return nil
	}
	return &response
}

func (c *Client) Exchange(ctx context.Context, transport Transport, message *dns.Msg, options QueryOptions) (*dns.Msg, error) {
	return c.ExchangeWithResponseCheck(ctx, transport, message, options, nil)
}

func (c *Client) ExchangeWithResponseCheck(ctx context.Context, transport Transport, message *dns.Msg, options QueryOptions, responseChecker func(response *dns.Msg) bool) (*dns.Msg, error) {
	if len(message.Question) == 0 {
		if c.logger != nil {
			c.logger.WarnContext(ctx, "bad question size: ", len(message.Question))
		}
		responseMessage := dns.Msg{
			MsgHdr: dns.MsgHdr{
				Id:       message.Id,
				Response: true,
				Rcode:    dns.RcodeFormatError,
			},
			Question: message.Question,
		}
		return &responseMessage, nil
	}
	question := message.Question[0]
	if options.ClientSubnet.IsValid() {
		message = SetClientSubnet(message, options.ClientSubnet, true)
	}
	isSimpleRequest := len(message.Question) == 1 &&
		len(message.Ns) == 0 &&
		len(message.Extra) == 0 &&
		!options.ClientSubnet.IsValid()
	disableCache := !isSimpleRequest || c.disableCache || options.DisableCache
	if !disableCache {
		response, ttl := c.loadResponse(question, transport)
		if response != nil {
			logCachedResponse(c.logger, ctx, response, ttl)
			response.Id = message.Id
			return response, nil
		}
	}
	if question.Qtype == dns.TypeA && options.Strategy == DomainStrategyUseIPv6 || question.Qtype == dns.TypeAAAA && options.Strategy == DomainStrategyUseIPv4 {
		responseMessage := dns.Msg{
			MsgHdr: dns.MsgHdr{
				Id:       message.Id,
				Response: true,
				Rcode:    dns.RcodeSuccess,
			},
			Question: []dns.Question{question},
		}
		if c.logger != nil {
			c.logger.DebugContext(ctx, "strategy rejected")
		}
		return &responseMessage, nil
	}
	if !transport.Raw() {
		if question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA {
			return c.exchangeToLookup(ctx, transport, message, question, options)
		}
		return nil, ErrNoRawSupport
	}
	messageId := message.Id
	contextTransport, clientSubnetLoaded := transportNameFromContext(ctx)
	if clientSubnetLoaded && transport.Name() == contextTransport {
		return nil, E.New("DNS query loopback in transport[", contextTransport, "]")
	}
	ctx = contextWithTransportName(ctx, transport.Name())
	if responseChecker != nil && c.rdrc != nil {
		rejected := c.rdrc.LoadRDRC(transport.Name(), question.Name, question.Qtype)
		if rejected {
			return nil, ErrResponseRejectedCached
		}
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	response, err := transport.Exchange(ctx, message)
	cancel()
	if err != nil {
		return nil, err
	}
	if responseChecker != nil && !responseChecker(response) {
		if c.rdrc != nil {
			c.rdrc.SaveRDRCAsync(transport.Name(), question.Name, question.Qtype, c.logger)
		}
		return response, ErrResponseRejected
	}
	if question.Qtype == dns.TypeHTTPS {
		if options.Strategy == DomainStrategyUseIPv4 || options.Strategy == DomainStrategyUseIPv6 {
			for _, rr := range response.Answer {
				https, isHTTPS := rr.(*dns.HTTPS)
				if !isHTTPS {
					continue
				}
				content := https.SVCB
				content.Value = common.Filter(content.Value, func(it dns.SVCBKeyValue) bool {
					if options.Strategy == DomainStrategyUseIPv4 {
						return it.Key() != dns.SVCB_IPV6HINT
					} else {
						return it.Key() != dns.SVCB_IPV4HINT
					}
				})
				https.SVCB = content
			}
		}
	}
	var timeToLive int
	for _, recordList := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
		for _, record := range recordList {
			if timeToLive == 0 || record.Header().Ttl > 0 && int(record.Header().Ttl) < timeToLive {
				timeToLive = int(record.Header().Ttl)
			}
		}
	}
	if options.RewriteTTL != nil {
		timeToLive = int(*options.RewriteTTL)
	}
	for _, recordList := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
		for _, record := range recordList {
			record.Header().Ttl = uint32(timeToLive)
		}
	}
	response.Id = messageId
	if !disableCache {
		c.storeCache(transport, question, response, timeToLive)
	}
	logExchangedResponse(c.logger, ctx, response, timeToLive)
	return response, err
}

func (c *Client) GetExactDomainFromHosts(ctx context.Context, domain string, nolog bool) string {
	if c.hosts == nil || domain == "" {
		return domain
	}
	for {
		cname, hasCNAME := c.hosts.CNAMEHosts[domain]
		if !hasCNAME {
			break
		}
		if !nolog && c.logger != nil {
			c.logger.DebugContext(ctx, "match CNAME hosts: ", domain, " => ", cname)
		}
		domain = cname
	}
	return domain
}

func (c *Client) GetAddrsFromHosts(ctx context.Context, domain string, stategy DomainStrategy, nolog bool) []netip.Addr {
	if c.hosts == nil || domain == "" {
		return nil
	}
	var addrs []netip.Addr
	ipv4Addrs, hasIPv4 := c.hosts.IPv4Hosts[domain]
	ipv6Addrs, hasIPv6 := c.hosts.IPv6Hosts[domain]
	if (!hasIPv4 && !hasIPv6) || (!hasIPv4 && stategy == DomainStrategyUseIPv4) || (!hasIPv6 && stategy == DomainStrategyUseIPv6) {
		return nil
	}
	if hasIPv4 && stategy != DomainStrategyUseIPv6 {
		c.printIPHostsLog(ctx, domain, ipv4Addrs, nolog)
		addrs = append(addrs, ipv4Addrs...)
	}
	if hasIPv6 && stategy != DomainStrategyUseIPv4 {
		c.printIPHostsLog(ctx, domain, ipv6Addrs, nolog)
		addrs = append(addrs, ipv6Addrs...)
	}
	return addrs
}

func (c *Client) Lookup(ctx context.Context, transport Transport, domain string, options QueryOptions) ([]netip.Addr, error) {
	return c.LookupWithResponseCheck(ctx, transport, domain, options, nil)
}

func (c *Client) LookupWithResponseCheck(ctx context.Context, transport Transport, domain string, options QueryOptions, responseChecker func(responseAddrs []netip.Addr) bool) ([]netip.Addr, error) {
	if dns.IsFqdn(domain) {
		domain = domain[:len(domain)-1]
	}
	dnsName := dns.Fqdn(domain)
	if transport.Raw() {
		if options.Strategy == DomainStrategyUseIPv4 {
			return c.lookupToExchange(ctx, transport, dnsName, dns.TypeA, options, responseChecker)
		} else if options.Strategy == DomainStrategyUseIPv6 {
			return c.lookupToExchange(ctx, transport, dnsName, dns.TypeAAAA, options, responseChecker)
		}
		var wg sync.WaitGroup
		var response4, response6 []netip.Addr
		var v4Err, v6Err error
		wg.Add(2)
		go func() {
			defer wg.Done()
			response4, v4Err = c.lookupToExchange(ctx, transport, dnsName, dns.TypeA, options, responseChecker)
		}()
		go func() {
			defer wg.Done()
			response6, v6Err = c.lookupToExchange(ctx, transport, dnsName, dns.TypeAAAA, options, responseChecker)
		}()
		wg.Wait()
		if len(response4) == 0 && len(response6) == 0 {
			return nil, errors.Join(v4Err, v6Err)
		}
		return sortAddresses(response4, response6, options.Strategy), nil
	}
	disableCache := c.disableCache || options.DisableCache
	if !disableCache {
		if options.Strategy == DomainStrategyUseIPv4 {
			response, err := c.questionCache(dns.Question{
				Name:   dnsName,
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}, transport)
			if err != ErrNotCached {
				return response, err
			}
		} else if options.Strategy == DomainStrategyUseIPv6 {
			response, err := c.questionCache(dns.Question{
				Name:   dnsName,
				Qtype:  dns.TypeAAAA,
				Qclass: dns.ClassINET,
			}, transport)
			if err != ErrNotCached {
				return response, err
			}
		} else {
			var wg sync.WaitGroup
			var response4, response6 []netip.Addr
			wg.Add(2)
			go func() {
				defer wg.Done()
				response4, _ = c.questionCache(dns.Question{
					Name:   dnsName,
					Qtype:  dns.TypeA,
					Qclass: dns.ClassINET,
				}, transport)
			}()
			go func() {
				defer wg.Done()
				response6, _ = c.questionCache(dns.Question{
					Name:   dnsName,
					Qtype:  dns.TypeAAAA,
					Qclass: dns.ClassINET,
				}, transport)
			}()
			wg.Wait()
			if len(response4) > 0 || len(response6) > 0 {
				return sortAddresses(response4, response6, options.Strategy), nil
			}
		}
	}
	if responseChecker != nil && c.rdrc != nil {
		var rejected bool
		if options.Strategy != DomainStrategyUseIPv6 {
			rejected = c.rdrc.LoadRDRC(transport.Name(), dnsName, dns.TypeA)
		}
		if !rejected && options.Strategy != DomainStrategyUseIPv4 {
			rejected = c.rdrc.LoadRDRC(transport.Name(), dnsName, dns.TypeAAAA)
		}
		if rejected {
			return nil, ErrResponseRejectedCached
		}
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	var rCode int
	response, err := transport.Lookup(ctx, domain, options.Strategy)
	cancel()
	if err != nil {
		return nil, wrapError(err)
	}
	if responseChecker != nil && !responseChecker(response) {
		if c.rdrc != nil {
			if common.Any(response, func(addr netip.Addr) bool {
				return addr.Is4()
			}) {
				c.rdrc.SaveRDRCAsync(transport.Name(), dnsName, dns.TypeA, c.logger)
			}
			if common.Any(response, func(addr netip.Addr) bool {
				return addr.Is6()
			}) {
				c.rdrc.SaveRDRCAsync(transport.Name(), dnsName, dns.TypeAAAA, c.logger)
			}
		}
		return response, ErrResponseRejected
	}
	header := dns.MsgHdr{
		Response: true,
		Rcode:    rCode,
	}
	if !disableCache {
		var timeToLive uint32
		if options.RewriteTTL != nil {
			timeToLive = *options.RewriteTTL
		} else {
			timeToLive = DefaultTTL
		}
		var wg sync.WaitGroup
		wg.Add(1)
		if options.Strategy != DomainStrategyUseIPv6 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				question4 := dns.Question{
					Name:   dnsName,
					Qtype:  dns.TypeA,
					Qclass: dns.ClassINET,
				}
				response4 := common.Filter(response, func(addr netip.Addr) bool {
					return addr.Is4() || addr.Is4In6()
				})
				message4 := &dns.Msg{
					MsgHdr:   header,
					Question: []dns.Question{question4},
				}
				if len(response4) > 0 {
					for _, address := range response4 {
						message4.Answer = append(message4.Answer, &dns.A{
							Hdr: dns.RR_Header{
								Name:   question4.Name,
								Rrtype: dns.TypeA,
								Class:  dns.ClassINET,
								Ttl:    timeToLive,
							},
							A: address.AsSlice(),
						})
					}
				}
				c.storeCache(transport, question4, message4, int(timeToLive))
			}()
		}
		if options.Strategy != DomainStrategyUseIPv4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				question6 := dns.Question{
					Name:   dnsName,
					Qtype:  dns.TypeAAAA,
					Qclass: dns.ClassINET,
				}
				response6 := common.Filter(response, func(addr netip.Addr) bool {
					return addr.Is6() && !addr.Is4In6()
				})
				message6 := &dns.Msg{
					MsgHdr:   header,
					Question: []dns.Question{question6},
				}
				if len(response6) > 0 {
					for _, address := range response6 {
						message6.Answer = append(message6.Answer, &dns.AAAA{
							Hdr: dns.RR_Header{
								Name:   question6.Name,
								Rrtype: dns.TypeAAAA,
								Class:  dns.ClassINET,
								Ttl:    DefaultTTL,
							},
							AAAA: address.AsSlice(),
						})
					}
				}
				c.storeCache(transport, question6, message6, int(timeToLive))
			}()
		}
		wg.Done()
		wg.Wait()
	}
	return response, nil
}

func (c *Client) ClearCache() {
	if c.cache != nil {
		c.cache.Purge()
	}
	if c.transportCache != nil {
		c.transportCache.Purge()
	}
}

func (c *Client) LookupCache(ctx context.Context, domain string, strategy DomainStrategy) ([]netip.Addr, bool) {
	if c.disableCache || c.independentCache {
		return nil, false
	}
	if dns.IsFqdn(domain) {
		domain = domain[:len(domain)-1]
	}
	dnsName := dns.Fqdn(domain)
	if strategy == DomainStrategyUseIPv4 {
		response, err := c.questionCache(dns.Question{
			Name:   dnsName,
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}, nil)
		if err != ErrNotCached {
			return response, true
		}
	} else if strategy == DomainStrategyUseIPv6 {
		response, err := c.questionCache(dns.Question{
			Name:   dnsName,
			Qtype:  dns.TypeAAAA,
			Qclass: dns.ClassINET,
		}, nil)
		if err != ErrNotCached {
			return response, true
		}
	} else {
		var wg sync.WaitGroup
		var response4, response6 []netip.Addr
		wg.Add(2)
		go func() {
			defer wg.Done()
			response4, _ = c.questionCache(dns.Question{
				Name:   dnsName,
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}, nil)
		}()
		go func() {
			defer wg.Done()
			response6, _ = c.questionCache(dns.Question{
				Name:   dnsName,
				Qtype:  dns.TypeAAAA,
				Qclass: dns.ClassINET,
			}, nil)
		}()
		wg.Wait()
		if len(response4) > 0 || len(response6) > 0 {
			return sortAddresses(response4, response6, strategy), true
		}
	}
	return nil, false
}

func (c *Client) ExchangeCache(ctx context.Context, message *dns.Msg) (*dns.Msg, bool) {
	if c.disableCache || c.independentCache || len(message.Question) != 1 {
		return nil, false
	}
	question := message.Question[0]
	response, ttl := c.loadResponse(question, nil)
	if response == nil {
		return nil, false
	}
	logCachedResponse(c.logger, ctx, response, ttl)
	response.Id = message.Id
	return response, true
}

func sortAddresses(response4 []netip.Addr, response6 []netip.Addr, strategy DomainStrategy) []netip.Addr {
	if strategy == DomainStrategyPreferIPv6 {
		return append(response6, response4...)
	} else {
		return append(response4, response6...)
	}
}

func (c *Client) storeCache(transport Transport, question dns.Question, message *dns.Msg, timeToLive int) {
	if timeToLive == 0 {
		return
	}
	if c.disableExpire {
		if !c.independentCache {
			c.cache.Add(question, message)
		} else {
			c.transportCache.Add(transportCacheKey{
				Question:      question,
				transportName: transport.Name(),
			}, message)
		}
		return
	}
	if !c.independentCache {
		c.cache.AddWithLifetime(question, message, time.Second*time.Duration(timeToLive))
	} else {
		c.transportCache.AddWithLifetime(transportCacheKey{
			Question:      question,
			transportName: transport.Name(),
		}, message, time.Second*time.Duration(timeToLive))
	}
}

func (c *Client) exchangeToLookup(ctx context.Context, transport Transport, message *dns.Msg, question dns.Question, options QueryOptions) (*dns.Msg, error) {
	domain := question.Name
	if question.Qtype == dns.TypeA {
		options.Strategy = DomainStrategyUseIPv4
	} else {
		options.Strategy = DomainStrategyUseIPv6
	}
	result, err := c.Lookup(ctx, transport, domain, options)
	if err != nil {
		return nil, wrapError(err)
	}
	var timeToLive uint32
	if options.RewriteTTL != nil {
		timeToLive = *options.RewriteTTL
	} else {
		timeToLive = DefaultTTL
	}
	return FixedResponse(message.Id, question, result, timeToLive), nil
}

func (c *Client) lookupToExchange(ctx context.Context, transport Transport, name string, qType uint16, options QueryOptions, responseChecker func(responseAddrs []netip.Addr) bool) ([]netip.Addr, error) {
	question := dns.Question{
		Name:   name,
		Qtype:  qType,
		Qclass: dns.ClassINET,
	}
	disableCache := c.disableCache || options.DisableCache
	if !disableCache {
		cachedAddresses, err := c.questionCache(question, transport)
		if err != ErrNotCached {
			return cachedAddresses, err
		}
	}
	message := dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: true,
		},
		Question: []dns.Question{question},
	}
	var (
		response *dns.Msg
		err      error
	)
	if responseChecker != nil {
		response, err = c.ExchangeWithResponseCheck(ctx, transport, &message, options, func(response *dns.Msg) bool {
			addresses, addrErr := MessageToAddresses(response)
			if addrErr != nil {
				return false
			}
			return responseChecker(addresses)
		})
	} else {
		response, err = c.Exchange(ctx, transport, &message, options)
	}
	if err != nil {
		return nil, err
	}
	return MessageToAddresses(response)
}

func (c *Client) questionCache(question dns.Question, transport Transport) ([]netip.Addr, error) {
	response, _ := c.loadResponse(question, transport)
	if response == nil {
		return nil, ErrNotCached
	}
	return MessageToAddresses(response)
}

func (c *Client) loadResponse(question dns.Question, transport Transport) (*dns.Msg, int) {
	var (
		response *dns.Msg
		loaded   bool
	)
	if c.disableExpire {
		if !c.independentCache {
			response, loaded = c.cache.Get(question)
		} else {
			response, loaded = c.transportCache.Get(transportCacheKey{
				Question:      question,
				transportName: transport.Name(),
			})
		}
		if !loaded {
			return nil, 0
		}
		return response.Copy(), 0
	} else {
		var expireAt time.Time
		if !c.independentCache {
			response, expireAt, loaded = c.cache.GetWithLifetime(question)
		} else {
			response, expireAt, loaded = c.transportCache.GetWithLifetime(transportCacheKey{
				Question:      question,
				transportName: transport.Name(),
			})
		}
		if !loaded {
			return nil, 0
		}
		timeNow := time.Now()
		if timeNow.After(expireAt) {
			if !c.independentCache {
				c.cache.Remove(question)
			} else {
				c.transportCache.Remove(transportCacheKey{
					Question:      question,
					transportName: transport.Name(),
				})
			}
			return nil, 0
		}
		var originTTL int
		for _, recordList := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
			for _, record := range recordList {
				if originTTL == 0 || record.Header().Ttl > 0 && int(record.Header().Ttl) < originTTL {
					originTTL = int(record.Header().Ttl)
				}
			}
		}
		nowTTL := int(expireAt.Sub(timeNow).Seconds())
		if nowTTL < 0 {
			nowTTL = 0
		}
		response = response.Copy()
		if originTTL > 0 {
			duration := uint32(originTTL - nowTTL)
			for _, recordList := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
				for _, record := range recordList {
					record.Header().Ttl = record.Header().Ttl - duration
				}
			}
		} else {
			for _, recordList := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
				for _, record := range recordList {
					record.Header().Ttl = uint32(nowTTL)
				}
			}
		}
		return response, nowTTL
	}
}

func MessageToAddresses(response *dns.Msg) ([]netip.Addr, error) {
	if response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError {
		return nil, RCodeError(response.Rcode)
	}
	addresses := make([]netip.Addr, 0, len(response.Answer))
	for _, rawAnswer := range response.Answer {
		switch answer := rawAnswer.(type) {
		case *dns.A:
			addresses = append(addresses, M.AddrFromIP(answer.A))
		case *dns.AAAA:
			addresses = append(addresses, M.AddrFromIP(answer.AAAA))
		case *dns.HTTPS:
			for _, value := range answer.SVCB.Value {
				if value.Key() == dns.SVCB_IPV4HINT || value.Key() == dns.SVCB_IPV6HINT {
					addresses = append(addresses, common.Map(strings.Split(value.String(), ","), M.ParseAddr)...)
				}
			}
		}
	}
	return addresses, nil
}

func wrapError(err error) error {
	switch dnsErr := err.(type) {
	case *net.DNSError:
		if dnsErr.IsNotFound {
			return RCodeNameError
		}
	case *net.AddrError:
		return RCodeNameError
	}
	return err
}

type transportKey struct{}

func contextWithTransportName(ctx context.Context, transportName string) context.Context {
	return context.WithValue(ctx, transportKey{}, transportName)
}

func transportNameFromContext(ctx context.Context) (string, bool) {
	value, loaded := ctx.Value(transportKey{}).(string)
	return value, loaded
}
