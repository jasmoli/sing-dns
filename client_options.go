package dns

import "net/netip"

type QueryOptions struct {
	Strategy     DomainStrategy
	DisableCache bool
	RewriteTTL   *uint32
	ClientSubnet netip.Prefix
}

func (o *QueryOptions) Copy() QueryOptions {
	return QueryOptions{
		Strategy:     o.Strategy,
		DisableCache: o.DisableCache,
		RewriteTTL:   o.RewriteTTL,
		ClientSubnet: o.ClientSubnet,
	}
}
