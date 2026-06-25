package macaddr

import (
	"net"

	"github.com/miekg/dns"
)

// ExtractFromMsg extracts the MAC address from EDNS0 option code 65001 (EDNS0LOCALSTART)
// in the DNS message m. This is used by dnsmasq on OpenWrt to attach the client's
// MAC address to DNS queries.
// Returns nil if no EDNS0 option with code 65001 is found.
func ExtractFromMsg(m *dns.Msg) net.HardwareAddr {
	opt := m.IsEdns0()
	if opt == nil {
		return nil
	}
	return extractFromOpt(opt)
}

// extractFromOpt searches the EDNS0 options for option code dns.EDNS0LOCALSTART (65001)
// and returns its data as a MAC address.
func extractFromOpt(opt *dns.OPT) net.HardwareAddr {
	for _, o := range opt.Option {
		if o.Option() == dns.EDNS0LOCALSTART {
			if local, ok := o.(*dns.EDNS0_LOCAL); ok {
				return local.Data
			}
		}
	}
	return nil
}
