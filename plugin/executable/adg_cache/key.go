package adg_cache

import (
	"encoding/binary"
	"net"

	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/pkg/dnsutils"
)

func (f *adgCachePlugin) getCacheKey(q *dns.Msg, clientID string) (string, error) {
	m := q.Copy()

	var ecsBytes []byte
	if opt := m.IsEdns0(); opt != nil {
		if ecs := dnsutils.GetECS(opt); ecs != nil {
			ecsBytes = packECSKey(ecs)
		}
		m.Extra = removeOPT(m.Extra)
	}

	wire, err := m.Pack()
	if err != nil {
		return "", err
	}

	wire[0] = 0
	wire[1] = 0

	if ecsBytes != nil {
		wire = append(wire, ecsBytes...)
	}

	if clientID != "" {
		wire = append(wire, 0)
		wire = append(wire, clientID...)
	}

	return string(wire), nil
}

func removeOPT(extra []dns.RR) []dns.RR {
	for i, e := range extra {
		if e.Header().Rrtype == dns.TypeOPT {
			return append(extra[:i], extra[i+1:]...)
		}
	}
	return extra
}

func packECSKey(ecs *dns.EDNS0_SUBNET) []byte {
	family, mask, addr := normalizeECSAddress(ecs)
	b := make([]byte, 3+len(addr))
	binary.BigEndian.PutUint16(b[0:2], family)
	b[2] = mask
	copy(b[3:], addr)
	return b
}

func normalizeECSAddress(ecs *dns.EDNS0_SUBNET) (family uint16, mask uint8, addr net.IP) {
	family = ecs.Family
	mask = ecs.SourceNetmask

	switch family {
	case 1:
		addr = ecs.Address.To4()
		if addr == nil {
			addr = make(net.IP, net.IPv4len)
		}
		if mask > net.IPv4len*8 {
			mask = net.IPv4len * 8
		}
	case 2:
		addr = ecs.Address.To16()
		if addr == nil {
			addr = make(net.IP, net.IPv6len)
		}
		if mask > net.IPv6len*8 {
			mask = net.IPv6len * 8
		}
	default:
		addr = append(net.IP(nil), ecs.Address...)
		return family, mask, addr
	}

	return family, mask, maskIP(addr, mask)
}

func maskIP(ip net.IP, mask uint8) net.IP {
	masked := append(net.IP(nil), ip...)
	fullBytes := int(mask / 8)
	remainingBits := mask % 8

	if fullBytes >= len(masked) {
		return masked
	}

	if remainingBits == 0 {
		for i := fullBytes; i < len(masked); i++ {
			masked[i] = 0
		}
		return masked
	}

	masked[fullBytes] &= ^byte(1<<(8-remainingBits) - 1)
	for i := fullBytes + 1; i < len(masked); i++ {
		masked[i] = 0
	}
	return masked
}
