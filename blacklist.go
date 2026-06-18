package blacklist

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
)

type Blacklist struct {
	mu       sync.RWMutex
	ips      map[string]struct{}
	cidrs    map[string]*net.IPNet
}

func New() *Blacklist {
	return &Blacklist{
		ips:   make(map[string]struct{}),
		cidrs: make(map[string]*net.IPNet),
	}
}

func parseIP(s string) (net.IP, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", s)
	}
	return ip, nil
}

func parseCIDR(s string) (string, *net.IPNet, error) {
	ip, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return "", nil, fmt.Errorf("invalid CIDR notation: %s", s)
	}
	normalized := ipNet.IP.String() + "/" + cidrMaskToPrefix(ipNet.Mask)
	_ = ip
	return normalized, ipNet, nil
}

func cidrMaskToPrefix(mask net.IPMask) string {
	ones, _ := mask.Size()
	return strconv.Itoa(ones)
}

func isRange(s string) bool {
	return isCIDR(s) || isWildcard(s)
}

func isCIDR(s string) bool {
	return len(s) > 0 && strings.Contains(s, "/")
}

func isWildcard(s string) bool {
	return len(s) > 0 && strings.Contains(s, "*")
}

func parseWildcard(s string) (string, *net.IPNet, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return "", nil, fmt.Errorf("invalid wildcard format: %s", s)
	}

	var prefixLen int
	var ipParts [4]byte

	for i, part := range parts {
		if part == "*" {
			for j := i; j < 4; j++ {
				ipParts[j] = 0
			}
			prefixLen = i * 8
			break
		}
		val, err := strconv.Atoi(part)
		if err != nil || val < 0 || val > 255 {
			return "", nil, fmt.Errorf("invalid wildcard format: %s", s)
		}
		ipParts[i] = byte(val)
		if i == 3 {
			prefixLen = 32
		}
	}

	if prefixLen == 0 {
		return "", nil, fmt.Errorf("invalid wildcard format, at least one segment must be specified: %s", s)
	}

	ip := net.IPv4(ipParts[0], ipParts[1], ipParts[2], ipParts[3])
	mask := net.CIDRMask(prefixLen, 32)
	ipNet := &net.IPNet{IP: ip.Mask(mask), Mask: mask}
	normalized := ipNet.IP.String() + "/" + strconv.Itoa(prefixLen)
	return normalized, ipNet, nil
}

func (b *Blacklist) Add(entry string) error {
	if isRange(entry) {
		return b.addRange(entry)
	}
	return b.addIP(entry)
}

func (b *Blacklist) addIP(s string) error {
	ip, err := parseIP(s)
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ips[ip.String()] = struct{}{}
	return nil
}

func (b *Blacklist) addRange(s string) error {
	var key string
	var ipNet *net.IPNet
	var err error

	if isWildcard(s) {
		key, ipNet, err = parseWildcard(s)
	} else {
		key, ipNet, err = parseCIDR(s)
	}
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cidrs[key] = ipNet
	return nil
}

func (b *Blacklist) Remove(entry string) error {
	if isRange(entry) {
		return b.removeRange(entry)
	}
	return b.removeIP(entry)
}

func (b *Blacklist) removeIP(s string) error {
	ip, err := parseIP(s)
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.ips, ip.String())
	return nil
}

func (b *Blacklist) removeRange(s string) error {
	var key string
	var err error

	if isWildcard(s) {
		key, _, err = parseWildcard(s)
	} else {
		key, _, err = parseCIDR(s)
	}
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.cidrs, key)
	return nil
}

func (b *Blacklist) Contains(s string) (bool, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return false, fmt.Errorf("invalid IP address: %s", s)
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if _, ok := b.ips[ip.String()]; ok {
		return true, nil
	}

	for _, cidr := range b.cidrs {
		if cidr.Contains(ip) {
			return true, nil
		}
	}

	return false, nil
}

func (b *Blacklist) List() (ips []string, cidrs []string) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	ips = make([]string, 0, len(b.ips))
	for ip := range b.ips {
		ips = append(ips, ip)
	}

	cidrs = make([]string, 0, len(b.cidrs))
	for cidr := range b.cidrs {
		cidrs = append(cidrs, cidr)
	}

	return
}
