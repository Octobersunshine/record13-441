package blacklist

import (
	"fmt"
	"net"
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

func parseCIDR(s string) (*net.IPNet, error) {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR notation: %s", s)
	}
	return ipNet, nil
}

func isCIDR(s string) bool {
	return len(s) > 0 && containsSlash(s)
}

func containsSlash(s string) bool {
	for _, c := range s {
		if c == '/' {
			return true
		}
	}
	return false
}

func (b *Blacklist) Add(entry string) error {
	if isCIDR(entry) {
		return b.addCIDR(entry)
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

func (b *Blacklist) addCIDR(s string) error {
	ipNet, err := parseCIDR(s)
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cidrs[s] = ipNet
	return nil
}

func (b *Blacklist) Remove(entry string) error {
	if isCIDR(entry) {
		return b.removeCIDR(entry)
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

func (b *Blacklist) removeCIDR(s string) error {
	_, _, err := net.ParseCIDR(s)
	if err != nil {
		return fmt.Errorf("invalid CIDR notation: %s", s)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.cidrs, s)
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
