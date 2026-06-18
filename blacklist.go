package blacklist

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type BanType string

const (
	BanTemporary BanType = "temporary"
	BanPermanent BanType = "permanent"
)

type BanEntry struct {
	Entry     string    `json:"entry"`
	BanType   BanType   `json:"ban_type"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type ipEntry struct {
	ipNet     *net.IPNet
	expiresAt time.Time
	banType   BanType
	createdAt time.Time
}

type Blacklist struct {
	mu       sync.RWMutex
	ips      map[string]ipEntry
	cidrs    map[string]ipEntry
	stopClean chan struct{}
}

func New() *Blacklist {
	bl := &Blacklist{
		ips:       make(map[string]ipEntry),
		cidrs:     make(map[string]ipEntry),
		stopClean: make(chan struct{}),
	}
	go bl.startCleaner()
	return bl
}

func (b *Blacklist) Close() {
	close(b.stopClean)
}

func (b *Blacklist) startCleaner() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			b.cleanExpired()
		case <-b.stopClean:
			return
		}
	}
}

func (b *Blacklist) cleanExpired() {
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()

	for key, entry := range b.ips {
		if entry.banType == BanTemporary && now.After(entry.expiresAt) {
			delete(b.ips, key)
		}
	}

	for key, entry := range b.cidrs {
		if entry.banType == BanTemporary && now.After(entry.expiresAt) {
			delete(b.cidrs, key)
		}
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

type BanConfig struct {
	BanType   BanType     `json:"ban_type"`
	Duration  time.Duration `json:"-"`
	DurationStr string     `json:"duration,omitempty"`
}

func DefaultBanConfig() BanConfig {
	return BanConfig{
		BanType:  BanPermanent,
		Duration: 0,
	}
}

func TemporaryBanConfig(duration time.Duration) BanConfig {
	return BanConfig{
		BanType:  BanTemporary,
		Duration: duration,
	}
}

func (b *Blacklist) Add(entry string, config ...BanConfig) error {
	cfg := DefaultBanConfig()
	if len(config) > 0 {
		cfg = config[0]
	}

	if cfg.BanType == BanTemporary && cfg.Duration <= 0 {
		return fmt.Errorf("temporary ban requires a positive duration")
	}

	if isRange(entry) {
		return b.addRange(entry, cfg)
	}
	return b.addIP(entry, cfg)
}

func (b *Blacklist) addIP(s string, cfg BanConfig) error {
	ip, err := parseIP(s)
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	entry := ipEntry{
		banType:   cfg.BanType,
		createdAt: time.Now(),
	}
	if cfg.BanType == BanTemporary {
		entry.expiresAt = time.Now().Add(cfg.Duration)
	}
	b.ips[ip.String()] = entry
	return nil
}

func (b *Blacklist) addRange(s string, cfg BanConfig) error {
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

	entry := ipEntry{
		ipNet:     ipNet,
		banType:   cfg.BanType,
		createdAt: time.Now(),
	}
	if cfg.BanType == BanTemporary {
		entry.expiresAt = time.Now().Add(cfg.Duration)
	}
	b.cidrs[key] = entry
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

func (b *Blacklist) Contains(s string) (bool, *BanEntry, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return false, nil, fmt.Errorf("invalid IP address: %s", s)
	}

	b.mu.RLock()
	defer b.mu.RUnlock()
	now := time.Now()

	if entry, ok := b.ips[ip.String()]; ok {
		if entry.banType == BanTemporary && now.After(entry.expiresAt) {
			return false, nil, nil
		}
		return true, b.toBanEntry(ip.String(), entry), nil
	}

	for key, entry := range b.cidrs {
		if entry.ipNet != nil && entry.ipNet.Contains(ip) {
			if entry.banType == BanTemporary && now.After(entry.expiresAt) {
				continue
			}
			return true, b.toBanEntry(key, entry), nil
		}
	}

	return false, nil, nil
}

func (b *Blacklist) toBanEntry(key string, entry ipEntry) *BanEntry {
	be := &BanEntry{
		Entry:     key,
		BanType:   entry.banType,
		CreatedAt: entry.createdAt,
	}
	if entry.banType == BanTemporary {
		be.ExpiresAt = entry.expiresAt
	}
	return be
}

func (b *Blacklist) List() (ips []BanEntry, cidrs []BanEntry) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	now := time.Now()

	ips = make([]BanEntry, 0, len(b.ips))
	for key, entry := range b.ips {
		if entry.banType == BanTemporary && now.After(entry.expiresAt) {
			continue
		}
		ips = append(ips, *b.toBanEntry(key, entry))
	}

	cidrs = make([]BanEntry, 0, len(b.cidrs))
	for key, entry := range b.cidrs {
		if entry.banType == BanTemporary && now.After(entry.expiresAt) {
			continue
		}
		cidrs = append(cidrs, *b.toBanEntry(key, entry))
	}

	return
}
