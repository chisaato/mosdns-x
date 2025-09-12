// Package macaddr provides a matcher for MAC addresses.
// It supports loading MAC addresses from various sources including files.
package macaddr

import (
	"fmt"
	"net"
)

// Matcher is a MAC address matcher that uses a hash map for efficient lookups.
type Matcher struct {
	// macs stores the MAC addresses. Using [6]byte as the key for direct comparison.
	// struct{} is used as the value to minimize memory footprint.
	macs map[[6]byte]struct{}
}

// Match checks if the given MAC address is in the matcher's set.
// It returns true if the MAC address is found, false otherwise.
func (m *Matcher) Match(mac net.HardwareAddr) bool {
	// Ensure the MAC address is 6 bytes long (EUI-48)
	if len(mac) != 6 {
		return false
	}

	// Convert []byte to [6]byte for use as a map key
	var key [6]byte
	copy(key[:], mac)

	_, found := m.macs[key]
	return found
}

// Len returns the number of MAC addresses in the matcher.
func (m *Matcher) Len() int {
	return len(m.macs)
}

// Close implements the io.Closer interface.
// Since there are no external resources to close, it does nothing.
func (m *Matcher) Close() error {
	// No resources to close for an in-memory map
	return nil
}

// Add adds a MAC address pattern to the matcher.
// pattern should be a valid MAC address string, e.g., "aa:bb:cc:dd:ee:ff".
func (m *Matcher) Add(pattern string, v struct{}) error {
	hwAddr, err := net.ParseMAC(pattern)
	if err != nil {
		return fmt.Errorf("invalid MAC address %s: %w", pattern, err)
	}
	if len(hwAddr) != 6 {
		return fmt.Errorf("MAC address must be 6 bytes, got %d", len(hwAddr))
	}
	m.add(hwAddr)
	return nil
}

// NewMatcher creates a new empty Matcher.
func NewMatcher() *Matcher {
	return &Matcher{
		macs: make(map[[6]byte]struct{}),
	}
}

// add is a helper method to add a net.HardwareAddr to the internal map.
// It assumes the MAC address is valid and 6 bytes long.
func (m *Matcher) add(mac net.HardwareAddr) {
	var key [6]byte
	copy(key[:], mac)
	m.macs[key] = struct{}{}
}

// Ensure that Matcher implements the necessary interface for msg_matcher.NewMacAddressMatcher
// This is a compile-time check to ensure compatibility.
var _ interface {
	Match(mac net.HardwareAddr) bool
	Len() int
	Close() error
	Add(pattern string, v struct{}) error
} = (*Matcher)(nil)
