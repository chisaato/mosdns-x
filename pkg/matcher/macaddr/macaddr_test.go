package macaddr

import (
	"net"
	"testing"
)


func TestMatcher_Match(t *testing.T) {
	m := &Matcher{
		macs: make(map[[6]byte]struct{}),
	}

	// Test MAC address
	testMAC, _ := net.ParseMAC("00:11:22:33:44:55")
	var key [6]byte
	copy(key[:], testMAC)
	m.macs[key] = struct{}{}

	tests := []struct {
		name     string
		mac      net.HardwareAddr
		expected bool
	}{
		{
			name:     "existing MAC address",
			mac:      testMAC,
			expected: true,
		},
		{
			name:     "non-existing MAC address",
			mac:      net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
			expected: false,
		},
		{
			name:     "invalid MAC address length",
			mac:      net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44}, // 5 bytes
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := m.Match(tt.mac)
			if result != tt.expected {
				t.Errorf("Match() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestMatcher_Len(t *testing.T) {
	m := &Matcher{
		macs: make(map[[6]byte]struct{}),
	}

	// Initially empty
	if m.Len() != 0 {
		t.Errorf("Len() = %d, expected 0", m.Len())
	}

	// Add some MAC addresses
	macs := []string{"00:11:22:33:44:55", "66:77:88:99:aa:bb", "cc:dd:ee:ff:00:11"}
	for _, macStr := range macs {
		mac, _ := net.ParseMAC(macStr)
		m.add(mac)
	}

	if m.Len() != len(macs) {
		t.Errorf("Len() = %d, expected %d", m.Len(), len(macs))
	}
}

func TestMatcher_Close(t *testing.T) {
	m := &Matcher{
		macs: make(map[[6]byte]struct{}),
	}

	// Close should not return an error
	err := m.Close()
	if err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

// Note: BatchLoadProvider tests are commented out due to data_provider dependency
// These tests would require a proper mock of the data_provider.DataManager interface
// which is defined in an external package.

/*
func TestBatchLoadProvider_DirectMAC(t *testing.T) {
	// Implementation would require proper DataManager mock
}

func TestBatchLoadProvider_FileSource(t *testing.T) {
	// Implementation would require proper DataManager mock
}

func TestBatchLoadProvider_InvalidMAC(t *testing.T) {
	// Implementation would require proper DataManager mock
}

func TestBatchLoadProvider_FileNotFound(t *testing.T) {
	// Implementation would require proper DataManager mock
}
*/

func TestMatcher_Add(t *testing.T) {
	m := &Matcher{
		macs: make(map[[6]byte]struct{}),
	}

	testMAC, _ := net.ParseMAC("00:11:22:33:44:55")

	// Initially not present
	if m.Match(testMAC) {
		t.Error("MAC address should not be present initially")
	}

	// Add MAC address
	m.add(testMAC)

	// Now should be present
	if !m.Match(testMAC) {
		t.Error("MAC address should be present after adding")
	}

	// Length should be 1
	if m.Len() != 1 {
		t.Errorf("Expected length 1, got %d", m.Len())
	}
}
func TestMatcher_CaseInsensitive(t *testing.T) {
	m := NewMatcher()

	// Add lowercase MAC with letters
	err := m.Add("aa:bb:cc:dd:ee:ff", struct{}{})
	if err != nil {
		t.Fatalf("Failed to add MAC: %v", err)
	}

	// Parse uppercase MAC
	upperMAC, err := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	if err != nil {
		t.Fatalf("Failed to parse uppercase MAC: %v", err)
	}

	// Should match
	if !m.Match(upperMAC) {
		t.Error("Uppercase MAC should match lowercase stored MAC")
	}

	// Test mixed case
	mixedMAC, err := net.ParseMAC("Aa:Bb:Cc:Dd:Ee:Ff")
	if err != nil {
		t.Fatalf("Failed to parse mixed MAC: %v", err)
	}

	if !m.Match(mixedMAC) {
		t.Error("Mixed case MAC should match")
	}

	// Length should be 1
	if m.Len() != 1 {
		t.Errorf("Expected length 1, got %d", m.Len())
	}
}