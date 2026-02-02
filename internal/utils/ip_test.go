package utils_test

import (
	"nids/internal/trie"
	"nids/internal/utils"
	"testing"
)

func TestConvertIPToBinary(t *testing.T) {
	res, _ := utils.ConvertIPToBinary("192.168.53.40")
	expected := "11000000101010000011010100101000"

	if res != expected {
		t.Errorf("ConvertIPToBinary: expected %v, got %v", expected, res)
	}
}

func TestExtractCIDRBits(t *testing.T) {
	binip := "11000000101010000011010100101000"
	cidr := 32
	res, _ := utils.ExtractCIDRBits(binip, cidr)
	expected := binip[:cidr]

	if res != expected && len(res) != cidr {
		t.Errorf("ExtractCIDRBits: expected %v, got %v", expected, res)
	}
}

func TestIsIPBlockPresent(t *testing.T) {
	tr := trie.CreateTrie()

	_ = tr.InsertIP("192.168.1.0", 24)
	_ = tr.InsertIP("10.0.0.1", 32)

	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{
			name:     "Exact match for single IP",
			ip:       "10.0.0.1",
			expected: true,
		},
		{
			name:     "IP inside blocked subnet prefix",
			ip:       "192.168.1.55", // Starts with the 24-bit blocked prefix
			expected: true,
		},
		{
			name:     "IP outside blocked subnet",
			ip:       "192.168.2.1", // Third octet is different
			expected: false,
		},
		{
			name:     "Completely unknown IP",
			ip:       "8.8.8.8",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tr.IsIPBlockPresent(tt.ip)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if got != tt.expected {
				t.Errorf("IsIPBlockPresent(%s) = %v; want %v", tt.ip, got, tt.expected)
			}
		})
	}
}
