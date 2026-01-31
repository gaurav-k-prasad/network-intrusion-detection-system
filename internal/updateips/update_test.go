package updateips_test

import (
	"fmt"
	"nids/internal/updateips"
	"testing"
)

func TestIPTrie(t *testing.T) {
	tr, err := updateips.GetIpTrie("../../blacklist.txt")

	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(tr.N)

	test := []struct {
		ip       string
		expected bool
	}{
		{
			"0.0.0.0",
			true,
		},
		{
			"0.5.3.182",
			true,
		},
		{
			"24.233.0.0",
			true,
		},
		{
			"38.192.199.44",
			true,
		},
		{
			"209.0.32.44",
			false,
		},
	}

	for _, tt := range test {
		t.Run(tt.ip, func(t *testing.T) {
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
