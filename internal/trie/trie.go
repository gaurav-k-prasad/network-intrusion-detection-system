/*
Implements Trie data structure required for IP address matching
*/
package trie

import (
	"fmt"
	"nids/internal/utils"
)

/*
# Root level Trie data structure
  - Root - Root tire node
  - N - Total IPs in Trie
*/
type Trie struct {
	Root *TrieNode
	N    int
}

/*
# TrieNodes keep all the data required for Trie
  - Zero - binary zero subtree
  - One - binary one subtree
  - IsTerminal - Set if it's the last node/terminal of a ip address
*/
type TrieNode struct {
	Zero       *TrieNode
	One        *TrieNode
	IsTerminal bool
}

/*
Creates a Trie Data structure
*/
func CreateTrie() *Trie {
	trie := &Trie{
		Root: nil,
		N:    0,
	}

	return trie
}

func CreateTrieNode() *TrieNode {
	return &TrieNode{
		Zero:       nil,
		One:        nil,
		IsTerminal: false,
	}
}

/*
Inserts ip address to the trie data structure
  - ip: Must be in base 10
  - cidr: cidr value for given ip
*/
func (t *Trie) InsertIP(ip string, cidr int) error {
	if ip == "" {
		return fmt.Errorf("no ip found")
	}

	binIP, err := utils.ConvertIPToBinary(ip)
	if err != nil {
		return err
	}

	val, err := utils.ExtractCIDRBits(binIP, cidr)
	if err != nil {
		return err
	}

	if t.Root == nil {
		t.Root = CreateTrieNode()
	}

	curr := t.Root
	for _, r := range val {
		if r == '0' {
			if curr.Zero == nil {
				curr.Zero = CreateTrieNode()
			}
			curr = curr.Zero
		} else {
			if curr.One == nil {
				curr.One = CreateTrieNode()
			}
			curr = curr.One
		}
	}

	curr.IsTerminal = true
	t.N += 1
	return nil
}

/*
Checks if the given ip address block present in trie
*/
func (t *Trie) IsIPBlockPresent(ip string) (bool, error) {
	val, err := utils.ConvertIPToBinary(ip)
	if err != nil {
		return false, err
	}

	curr := t.Root
	if curr == nil {
		return false, nil
	}

	// Iterate through the binary string
	for i := 0; i < len(val); i++ {
		if curr.IsTerminal {
			return true, nil
		}

		r := val[i]

		if r == '0' {
			curr = curr.Zero
		} else {
			curr = curr.One
		}

		if curr == nil {
			return false, nil
		}
	}

	return curr.IsTerminal, nil
}
