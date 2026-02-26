package utils

import (
	"fmt"
	"strconv"
	"strings"
)

/*
Given a ip address in form 192.168.53.40 returns in 11000000101010000011010100101000
*/
func ConvertIPToBinary(ip string) (string, error) {
	ips := strings.Split(ip, ".")
	var binaryIps [4]string

	for i := range 4 {
		num, err := strconv.ParseInt(ips[i], 10, 64)
		if err != nil {
			return "", fmt.Errorf("invalid ip value")
		}
		binaryIps[i] = fmt.Sprintf("%08v", strconv.FormatInt(num, 2))
	}

	return fmt.Sprintf("%s%s%s%s", binaryIps[0], binaryIps[1], binaryIps[2], binaryIps[3]), nil
}

/*
From a given binary string 1010101100111...(32 bits) gets the first cidr(int) bits
*/
func ExtractCIDRBits(binip string, cidr int) (string, error) {
	if len(binip) != 32 || cidr > 32 || cidr < 0 {
		return "", fmt.Errorf("invalid size of binary ip address")
	}

	return binip[:cidr], nil
}

func IsIpInCIDR(ip string, cidrBlock string) (bool, error) {
	vals := strings.Split(cidrBlock, "/")

	if len(vals) != 2 {
		panic("Invalid cidr format, format = xx.xx.xx.xx/xx")
	}

	binip, err := ConvertIPToBinary(vals[0])
	if err != nil {
		return false, err
	}

	cidr, err := strconv.Atoi(vals[1])
	if err != nil {
		return false, err
	}

	cidrBits, err := ExtractCIDRBits(binip, cidr)
	if err != nil {
		return false, err
	}

	binipCheck, err := ConvertIPToBinary(ip)
	if err != nil {
		return false, err
	}

	for i := 0; i < len(cidrBits); i++ {
		if binipCheck[i] != cidrBits[i] {
			return false, nil
		}
	}

	return true, nil
}

/*
Finds if the ip is trusted or not
*/
func IsIPTrusted(ip string) (bool, error) {
	// ! WARNING: CONFIG
	trustedNetwork := "172.28.0.0/16"
	return IsIpInCIDR(ip, trustedNetwork)
}
