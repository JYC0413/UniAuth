package utils

import (
	"math/big"
)

// ParseMask 将 Hex String 转为 BigInt
func ParseMask(hexStr string) *big.Int {
	i := new(big.Int)
	i.SetString(hexStr, 16)
	return i
}

// MaskToHex 将 BigInt 转为 32位 Hex String
func MaskToHex(mask *big.Int) string {
	hex := mask.Text(16)
	// Pad with leading zeros to ensure 32 chars length if needed,
	// though PRD says char(32), usually we just store the hex string.
	// Let's ensure it fits the format if strictly required, but usually variable length is fine unless fixed width char(32) in DB.
	// For char(32) in DB, we might need padding.
	// Simple padding:
	for len(hex) < 32 {
		hex = "0" + hex
	}
	if len(hex) > 32 {
		// Should not happen for 128 bit, but just in case
		hex = hex[len(hex)-32:]
	}
	return hex
}

// CalculateMask 计算权限掩码
func CalculateMask(indices []int16) *big.Int {
	mask := new(big.Int)
	one := big.NewInt(1)
	for _, idx := range indices {
		if idx >= 0 && idx < 128 {
			bit := new(big.Int).Lsh(one, uint(idx))
			mask.Or(mask, bit)
		}
	}
	return mask
}
