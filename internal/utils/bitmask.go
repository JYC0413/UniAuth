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

// MaskToHex 将 BigInt 转为 Hex String
func MaskToHex(mask *big.Int) string {
	return mask.Text(16)
}

// CalculateMask 计算权限掩码
func CalculateMask(indices []int16) *big.Int {
	mask := new(big.Int)
	one := big.NewInt(1)
	for _, idx := range indices {
		if idx >= 0 {
			bit := new(big.Int).Lsh(one, uint(idx))
			mask.Or(mask, bit)
		}
	}
	return mask
}
