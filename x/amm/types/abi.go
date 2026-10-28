package types

import (
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

// Minimal ERC20 ABI: only the methods the module needs.
const erc20ABIJSON = `[
  {"constant":true,"inputs":[{"name":"account","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},
  {"constant":false,"inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},
  {"constant":true,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"}
]`

// ERC20ABI is the parsed minimal ERC20 ABI used for external token custody.
var ERC20ABI abi.ABI

func init() {
	parsed, err := abi.JSON(strings.NewReader(erc20ABIJSON))
	if err != nil {
		panic("failed to parse erc20 abi: " + err.Error())
	}
	ERC20ABI = parsed
}
