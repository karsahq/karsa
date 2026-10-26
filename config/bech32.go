package config

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/evm/crypto/hd"
)

const (
	// Bech32Prefix defines the Bech32 prefix used for accounts on the Karsa blockchain.
	Bech32Prefix = "karsa"
	// Bech32PrefixAccAddr defines the Bech32 prefix of an account's address.
	Bech32PrefixAccAddr = Bech32Prefix
	// Bech32PrefixAccPub defines the Bech32 prefix of an account's public key.
	Bech32PrefixAccPub = Bech32Prefix + sdk.PrefixPublic
	// Bech32PrefixValAddr defines the Bech32 prefix of a validator's operator address.
	Bech32PrefixValAddr = Bech32Prefix + sdk.PrefixValidator + sdk.PrefixOperator
	// Bech32PrefixValPub defines the Bech32 prefix of a validator's operator public key.
	Bech32PrefixValPub = Bech32Prefix + sdk.PrefixValidator + sdk.PrefixOperator + sdk.PrefixPublic
	// Bech32PrefixConsAddr defines the Bech32 prefix of a consensus node address.
	Bech32PrefixConsAddr = Bech32Prefix + sdk.PrefixValidator + sdk.PrefixConsensus
	// Bech32PrefixConsPub defines the Bech32 prefix of a consensus node public key.
	Bech32PrefixConsPub = Bech32Prefix + sdk.PrefixValidator + sdk.PrefixConsensus + sdk.PrefixPublic
)

// init sets the Bech32 prefixes as early as possible, before any of this
// package's importers can stringify an address.
//
// It also disables the SDK's global address string cache: the SDK caches the
// result of AccAddress.String() per address bytes, and dependency initializers
// may stringify module addresses before these custom prefixes are applied. Such
// entries would keep returning "cosmos"-prefixed strings for the lifetime of
// the process, so lookups always re-encode with the configured prefix instead.
func init() {
	SetBech32Prefixes(sdk.GetConfig())
	sdk.SetAddrCacheEnabled(false)
}

// SetBech32Prefixes sets the global prefixes to be used when serializing addresses and public keys to Bech32 strings.
func SetBech32Prefixes(config *sdk.Config) {
	config.SetBech32PrefixForAccount(Bech32PrefixAccAddr, Bech32PrefixAccPub)
	config.SetBech32PrefixForValidator(Bech32PrefixValAddr, Bech32PrefixValPub)
	config.SetBech32PrefixForConsensusNode(Bech32PrefixConsAddr, Bech32PrefixConsPub)
}

// SetBip44CoinType sets the global coin type to be used in hierarchical deterministic wallets.
func SetBip44CoinType(config *sdk.Config) {
	config.SetCoinType(hd.Bip44CoinType)
	config.SetPurpose(sdk.Purpose)               // Shared
	config.SetFullFundraiserPath(hd.BIP44HDPath) //nolint: staticcheck
}
