package types

// Event types emitted by the module.
const (
	EventTypeCreatePool      = "create_pool"
	EventTypeAddLiquidity    = "add_liquidity"
	EventTypeRemoveLiquidity = "remove_liquidity"
	EventTypeSwap            = "swap"
)

// Attribute keys used by the module events.
const (
	AttributeKeyPoolID        = "pool_id"
	AttributeKeyAssetA        = "asset_a"
	AttributeKeyAssetB        = "asset_b"
	AttributeKeyAmountA       = "amount_a"
	AttributeKeyAmountB       = "amount_b"
	AttributeKeyShares        = "shares"
	AttributeKeySender        = "sender"
	AttributeKeyReceiver      = "receiver"
	AttributeKeyAmountIn      = "amount_in"
	AttributeKeyAmountOut     = "amount_out"
	AttributeKeyIntegrator    = "integrator"
	AttributeKeyIntegratorFee = "integrator_fee"
)
