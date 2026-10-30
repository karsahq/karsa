package types

// Event types emitted by the module.
const (
	EventTypeCreatePool      = "create_pool"
	EventTypeAddLiquidity    = "add_liquidity"
	EventTypeRemoveLiquidity = "remove_liquidity"
	EventTypeSwap            = "swap"
	EventTypePoolStatus      = "pool_status"
	EventTypeDonate          = "donate_pool"
	EventTypeConvertIn       = "convert_in"
	EventTypeConvertOut      = "convert_out"
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
	AttributeKeyStatus        = "status"
	AttributeKeyAsset         = "asset"
	AttributeKeyDenom         = "denom"
	AttributeKeyContract      = "contract"
	AttributeKeyAmount        = "amount"
)
