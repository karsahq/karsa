package types

import (
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/msgservice"
)

// RegisterLegacyAminoCodec registers the module's concrete types on the amino codec.
// The module only uses protobuf encoding, so this is a no-op.
func RegisterLegacyAminoCodec(_ *codec.LegacyAmino) {}

// RegisterInterfaces registers the module's message implementations.
func RegisterInterfaces(registry codectypes.InterfaceRegistry) {
	registry.RegisterImplementations(
		(*sdk.Msg)(nil),
		&MsgCreatePool{},
		&MsgAddLiquidity{},
		&MsgRemoveLiquidity{},
		&MsgSwapExactIn{},
		&MsgSwapExactOut{},
		&MsgSetPoolStatus{},
		&MsgDonatePool{},
		&MsgCheckPool{},
		&MsgUpdateParams{},
	)

	msgservice.RegisterMsgServiceDesc(registry, &_Msg_serviceDesc)
}
