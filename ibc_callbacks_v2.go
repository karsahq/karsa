package karsa

import (
	channeltypesv2 "github.com/cosmos/ibc-go/v11/modules/core/04-channel/v2/types"
	ibcapi "github.com/cosmos/ibc-go/v11/modules/core/api"
)

// packetUnmarshalerV2 lets the callbacks middleware see the transfer module's
// packet unmarshaler while the packet still flows through the ERC20 middleware.
// The ERC20 v2 middleware implements IBCModule but not PacketDataUnmarshaler,
// and callbacks v2 requires both.
type packetUnmarshalerV2 struct {
	ibcapi.IBCModule
	unmarshaler ibcapi.PacketDataUnmarshaler
}

func (p packetUnmarshalerV2) UnmarshalPacketData(payload channeltypesv2.Payload) (any, error) {
	return p.unmarshaler.UnmarshalPacketData(payload)
}
