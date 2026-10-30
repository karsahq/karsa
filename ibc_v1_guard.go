package karsa

import (
	errorsmod "cosmossdk.io/errors"

	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	ibctransfertypes "github.com/cosmos/ibc-go/v11/modules/apps/transfer/types"
)

// rejectIBCV1Tx rejects channel-based ICS20 transfers at the ante layer. Karsa
// only exposes IBC v2; the empty v1 router already prevents channel handshakes,
// but rejecting MsgTransfer makes the policy explicit and avoids a confusing
// "no route" failure after fees are processed.
func rejectIBCV1Tx(tx sdk.Tx) error {
	for _, msg := range tx.GetMsgs() {
		if _, ok := msg.(*ibctransfertypes.MsgTransfer); ok {
			return errorsmod.Wrap(
				sdkerrors.ErrInvalidRequest,
				"IBC v1 transfers are disabled on Karsa; use IBC v2",
			)
		}
	}

	return nil
}
