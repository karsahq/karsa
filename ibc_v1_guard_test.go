package karsa

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	sdk "github.com/cosmos/cosmos-sdk/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	ibctransfertypes "github.com/cosmos/ibc-go/v11/modules/apps/transfer/types"
)

type guardTestTx struct {
	msgs []sdk.Msg
}

func (t guardTestTx) GetMsgs() []sdk.Msg {
	return t.msgs
}

func (t guardTestTx) GetMsgsV2() ([]proto.Message, error) {
	return nil, nil
}

func TestRejectIBCV1Tx(t *testing.T) {
	err := rejectIBCV1Tx(guardTestTx{msgs: []sdk.Msg{&ibctransfertypes.MsgTransfer{}}})
	require.ErrorContains(t, err, "IBC v1 transfers are disabled")

	err = rejectIBCV1Tx(guardTestTx{msgs: []sdk.Msg{&banktypes.MsgSend{}}})
	require.NoError(t, err)
}
