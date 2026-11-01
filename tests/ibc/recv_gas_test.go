package ibc

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"

	"github.com/cosmos/evm/testutil"
	testutiltypes "github.com/cosmos/evm/testutil/types"
	"github.com/cosmos/evm/x/erc20/types"
	ibctestutil "github.com/cosmos/evm/x/ibc/callbacks/testutil"
	callbacktypes "github.com/cosmos/evm/x/ibc/callbacks/types"
	transfertypes "github.com/cosmos/ibc-go/v11/modules/apps/transfer/types"
	channeltypesv2 "github.com/cosmos/ibc-go/v11/modules/core/04-channel/v2/types"
	ibctesting "github.com/cosmos/ibc-go/v11/testing"
	"github.com/karsahq/karsa"
)

// Gas budget the relayer in karsahq/ibc-ferry assigns to one relay message and
// the cap it assumes for a single EVM callback. They are duplicated here on
// purpose: if a change makes a receive cost more than these, the relayer
// defaults silently stop working, so this test should fail first.
const (
	relayerSingleMessageGas = 700_000
	relayerMaxCallbackGas   = 1_000_000
)

// TestRecvGasStaysWithinRelayerLimits measures the keeper-level gas a receive
// costs with and without a destination callback. The numbers are a lower bound
// on the transaction cost, because the ante handler, signature verification,
// and event handling are added on top.
func (suite *MiddlewareV2TestSuite) TestRecvGasStaysWithinRelayerLimits() {
	plain := suite.measureRecvGas(false)
	withCallback := suite.measureRecvGas(true)

	suite.T().Logf("recv gas: plain=%d withCallback=%d", plain, withCallback)

	suite.Require().Less(plain, int64(relayerSingleMessageGas),
		"a plain receive must fit the relayer single-message gas limit")
	suite.Require().Less(withCallback, int64(relayerSingleMessageGas+relayerMaxCallbackGas),
		"a receive with the largest allowed callback must fit the relayer reservation")
	suite.Require().LessOrEqual(withCallback-plain, int64(relayerMaxCallbackGas),
		"a callback must not cost more than the cap the relayer reserves for it")
}

func (suite *MiddlewareV2TestSuite) measureRecvGas(withCallback bool) int64 {
	contractData, err := ibctestutil.LoadCounterWithCallbacksContract()
	suite.Require().NoError(err)
	counterABI := contractData.ABI

	suite.SetupTest()

	karsaApp := suite.evmChainA.App.(*karsa.App)
	ctx := suite.evmChainA.GetContext()
	sourceSender := suite.chainB.SenderAccount.GetAddress()
	receiver := suite.evmChainA.SenderAccount.GetAddress()

	sourceClient := suite.pathBToA.EndpointB.ClientID
	destinationClient := suite.pathBToA.EndpointA.ClientID
	isolatedAddr := callbacktypes.GenerateIsolatedAddress(destinationClient, sourceSender.String())

	amount := ibctesting.DefaultCoinAmount
	packetData := transfertypes.NewFungibleTokenPacketData(
		testBondDenom, amount.String(), sourceSender.String(), isolatedAddr.String(), "",
	)
	data, err := transfertypes.UnmarshalPacketData(packetData.GetBytes(), transfertypes.V1, "")
	suite.Require().NoError(err)
	voucherDenom := testutil.GetVoucherDenomFromPacketData(data, transfertypes.PortID, sourceClient)
	voucher, err := types.NewTokenPairSTRv2(voucherDenom)
	suite.Require().NoError(err)

	contractAddr, err := DeployContract(suite.T(), suite.evmChainA, testutiltypes.ContractDeploymentData{
		Contract: contractData,
	})
	suite.Require().NoError(err)

	if withCallback {
		packed, err := counterABI.Pack("add", voucher.GetERC20Contract(), amount.BigInt())
		suite.Require().NoError(err)
		packetData.Memo = fmt.Sprintf(
			`{"dest_callback":{"address":"%s","gas_limit":"%d","calldata":"%x"}}`,
			common.HexToAddress(contractAddr.Hex()), relayerMaxCallbackGas, packed,
		)
	}

	payload := channeltypesv2.NewPayload(
		transfertypes.PortID, transfertypes.PortID,
		transfertypes.V1, transfertypes.EncodingJSON,
		packetData.GetBytes(),
	)

	router := karsaApp.GetIBCKeeper().ChannelKeeperV2.Router.Route(ibctesting.TransferPort)
	before := ctx.GasMeter().GasConsumed()
	result := router.OnRecvPacket(ctx, sourceClient, destinationClient, 1, payload, receiver)
	after := ctx.GasMeter().GasConsumed()

	suite.Require().Equal(channeltypesv2.PacketStatus_Success, result.Status)
	return int64(after - before)
}
