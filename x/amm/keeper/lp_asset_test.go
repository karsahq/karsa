package keeper

import (
	"context"
	"strings"
	"testing"

	"github.com/karsahq/karsa/x/amm/types"

	erc20types "github.com/cosmos/evm/x/erc20/types"

	"github.com/ethereum/go-ethereum/common"

	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

type mockBankKeeper struct {
	metadata *banktypes.Metadata
}

func (m *mockBankKeeper) SendCoins(context.Context, sdk.AccAddress, sdk.AccAddress, sdk.Coins) error {
	return nil
}

func (m *mockBankKeeper) SendCoinsFromAccountToModule(context.Context, sdk.AccAddress, string, sdk.Coins) error {
	return nil
}

func (m *mockBankKeeper) SendCoinsFromModuleToAccount(context.Context, string, sdk.AccAddress, sdk.Coins) error {
	return nil
}

func (m *mockBankKeeper) MintCoins(context.Context, string, sdk.Coins) error { return nil }
func (m *mockBankKeeper) BurnCoins(context.Context, string, sdk.Coins) error { return nil }

func (m *mockBankKeeper) SpendableCoins(context.Context, sdk.AccAddress) sdk.Coins {
	return sdk.NewCoins()
}

func (m *mockBankKeeper) SetDenomMetaData(_ context.Context, metadata banktypes.Metadata) {
	m.metadata = &metadata
}

type mockErc20Keeper struct {
	tokenSet       bool
	dynamicEnabled bool
	registeredAddr common.Address
}

func (m *mockErc20Keeper) GetTokenPairID(sdk.Context, string) []byte { return nil }

func (m *mockErc20Keeper) GetTokenPair(sdk.Context, []byte) (erc20types.TokenPair, bool) {
	return erc20types.TokenPair{}, false
}

func (m *mockErc20Keeper) IsDenomRegistered(sdk.Context, string) bool { return false }

func (m *mockErc20Keeper) IsERC20Registered(sdk.Context, common.Address) bool { return false }

func (m *mockErc20Keeper) SetToken(_ sdk.Context, pair erc20types.TokenPair) error {
	m.tokenSet = true
	return nil
}

func (m *mockErc20Keeper) EnableDynamicPrecompile(_ sdk.Context, address common.Address) error {
	m.dynamicEnabled = true
	m.registeredAddr = address
	return nil
}

func TestRegisterLPAsset(t *testing.T) {
	bankKeeper := &mockBankKeeper{}
	erc20Keeper := &mockErc20Keeper{}

	k := Keeper{bankKeeper: bankKeeper, erc20Keeper: erc20Keeper}

	addr, err := k.registerLPAsset(sdk.Context{}, 7, "amm/pool/7")
	if err != nil {
		t.Fatalf("registerLPAsset returned error: %s", err)
	}

	expected := types.LPAssetAddress("amm/pool/7")
	if addr != strings.ToLower(expected.Hex()) {
		t.Fatalf("address = %s, want %s", addr, strings.ToLower(expected.Hex()))
	}
	if !erc20Keeper.tokenSet {
		t.Fatal("token pair was not registered")
	}
	if !erc20Keeper.dynamicEnabled {
		t.Fatal("dynamic precompile was not enabled")
	}
	if erc20Keeper.registeredAddr != expected {
		t.Fatalf("enabled address = %s, want %s", erc20Keeper.registeredAddr, expected)
	}

	metadata := bankKeeper.metadata
	if metadata == nil {
		t.Fatal("bank metadata was not set")
	}
	if metadata.Base != "amm/pool/7" {
		t.Fatalf("base = %s", metadata.Base)
	}
	if metadata.Symbol != "KLP-7" {
		t.Fatalf("symbol = %s", metadata.Symbol)
	}
	if len(metadata.DenomUnits) != 2 {
		t.Fatalf("denom units = %d, want 2", len(metadata.DenomUnits))
	}
	if metadata.DenomUnits[0].Exponent != 0 {
		t.Fatalf("base exponent = %d, want 0", metadata.DenomUnits[0].Exponent)
	}
	if metadata.DenomUnits[1].Exponent != 18 {
		t.Fatalf("display exponent = %d, want 18", metadata.DenomUnits[1].Exponent)
	}
	if metadata.DenomUnits[1].Denom != metadata.Display {
		t.Fatalf("display %s has no matching denom unit", metadata.Display)
	}
}
