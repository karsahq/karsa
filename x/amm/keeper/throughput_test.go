//go:build test

package keeper_test

import (
	"strings"
	"testing"
	"time"

	karsa "github.com/karsahq/karsa"
	ammtypes "github.com/karsahq/karsa/x/amm/types"

	erc20types "github.com/cosmos/evm/x/erc20/types"

	sdkmath "cosmossdk.io/math"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

const (
	// throughputBlockGas is the per-block gas limit we are evaluating.
	throughputBlockGas = 150_000_000
	// throughputBlockTime is the configured block cadence.
	throughputBlockTime = 1500 * time.Millisecond
)

// opResult captures the cost of one operation type.
type opResult struct {
	name    string
	ops     int
	elapsed time.Duration
	// measuredCosmosGas is what the Cosmos gas meter observed. It is zero for
	// keeper-level calls that do not charge the Cosmos meter, in which case
	// refGas (the reference gas figure) drives the projection.
	measuredCosmosGas uint64
	refGas            float64
}

func (r opResult) gasPerOp() float64 {
	if r.measuredCosmosGas > 0 {
		return float64(r.measuredCosmosGas) / float64(r.ops)
	}
	return r.refGas
}

func (r opResult) msPerOp() float64 {
	return float64(r.elapsed.Microseconds()) / 1000.0 / float64(r.ops)
}

func (r opResult) report(t *testing.T) {
	t.Helper()

	if r.ops == 0 {
		return
	}

	gasPerOp := r.gasPerOp()
	msPerOp := r.msPerOp()

	opsForLimit := float64(throughputBlockGas) / gasPerOp
	msForLimit := opsForLimit * msPerOp

	source := "measured"
	if r.measuredCosmosGas == 0 {
		source = "reference"
	}

	t.Logf(
		"%-22s ops=%4d  gas/op=%8.0f (%s)  %6.2f ms/op  -> %5.0f ops/block  %6.0f ms for 150M gas  (budget %.0f ms)",
		r.name, r.ops, gasPerOp, source, msPerOp, opsForLimit, msForLimit,
		float64(throughputBlockTime.Milliseconds()),
	)
}

// measure runs fn ops times, each with a fresh gas meter, and reports timing.
func measure(t *testing.T, name string, ops int, refGas float64, baseCtx sdk.Context, run func(ctx sdk.Context, i int) error) opResult {
	t.Helper()

	for i := 0; i < 5; i++ {
		require.NoError(t, run(withGasMeter(baseCtx), i), name)
	}

	var totalGas uint64
	start := time.Now()

	for i := 0; i < ops; i++ {
		gctx := withGasMeter(baseCtx)
		require.NoError(t, run(gctx, i), name)
		totalGas += gctx.GasMeter().GasConsumed()
	}

	return opResult{
		name:              name,
		ops:               ops,
		elapsed:           time.Since(start),
		measuredCosmosGas: totalGas,
		refGas:            refGas,
	}
}

func withGasMeter(ctx sdk.Context) sdk.Context {
	return ctx.WithGasMeter(storetypes.NewInfiniteGasMeter())
}

// fundNative mints the native denom to the given account.
func fundNative(t *testing.T, app *karsa.App, ctx sdk.Context, addr sdk.AccAddress, amount sdkmath.Int) {
	t.Helper()

	coins := sdk.NewCoins(sdk.NewCoin(karsaNativeDenom(), amount))
	require.NoError(t, app.BankKeeper.MintCoins(ctx, ammtypes.ModuleName, coins))
	require.NoError(t, app.BankKeeper.SendCoinsFromModuleToAccount(ctx, ammtypes.ModuleName, addr, coins))
}

// TestThroughput projects per-block execution time for the AMM hot paths.
func TestThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("throughput measurement skipped in -short mode")
	}

	akraAsset := akraERC20().Hex()

	t.Run("bank_swap", func(t *testing.T) {
		app, ctx := newTestApp(t)
		registerTestUSDCPair(t, app, ctx)

		sender := sdk.AccAddress(common.HexToAddress("0x00000000000000000000000000000000000000AA").Bytes())
		fundTestDenoms(t, app, ctx, sender, sdkmath.NewIntWithDecimal(10_000_000, 18))

		_, _, err := app.AmmKeeper.CreatePool(
			ctx, sender, akraAsset, testUSDCPair.Hex(), 30,
			sdkmath.NewInt(10_000_000), sdkmath.NewInt(10_000_000),
		)
		require.NoError(t, err)

		pathAB := []string{akraAsset, testUSDCPair.Hex()}
		pathBA := []string{testUSDCPair.Hex(), akraAsset}
		amountIn := sdkmath.NewInt(1_000)

		res := measure(t, "bank<->bank swap", 500, 58_000, ctx, func(gctx sdk.Context, i int) error {
			path := pathAB
			if i%2 == 1 {
				path = pathBA
			}
			_, _, err := app.AmmKeeper.Swap(gctx, sender, sender, path, amountIn, sdkmath.NewInt(1), nil, 0)
			return err
		})
		res.report(t)
	})

	t.Run("external_swap", func(t *testing.T) {
		app, ctx := newTestApp(t)
		deployer := common.HexToAddress("0x00000000000000000000000000000000000000EE")
		sender := sdk.AccAddress(deployer.Bytes())

		fundNative(t, app, ctx, sender, sdkmath.NewIntWithDecimal(10_000_000, 18))

		token := deployTestERC20(t, app, ctx, deployer, "Momo", "MOMO", 18)
		mintTestERC20(t, app, ctx, token, deployer, sdkmath.NewInt(10_000_000))
		require.NoError(t, app.Erc20Keeper.SetToken(ctx, erc20types.NewTokenPair(
			token, "erc20:"+strings.ToLower(token.Hex()), erc20types.OWNER_EXTERNAL,
		)))

		_, _, err := app.AmmKeeper.CreatePool(
			ctx, sender, akraAsset, token.Hex(), 30,
			sdkmath.NewInt(1_000_000), sdkmath.NewInt(1_000_000),
		)
		require.NoError(t, err)

		pathAB := []string{akraAsset, token.Hex()}
		pathBA := []string{token.Hex(), akraAsset}
		amountIn := sdkmath.NewInt(1_000)

		res := measure(t, "akra<->erc20 swap", 200, 380_000, ctx, func(gctx sdk.Context, i int) error {
			path := pathAB
			if i%2 == 1 {
				path = pathBA
			}
			_, _, err := app.AmmKeeper.Swap(gctx, sender, sender, path, amountIn, sdkmath.NewInt(1), nil, 0)
			return err
		})
		res.report(t)
	})

	t.Run("external_external_swap", func(t *testing.T) {
		app, ctx := newTestApp(t)
		deployer := common.HexToAddress("0x00000000000000000000000000000000000000EE")
		sender := sdk.AccAddress(deployer.Bytes())

		fundNative(t, app, ctx, sender, sdkmath.NewIntWithDecimal(10_000_000, 18))

		tokenA := deployTestERC20(t, app, ctx, deployer, "Momo", "MOMO", 18)
		tokenB := deployTestERC20(t, app, ctx, deployer, "Mimi", "MIMI", 18)
		mintTestERC20(t, app, ctx, tokenA, deployer, sdkmath.NewInt(10_000_000))
		mintTestERC20(t, app, ctx, tokenB, deployer, sdkmath.NewInt(10_000_000))

		for _, tok := range []common.Address{tokenA, tokenB} {
			require.NoError(t, app.Erc20Keeper.SetToken(ctx, erc20types.NewTokenPair(
				tok, "erc20:"+strings.ToLower(tok.Hex()), erc20types.OWNER_EXTERNAL,
			)))
		}

		_, _, err := app.AmmKeeper.CreatePool(
			ctx, sender, tokenA.Hex(), tokenB.Hex(), 30,
			sdkmath.NewInt(1_000_000), sdkmath.NewInt(1_000_000),
		)
		require.NoError(t, err)

		pathAB := []string{tokenA.Hex(), tokenB.Hex()}
		pathBA := []string{tokenB.Hex(), tokenA.Hex()}
		amountIn := sdkmath.NewInt(1_000)

		res := measure(t, "erc20<->erc20 swap", 200, 640_000, ctx, func(gctx sdk.Context, i int) error {
			path := pathAB
			if i%2 == 1 {
				path = pathBA
			}
			_, _, err := app.AmmKeeper.Swap(gctx, sender, sender, path, amountIn, sdkmath.NewInt(1), nil, 0)
			return err
		})
		res.report(t)
	})

	t.Run("bank_transfer", func(t *testing.T) {
		app, ctx := newTestApp(t)
		sender := sdk.AccAddress(common.HexToAddress("0x00000000000000000000000000000000000000AA").Bytes())
		receiver := sdk.AccAddress(common.HexToAddress("0x00000000000000000000000000000000000000BB").Bytes())

		fundNative(t, app, ctx, sender, sdkmath.NewIntWithDecimal(100_000_000, 18))

		coins := sdk.NewCoins(sdk.NewCoin(karsaNativeDenom(), sdkmath.NewInt(1_000)))

		res := measure(t, "bank transfer", 2000, 70_000, ctx, func(gctx sdk.Context, _ int) error {
			return app.BankKeeper.SendCoins(gctx, sender, receiver, coins)
		})
		res.report(t)
	})

	t.Run("signature_recovery", func(t *testing.T) {
		// Real blocks pay secp256k1 recovery per tx in the ante handler; the
		// keeper-level timings above do not include it.
		key, err := crypto.GenerateKey()
		require.NoError(t, err)

		hash := crypto.Keccak256([]byte("karsa throughput benchmark"))
		sig, err := crypto.Sign(hash, key)
		require.NoError(t, err)

		for i := 0; i < 10; i++ {
			_, err := crypto.Ecrecover(hash, sig)
			require.NoError(t, err)
		}

		const n = 1000
		start := time.Now()
		for i := 0; i < n; i++ {
			_, err := crypto.Ecrecover(hash, sig)
			require.NoError(t, err)
		}
		perTx := float64(time.Since(start).Microseconds()) / 1000.0 / float64(n)

		t.Logf("%-22s %6.3f ms/tx  -> %5.0f ms for 234 swaps/block  (budget %.0f ms)",
			"secp256k1 recover", perTx, perTx*234, float64(throughputBlockTime.Milliseconds()))
	})

	t.Run("commit", func(t *testing.T) {
		app, ctx := newTestApp(t)
		sender := sdk.AccAddress(common.HexToAddress("0x00000000000000000000000000000000000000AA").Bytes())
		receiver := sdk.AccAddress(common.HexToAddress("0x00000000000000000000000000000000000000BB").Bytes())

		fundNative(t, app, ctx, sender, sdkmath.NewIntWithDecimal(1_000_000, 18))

		coins := sdk.NewCoins(sdk.NewCoin(karsaNativeDenom(), sdkmath.NewInt(1_000)))
		for i := 0; i < 2000; i++ {
			require.NoError(t, app.BankKeeper.SendCoins(ctx, sender, receiver, coins))
		}

		start := time.Now()
		_, err := app.Commit()
		require.NoError(t, err)
		t.Logf("%-22s 2000 writes -> commit %6.1f ms", "state commit", float64(time.Since(start).Microseconds())/1000)
	})
}
