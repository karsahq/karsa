// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IAmm
/// @notice Interface of the Karsa AMM precompile.
/// @dev The precompile lives at a fixed address: 0x0000000000000000000000000000000000000900
///      Addresses in `path` are ERC20 token pairs (bank-backed precompiles or
///      contract tokens registered with x/erc20).
interface IAmm {
    /// @notice Returns the expected output amount for an exact-input swap.
    /// @param path Ordered list of assets, length >= 2 (e.g. [MOMO, USDT, akra]).
    /// @param amountIn Amount of path[0] to swap.
    /// @return amountOut Expected amount of the last asset in `path`.
    function quote(address[] calldata path, uint256 amountIn)
        external
        view
        returns (uint256 amountOut);

    /// @notice Returns the reserves and configuration of a pool.
    /// @param assetA One side of the pair (order does not matter).
    /// @param assetB The other side of the pair.
    /// @return id Pool identifier.
    /// @return reserveA Reserve of assetA, in its own base units.
    /// @return reserveB Reserve of assetB, in its own base units.
    /// @return totalShares Total LP shares, including the permanently locked share.
    /// @return feeBps Pool fee in basis points (30 = 0.30%).
    /// @return poolType 0 = constant product, 1 = stableswap.
    /// @return amplification Amplification coefficient A (stableswap only, 0 otherwise).
    /// @return scalingFactorA Factor normalising assetA to 18 decimals (0 means 1).
    /// @return scalingFactorB Factor normalising assetB to 18 decimals (0 means 1).
    function getPool(address assetA, address assetB)
        external
        view
        returns (
            uint64 id,
            uint256 reserveA,
            uint256 reserveB,
            uint256 totalShares,
            uint32 feeBps,
            uint8 poolType,
            uint64 amplification,
            uint256 scalingFactorA,
            uint256 scalingFactorB
        );

    /// @notice Swaps an exact amount of path[0] for the last asset in `path`.
    /// @dev The caller must hold `amountIn` of path[0]; the module moves those
    ///      tokens on the caller's behalf. `integratorFeeBps` is capped by the
    ///      module params (1% by default) and is paid to `integrator` in the
    ///      input token. Pass `receiver = address(0)` to receive at the caller.
    /// @param path Ordered list of assets, length >= 2.
    /// @param amountIn Amount of path[0] to swap.
    /// @param minOut Minimum acceptable amount of the last asset (slippage guard).
    /// @param receiver Recipient of the output, or address(0) for the caller.
    /// @param integrator Address that receives the extra fee, or address(0).
    /// @param integratorFeeBps Extra fee in basis points, charged on top of the pool fee.
    /// @return amountOut Amount of the last asset sent to `receiver`.
    /// @return integratorFee Fee paid to `integrator`, in the input token.
    function swapExactIn(
        address[] calldata path,
        uint256 amountIn,
        uint256 minOut,
        address receiver,
        address integrator,
        uint256 integratorFeeBps
    ) external returns (uint256 amountOut, uint256 integratorFee);
}
