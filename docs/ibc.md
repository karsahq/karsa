# IBC

Karsa is **IBC v2 only**. The channel-based ICS20 v1 transfer route is not
registered.

## Wiring

```
ChannelKeeperV2 router
  └── callbacks v2 middleware
        └── erc20 v2 middleware
              └── transfer v2
```

The v1 `PortKeeper` router is deliberately left empty. A v1 channel handshake
for the transfer port therefore fails instead of silently falling back to v1.
`MsgTransfer` v1 is also rejected in the ante handler, so a channel-based send
fails explicitly before fees are processed. IBC core clients remain available
because IBC v2 uses them too.

## EVM callbacks

Callbacks are available on v2. A packet memo may request:

- `dest_callback`: call an EVM contract atomically after the voucher is
  received. The callback keeper approves the voucher to the contract and
  requires the contract to pull the tokens; otherwise the packet fails.
- `src_callback`: call the sending contract on acknowledgement or timeout.

The gas cap is `1_000_000`. The v2 stack uses an adapter around the ERC20
middleware because `erc20/v2` implements `IBCModule` but not
`PacketDataUnmarshaler`, which callbacks v2 requires.

## Tests

`tests/ibc` runs Karsa-to-Karsa IBC v2 tests. They cover send, receive,
acknowledgement, timeout, ERC20 conversion, the ICS20 precompile, and both the
receive-side and source-side EVM callbacks (ack and timeout).

## Minimal live relayer

The experimental one-way relayer and its Karsa/Gaia harnesses now live in
[`karsahq/ibc-ferry`](https://github.com/karsahq/ibc-ferry), on the
`prototype/python` branch. The `main` branch is reserved for the Go port.

Peers must support IBC v2 to connect. Do not expect channel-based Cosmos chains
to interoperate with Karsa.
