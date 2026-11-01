# Karsa Native Token

A token that exposes an **ERC20 interface** but **does not deploy an ERC20
contract**. Balances live in the bank ledger; the ERC20 logic runs in a dynamic
precompile at a deterministic `0x` address.

Product message:

> Deploy an ERC20-compatible token without deploying an ERC20 contract.
> Native performance, standard EVM compatibility.

## 1. Position in the architecture

Karsa has two token issuance paths. Both are ERC20 from the user's perspective;
the difference is where balances live and where the logic runs.

| | **Native ERC20** (this document) | **Custom ERC20** |
|---|---|---|
| Balances | bank ledger | contract storage |
| `transfer` executed by | precompile (Go) | Solidity |
| `0x` address | module-created, deterministic from creator | `CREATE` (sender + nonce) |
| Custom transfer logic | not possible | unrestricted |
| Custom issuance logic | controller, through the minter precompile | unrestricted |
| AMM pool swap gas | ~55k | ~197k–340k |
| Native IBC | yes | no (requires a bridge) |
| Explorer source | none (precompile) | verified |
| Protocol fee on creation | optional, default 0 | none |
| Gas on creation | ~100k | ~700k–1.2M |

**Asset identity principle:** one address, one denom, one source of truth for
balances. The address is the identity; the denom is only the bank representation
of that address. A native token must not have a separately tradable ERC20
wrapper, and a custom ERC20 must not be registered as a native token.

## 2. The address comes first; the denom follows

Unlike `ibc/…` or `erc20:0x…` assets, a native token does **not** derive its
address from a denom. The order is reversed so the address is the primary
identity — exactly like an ERC20 on Ethereum.

```
address = sha256("karsa/native/" + lowercase(creator) + "/" + sequence)[12:]
denom   = "n:" + "0x" + lowercase(address)     // example: n:0x1a2b…ef12 (44 bytes)
```

`sequence` is the token number for that creator. Address derivation:

```
sequence = 0
while true:
    addr = sha256("karsa/native/" + lowercase(creator) + "/" + sequence)[12:]
    denom = "n:0x" + lowercase(addr)
    if denom already exists in the bank  -> sequence++, retry
    if addr is in the static precompile range (0x1..0x9ff) -> sequence++, retry
    if addr already has an account or contract -> sequence++, retry
    stop
```

Properties:

| Property | Consequence |
|---|---|
| Address is deterministic from `(creator, sequence)` | The creator can recompute its token without storing anything |
| Denom ↔ address mapping is **syntactic** | The denom can be computed from the address without reading state, and vice versa |
| `sequence` retry | Collisions never become a hard failure |
| Lowercase is required | `n:0xAbC` and `n:0xabc` are different denoms — always normalise |
| `n:` prefix is **permanent** | A protocol constant; changing it orphans every issued token |

Protocol constant:

```
NativeTokenDenomPrefix = "n:"
```

The 44-byte denom (same length as `erc20:0x…`) costs about 780 more gas to write
in a pool than a short symbol denom — roughly 1% of a swap, which is acceptable.

## 3. The symbol is not an identity

**Decision: symbols are not unique. There is no reservation, reclaim, or
adjudication.**

| Rule | Value |
|---|---|
| Symbol uniqueness | none — many tokens may use "MOMO" |
| Canonical symbol reservation | none |
| Reclaim / takeover | none, including by governance |
| Probation / dispute window | none |
| Symbol length | 3–12 characters, `[A-Za-z0-9]` |
| Mutable symbol | no (metadata is immutable in the MVP) |

### Why symbols are not exclusive

An exclusive name forces the protocol to answer questions it cannot answer well:
who owns `momo`, how to resolve disputes, and how to revoke a name without
breaking integrations. Every answer adds governance, disputes, and time windows —
for the sole purpose of saving gas in a pool.

Because the token identity is the **address**, the symbol does not need to be
unique. This is the Ethereum model: anyone may have a token named "USDC", and
trust comes from token lists, not from the name.

The accepted consequence: a UI may show two "MOMO" tokens with different
addresses. The resolution is the same as Ethereum — the address is the truth, and
the explorer shows a badge.

## 4. Decimals

- MVP: **18 decimals only.** There is no scaling between bank and EVM; one bank
  base unit equals one EVM base unit.
- `decimals()` on the precompile returns 18.
- Denoms with other decimals (for example, 6-decimal `uusdc`) **cannot** be
  created through this path. Use the existing `x/erc20` token-pair model for
  those assets.
- Maximum `totalSupply`: `2^256-1`, validated at mint time.

## 5. Ownership: a contract, not a key

There is no authority key and no mint/burn message. Supply can only move through
a contract.

```
CREATE (factory precompile; caller must be a contract)
   │
   ├─ controller = ""        -> supply is immutable forever
   └─ controller = 0xCtrl    -> only 0xCtrl can mint/burn
```

| Decision | Value |
|---|---|
| Creator | contract address, **immutable** |
| Controller | set at creation; `""` means immutable supply |
| Who may mint/burn | only `controller`, through the minter precompile |
| Change controller | **not available** in the MVP; immutable after creation |
| Renounce | **not available** in the MVP; an empty controller can only be chosen at creation |
| Metadata | immutable (MVP) |
| Pause / freeze / blacklist | **none** |
| Holder burn | none; only the controller may burn, and only from the controller's own balance |

Rationale: keys can be lost, stolen, or moved without a trace. A contract can be
audited, monitored, and constrained by its own code.

The cost: a bug in the controller permanently ends the supply policy. That is the
token owner's risk, not the protocol's.

`creator` and `controller` are separated deliberately: creator records who
created the token, controller records which contract may change supply. In the
MVP both are immutable. There is no path to replace or renounce the controller;
a token that needs controller rotation must wait for a new mechanism or use a
custom ERC20.

There is no pause/blacklist because transfer behaviour must remain standard.
Tokens that need freezing must use the custom ERC20 path.

## 6. Verification is the only trust signal

Because symbols are not unique, the only trust signal is the `verified` flag in
the registry, managed by governance and displayed as a badge by the explorer.

| State | Display |
|---|---|
| `verified = true` | verified badge; token appears in the main list |
| `verified = false` | marked unverified; still usable and poolable |

The rule that must never be broken: **never infer trust from a name or symbol.**
Explorers and UIs must show the address next to the symbol.

## 7. Messages

There are no Cosmos messages to create, mint, or burn tokens. That is a decision,
not an omission:

| Operation | Path |
|---|---|
| Create token | **factory** precompile (`0x…0901`) — contracts only |
| Mint / burn | **minter** precompile (`0x…0902`) — controller only |

A key can do neither. There is no governance switch to re-enable them; opening a
key-based path again would require a chain upgrade.

The remaining messages are governance-only:

```proto
MsgSetTokenVerified { authority, denom, verified }
MsgUpdateParams    { authority, params }
```

**Consequence for `creator`.** Because creation only happens through a contract,
`creator` is always a contract address, never a key. If everyone uses one shared
launcher, `creator` is the same for every token and human attribution only
appears in launcher events. If each project deploys its own contract, `creator`
is unique per token but each project pays the deploy cost.

The factory precompile rejects non-contract callers, so the rule cannot be
bypassed through an EOA.

The minter precompile only works for denoms whose `controller` is the caller, so
it cannot mint another token's denom.

Mint and burn emit EVM `Mint` / `Burn` logs from the minter precompile so EVM
indexers see supply changes without reading Cosmos events. The ERC20 precompile's
`totalSupply` changes in the bank ledger, so it does not emit `Transfer` for
mints/burns triggered outside itself.

## 8. Registry

```go
// x/nativetoken store (prefix -> content)
0x01 token/{denom}          -> Token{ Creator, Controller, Name, Symbol, Verified, CreatedAt }
0x05 list/{denom}           -> byte{}             // enumeration for queries and genesis
0x02 sequence/{creator}     -> uint64             // per creator, basis for address derivation
0x03 address/{0x…}          -> denom              // used by the minter precompile
0x04 params                 -> Params
```

- `Creator` and `Controller` are stored as lowercase `0x…` strings.
- `sequence/{creator}` **must** be included in genesis export: addresses are
  derived from it.
- `address/{0x…}` lets the minter precompile find the denom from the token
  address alone.

The registry **does not** enforce symbol uniqueness and does not store a symbol
index. Denom uniqueness is already guaranteed by `x/bank` and checks at creation.

## 9. AMM integration

A native token can be a pool side without conversion. At creation:

```go
erc20Keeper.SetToken(ctx, erc20types.NewTokenPair(address, denom, erc20types.OWNER_MODULE))
erc20Keeper.EnableDynamicPrecompile(ctx, address)
```

This is the same path as `registerTestPair` in the AMM tests, so `resolveAsset`
recognises the token as bank-backed (`IsNativeCoin() == true`) and
`moveIn`/`moveOut` become pure bank sends — no conversion, no escrow.

Pools only store `denom_a`/`denom_b` for bank-canonical sides. For a
direct-custody external ERC20, the denom fields are empty because the contract
address is the identity. This behaviour is already implemented in `x/amm`.

## 10. ERC20 precompile requirements

| Item | Requirement |
|---|---|
| `name()` `symbol()` `decimals()` | from registry/bank metadata |
| `totalSupply()` | bank denom supply |
| `balanceOf()` | bank balance |
| `transfer()` `transferFrom()` | move exactly `amount`, return `true` |
| `approve()` `allowance()` | standard; `max uint256` means unlimited (do not decrement) |
| `Transfer` event | every balance change, including mint/burn (zero address) |
| `Approval` event | every allowance change |
| Hooks / fees / pause | **none** |
| `permit` (EIP-2612) | **not supported in the MVP** |

### Blocked addresses

A transfer rejected by `config/permissions.go` **must**:

- return a clear error, and
- **not** emit a fake `Transfer` event.

## 11. Explorer integration

Blockscout detects tokens through `eth_getCode` and ERC20 calls (`eth_call`), then
follows balance changes through `eth_getLogs` and `eth_getTransactionReceipt`.
That RPC surface is **already tested in Karsa** through `tests/e2e/smoke.sh`; a
full Blockscout instance has not been run in CI because it needs
Postgres/Redis/Docker.

| Test | Status | Evidence |
|---|---|---|
| Token detection (`eth_getCode`) | **passes** | the precompile returns ERC20 bytecode |
| Metadata (`name`, `symbol`, `decimals`) | **passes** | values match bank metadata (`USDC`, 6) |
| Transfer events (`eth_getLogs`) | **passes** | the `Transfer` topic is found |
| Balance changes (`balanceOf`) | **passes** | the receiver balance changes after a transfer |
| Transaction receipt | **passes** | `status=0x1`, transfer log present |
| Mint/burn in the explorer | not tested | EVM logs exist; explorer indexing does not |
| Token holder list | not tested | needs the Blockscout indexer |
| `verified` badge | not implemented | needs registry → explorer integration |

**Metadata requirement.** The ERC20 precompile reads `name`/`symbol`/`decimals`
from bank metadata. A bank denom without metadata **reverts** on all three calls,
so Blockscout cannot display the token. Native Karsa tokens always write metadata
at creation; manually registered assets must do the same.

The next step is running a real Blockscout instance against a Karsa node and
verifying the holder list and badge. Until then, the promise "tokens
automatically appear in the explorer" must not be made.

Provide a reference `IERC20.sol` in the documentation for integrators, even
though there is no source to verify.

## 12. Other verification items

| Item | Why it matters |
|---|---|
| `decimals()` unit conversion | Wallets/UI must display the same number as the bank |
| Infinite approval | A wrong implementation drains allowances or fails to decrement |
| Approval race (`approve` 0 first) | Standard behaviour that tooling relies on |
| `transfer` return value | Must return `true`; do not mimic USDT's empty return |
| `IERC20` interaction from Solidity | Include `staticcall` for `balanceOf` |
| Precompile call determinism | No state may depend on local context |

## 13. Controller and phase 2

### `permit` (EIP-2612)

Not supported in the MVP. It adds nonces, signature validation, domain
separators, and a new attack surface. Document this explicitly so dApps do not
assume every ERC20-compatible token supports EIP-2612.

### Solidity controller (implemented)

A token created with a non-empty controller can be minted or burned only by that
contract. The token remains bank-backed and the controller does not hold balances
or intercept transfers.

```
Controller.sol ──mint/burn──► Minter precompile (0x…0902) ──► bank
```

- The minter precompile checks `controller[denom] == msg.sender`.
- The controller does **not** hold balances and does **not** touch transfers.
- The controller is fixed at token creation. There is no replacement or renounce
  path, and no key or governance path to take it over.
- The factory and minter precompiles are static at `0x…0901` and `0x…0902`, not
  per token. See `docs/precompiles.md` for the static precompile list.
- There is no SDK-provided Solidity template. Deploy your own controller and use
  reentrancy protection and a supply cap. The controller address is immutable.

## 14. Module parameters

| Param | Initial value | Notes |
|---|---|---|
| `creation_fee` | empty / **0** | `sdk.Coins`; purely anti-spam |
| `min_symbol_len` | 3 | metadata only |
| `max_symbol_len` | 12 | metadata only |
| `max_name_len` | 64 | |
| `max_initial_supply` | `2^256-1` | EVM representation limit |

There is no `creation_fee_denom`, refund, or `immutable_default` parameter in
the module. The creation fee is whatever `sdk.Coins` governance sets.

`creation_fee` no longer acts as a name price — no name is scarce. It only slows
down scripted mass creation.

## 15. Not part of this model

- decimals other than 18,
- pause, freeze, blacklist, fee-on-transfer, rebasing,
- ERC20 wrappers for native tokens,
- symbol uniqueness, name reservation, reclaim, probation,
- `permit` (phase 2),
- controller replacement / renounce.

## 16. Decision summary

| # | Decision |
|---|---|
| 1 | The address is the identity; `address = sha256("karsa/native/" + creator + "/" + sequence)[12:]` |
| 2 | `denom = "n:0x" + lowercase(address)`, 44 bytes, permanent prefix |
| 3 | Symbols are not unique; no reservation/reclaim/adjudication |
| 4 | `verified` is the only trust signal + explorer badge |
| 5 | `creation_fee` is optional (`sdk.Coins`), empty/0 by default |
| 6 | Creator = contract, immutable; controller optional (contract) and immutable in the MVP |
| 7 | 18 decimals only, no bank↔EVM scaling |
| 8 | No pause/freeze/blacklist; transfer behaviour is standard |
| 9 | `permit` is phase 2 |
| 10 | No Cosmos messages for create/mint/burn; creation only through the factory precompile `0x…0901`, supply only through the minter precompile `0x…0902` |
| 11 | Factory and minter precompiles are **static**; the token itself is **dynamic** per denom |
| 12 | Mint is capped at `2^256-1`; burn only from the controller's own balance |
