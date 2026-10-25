# Karsa — Kernel for Assets, Runtime, Settlement & Apps

**KARSA** stands for **K**ernel for **A**ssets, **R**untime, **S**ettlement & **A**pps.

Karsa is a Cosmos EVM chain derived from the Cosmos EVM example chain (the
`evmd` implementation), used to demonstrate the Cosmos EVM integration and to
provide a chain object for testing.

## Config

By default, this chain has the following configuration:

| Option              | Value                  |
|---------------------|------------------------|
| Binary              | `karsad`               |
| Chain ID            | `karsa_262144-1`       |
| Custom Opcodes      | -                      |
| Default Token Pairs | 1 for the native token |
| Denomination        | `akra` (display `kra`, symbol `KRA`) |
| EVM permissioning   | permissionless         |
| Enabled Precompiles | all                    |

## Running The Chain

To run a local Karsa node, execute the local node script:

```bash
./local_node.sh [FLAGS]
```

Available flags are:

- `-y`: Overwrite previous database
- `-n`: Do **not** overwrite previous database
- `--no-install`: Skip building the binary
- `--remote-debugging`: Build a binary suitable for remote debugging

## Connect to Wallet

For the sake of this example, we'll be using Metamask:

1. Use the following seed phrase when adding a new wallet:
`gesture inject test cycle original hollow east ridge hen combine
junk child bacon zero hope comfort vacuum milk pitch cage oppose
unhappy lunar seat`
2. On the top left of the Metamask extension, click the Network button.
3. Click Add custom network from the bottom of the modal.
4. Under Default RPC URL, add the RPC URL as http://localhost:8545. Ensure your chain is running.
5. Once added, copy the rest of the settings shown in the below images.

![Button to select network](guide/networks.png "Networks Select")
![Button to add network](guide/add_network.png "Networks Add")
![RPC URL Settings](guide/rpc_url.png "RPC URL")
![Overview of required settings](guide/settings.png "Settings Overview")

## Available Cosmos SDK Modules

As mentioned above, this exemplary chain implementation is a reduced version of `simapp`.
Specifically, instead of offering access to all Cosmos SDK modules, it just includes the following:

- `auth`
- `authz`
- `bank`
- `capability`
- `consensus`
- `distribution`
- `evidence`
- `feegrant`
- `genutil`
- `gov`
- `mint`
- `params`
- `slashing`
- `staking`
- `upgrade`
