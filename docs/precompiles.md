# Karsa Precompiles

Dua jenis precompile di Karsa, dengan siklus hidup yang berbeda.

| | **Statis** | **Dinamis** |
|---|---|---|
| Jumlah | tetap, saat ini 11 | satu per aset |
| Alamat | konstanta protokol (`0x…0100`–`0x…09ff`) | diturunkan dari denom/alamat |
| Didaftarkan | genesis atau `evm.params.active_static_precompiles` | runtime lewat `x/erc20.EnableDynamicPrecompile` |
| Diubah oleh | governance (`MsgUpdateParams` ke `x/vm`) | modul pemilik aset |
| Contoh | Bank, AMM, Staking | LP token, voucher IBC, native token `n:0x…` |

## 1. Precompile statis yang aktif

Default genesis mengambil `evmtypes.AvailableStaticPrecompiles` (10 entri) dan
menambahkan AMM (`genesis.go:33`).

| Alamat | Nama | Jenis | Fungsi |
|---|---|---|---|
| `0x…0100` | P256 | stateless | verifikasi tanda tangan secp256r1 |
| `0x…0400` | Bech32 | stateless | konversi alamat hex ↔ bech32 |
| `0x…0800` | Staking | module | operasi staking |
| `0x…0801` | Distribution | module | reward dan distribusi |
| `0x…0802` | ICS20 | module | transfer IBC |
| `0x…0803` | Vesting | module | akun vesting |
| `0x…0804` | Bank | module | saldo, supply, send |
| `0x…0805` | Gov | module | governance |
| `0x…0806` | Slashing | module | slashing |
| `0x…0807` | ICS02 | module | IBC client |
| `0x…0900` | AMM | Karsa | swap, quote, getPool, liquidity |
| **`0x…0901`** | **Token Factory** | **Karsa** | `createToken` — membuat native token dari kontrak |
| **`0x…0902`** | **Token Minter** | **Karsa** | `mint`/`burn` atas nama controller token |

## 2. Satu sumber kebenaran

Daftar statis dibangun oleh `NewEVMGenesisState` (`genesis.go`) dan dipakai oleh
`App.DefaultGenesis` (`app.go`). `karsad init` sekarang memakai `App.DefaultGenesis`
lewat wrapper `NewInitCmd` (`cmd/karsad/cmd/init.go`), sehingga chain baru langsung
memperoleh seluruh precompile aktif.

> Sebelumnya `karsad init` memakai `BasicModuleManager.DefaultGenesis`, yang hanya
> berisi default per-modul dan **tidak** menyertakan daftar precompile. Chain hasil
> `init` karenanya tidak memiliki precompile yang berfungsi, dan `local_node.sh`
> menutupinya dengan menambal genesis lewat `jq`. Patch itu sudah dihapus.

Yang perlu dijaga sekarang hanya `NewEVMGenesisState`: menambah precompile berarti
menambahkannya di sana, dan `genesis_test.go` menjaga ketiga alamat Karsa.

## 3. Alamat tetap Karsa

| Apa | Alamat |
|---|---|
| Native coin KRA | bukan kontrak — currency jaringan, 18 desimal |
| ERC20 view dari `akra` | `0xd9171c1192d82ecd4f71dec2ee0264769af9531e` |
| AMM | `0x…0900` |
| Token factory | `0x…0901` |
| Token minter | `0x…0902` |
| Token native user | diturunkan dari denom `n:0x…` |
| Aset IBC | diturunkan dari trace hash |

`0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE` adalah penanda EIP-7528
("aset native" di token list), **bukan** kontrak: tidak ada kode di sana. Jangan
didaftarkan sebagai precompile; Karsa tidak membutuhkannya karena precompile
`akra` dibaca langsung dari bank ledger, tanpa langkah wrap seperti WETH.

### Alamat `akra`

`NewErc20GenesisState` mendaftarkan pasangan native pada alamat deterministik:

```
address = sha256("karsa/erc20/akra")[12:]
        = 0xd9171c1192d82ecd4f71dec2ee0264769af9531e
```

Konstanta hidup di `config.NativeERC20Address`; `config/config_test.go` mengunci
nilainya ke derivasi di atas. Alamat ini bagian dari genesis: mengubahnya berarti
mengubah identitas ERC20 dari aset native dan memutus wallet, pool, serta explorer
yang sudah menyimpannya. Jangan menyalin alamat dari chain lain (sebelumnya Karsa
memakai alamat WEVMOS milik Evmos).

## 4. Biaya gas: tidak ada

Precompile statis **tidak menambah biaya gas** per panggilan EVM. `stateDB.Prepare`
memasukkan semuanya ke access list tanpa menagih gas.

Ini sudah diukur dan hipotesis sebaliknya sudah dibuktikan salah: pernah
diperkirakan 11 precompile × 2.400 gas = 26.400 gas per panggilan, ternyata angka
itu tidak muncul di hasil pengukuran. Jangan mengoptimasi ke arah itu lagi.

Konsekuensinya: memilih 11 atau 20 precompile tidak mengubah performa. Yang
berubah hanya permukaan serangan, karena setiap precompile adalah kode yang dapat
dipanggil dari EVM.

## 5. Precompile yang direncanakan

Belum ada. Kandidat berikutnya adalah `permit` (EIP-2612) pada precompile ERC20
token, jika ternyata bisa diimplementasikan dengan aman.

Lihat `docs/native-token.md` untuk model kepemilikan dan alur pembuatan token.

## 6. Checklist menambah precompile statis

- [ ] Tentukan alamat di rentang `0x…09xx`, di luar yang sudah terpakai
- [ ] Tambahkan ke `genesis.go` (`NewEVMGenesisState`)
- [ ] Tambahkan ke `local_node.sh` (patch `jq`)
- [ ] Daftarkan implementasinya di `app.go` / `precompiles` module
- [ ] Pastikan alamatnya masuk `config/permissions.go` (blocked addresses) agar
      tidak bisa menerima transfer dana secara tidak sengaja
- [ ] Tambahkan ke `IAmm.sol`-style interface Solidity + NatSpec
- [ ] Emit EVM log untuk operasi yang mengubah state, bukan hanya Cosmos event
- [ ] Tes: pemanggilan dari EOA, dari kontrak, reentrancy, dan alamat terblokir
- [ ] Verifikasi `karsad q evm params` menampilkan alamat baru

## 7. Precompile dinamis

Didaftarkan lewat `x/erc20`:

```go
erc20Keeper.SetToken(ctx, erc20types.NewTokenPair(address, denom, erc20types.OWNER_MODULE))
erc20Keeper.EnableDynamicPrecompile(ctx, address)
```

Yang memakai jalur ini:

| Aset | Alamat |
|---|---|
| Denom native non-EVM yang di-pair | diturunkan dari denom |
| Voucher IBC | diturunkan dari trace hash |
| LP token | `LPAssetAddress("amm/pool/{id}")` |
| Native token | `hash(creator, sequence)[:20]` |

Pendaftaran ini juga membuat akun EVM dengan code hash ERC20, sehingga alamatnya
lolos pemeriksaan `isContract()` pada integrasi pihak ketiga.
