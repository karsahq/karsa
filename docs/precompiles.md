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

## 2. Duplikasi yang harus dijaga

`karsad init` **tidak** memakai `DefaultGenesis()`, sehingga daftar precompile di
chain hasil `init` kosong. Karena itu `local_node.sh:251` menambal daftar yang sama
secara hardcoded.

Artinya daftar statis hidup di **dua tempat**:

```
genesis.go:33        NewEVMGenesisState()  → dipakai app, tes, dan chain baru
local_node.sh:251    jq patch untuk node lokal
```

> **Setiap penambahan precompile statis harus mengubah keduanya.** Kalau tidak,
> chain lokal dan chain baru akan berperilaku berbeda, dan gejalanya sulit dilacak.

Perbaikan jangka panjang yang disarankan: buat `karsad init` memakai
`DefaultGenesis()`, atau turunkan daftar di `local_node.sh` dari satu konstanta,
sehingga hanya ada satu sumber kebenaran.

## 3. Biaya gas: tidak ada

Precompile statis **tidak menambah biaya gas** per panggilan EVM. `stateDB.Prepare`
memasukkan semuanya ke access list tanpa menagih gas.

Ini sudah diukur dan hipotesis sebaliknya sudah dibuktikan salah: pernah
diperkirakan 11 precompile × 2.400 gas = 26.400 gas per panggilan, ternyata angka
itu tidak muncul di hasil pengukuran. Jangan mengoptimasi ke arah itu lagi.

Konsekuensinya: memilih 11 atau 20 precompile tidak mengubah performa. Yang
berubah hanya permukaan serangan, karena setiap precompile adalah kode yang dapat
dipanggil dari EVM.

## 4. Precompile yang direncanakan

Belum ada. Kandidat berikutnya adalah `permit` (EIP-2612) pada precompile ERC20
token, jika ternyata bisa diimplementasikan dengan aman.

Lihat `docs/native-token.md` untuk model kepemilikan dan alur pembuatan token.

## 5. Checklist menambah precompile statis

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

## 6. Precompile dinamis

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
