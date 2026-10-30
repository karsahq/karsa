# Karsa Native Token (`MsgCreateNativeToken`)

Token yang memakai **interface ERC20** tetapi **tidak men-deploy kontrak ERC20**.
Saldo disimpan di bank ledger, logika ERC20 dijalankan oleh dynamic precompile di
alamat `0x` yang deterministik.

Pesan produk:

> Deploy an ERC20-compatible token without deploying an ERC20 contract.
> Native performance, standard EVM compatibility.

## 1. Posisi dalam arsitektur

Karsa punya dua jalur penerbitan token. Keduanya ERC20 dari sisi pemakai; yang
berbeda adalah tempat saldo disimpan dan tempat logika dijalankan.

| | **Native ERC20** (dokumen ini) | **Custom ERC20** |
|---|---|---|
| Saldo | bank ledger | storage kontrak |
| `transfer` dijalankan oleh | precompile (Go) | Solidity |
| Alamat `0x` | deterministik dari denom | `CREATE` (pengirim + nonce) |
| Logika transfer custom | tidak mungkin | bebas |
| Logika penerbitan custom | authority / controller (fase 2) | bebas |
| Gas swap di pool AMM | ~76k | ~550k |
| Bisa IBC native | ya | tidak (butuh bridge) |
| Source di explorer | tidak ada (precompile) | terverifikasi |
| Biaya protokol saat terbit | `creation_fee` (param) | tidak ada |
| Biaya gas saat terbit | ~100k | ~700k–1.2M |

**Prinsip identitas aset:** satu denom, satu alamat EVM, satu sumber kebenaran
saldo. Native token tidak boleh punya wrapper ERC20 yang bisa diperdagangkan
terpisah, dan custom ERC20 tidak boleh diregistrasi sebagai token native.

## 2. Alamat deterministik

```
address = sha256("karsa/native/" + denom)[12:]   // 20 byte terakhir
```

- Prefix berbeda dari LP (`amm/lp/`) agar tidak pernah bertabrakan.
- Harus berada di luar rentang precompile statis (`0x1`–`0x9ff`), termasuk AMM
  (`0x…0900`). Validasi saat pembuatan; tolak dan minta simbol lain jika bentrok.
- Harus belum terisi: tolak jika sudah ada akun/kontrak di alamat tersebut.
- Derivasi ini **permanen**. Mengubahnya berarti mengubah alamat semua token.

## 3. Denom dan simbol

**Keputusan: denom global `n/{symbol}`.**

- Symbol unik secara global, tidak dapat diubah, dan **tidak dapat direbut kembali**
  — termasuk oleh governance. Identitas aset dipakai oleh pool AMM, transaksi, dan
  integrasi eksternal; mengambil alihnya menciptakan kebingungan aset.
- Panjang symbol: **3–12 karakter**, `[a-z0-9]`. Batas ini bukan kosmetik: KV write
  2.000 + **30 gas/byte**, dan denom disimpan di setiap record pool. Voucher IBC 68
  karakter membuat satu record pool membengkak ~136 byte (~4.000 gas per tulis).
- Nama token **boleh** diubah oleh authority. Symbol tidak.
- Registry menolak symbol yang sudah terpakai.

## 4. Desimal

- MVP: **hanya 18 desimal.** Tidak ada scaling antara bank dan EVM; 1 unit base
  bank = 1 unit base EVM.
- `decimals()` pada precompile mengembalikan 18.
- Denom dengan desimal lain (mis. `uusdc` 6 desimal) **tidak** bisa dibuat lewat
  jalur ini. Untuk aset seperti itu, gunakan model token pair `x/erc20` yang ada.
- `totalSupply` maksimum: `2^256-1`, divalidasi saat mint.

## 5. Model otorisasi (authority)

Setiap denom punya satu `authority` yang boleh mint dan burn.

```
CREATE ──► authority = pembuat (atau "" bila immutable)
              │
              ├─ MintBurn ──► MsgMint / MsgBurn oleh authority
              ├─ Transfer ──► MsgChangeTokenAuthority (tanda tangan authority lama)
              └─ Renounce ──► authority = "" (permanen, tanpa pemulihan)
```

| Keputusan | Nilai |
|---|---|
| Authority awal | pembuat token, kecuali `immutable: true` |
| Jenis authority | alamat Cosmos biasa **atau multisig account** |
| Validasi authority | lewat autentikasi Cosmos SDK (signer check), bukan sekadar format alamat |
| Renounce | permanen; tidak ada jalur pemulihan, termasuk governance |
| Perubahan nama | oleh authority |
| Perubahan simbol | **tidak diizinkan** |
| Reclaim simbol | **tidak ada**, termasuk oleh governance |
| Pause / freeze / blacklist | **tidak ada** di model ini |
| Burn oleh pemegang | boleh membakar saldo sendiri, siapa pun |

Alasan `renounce` permanen: developer butuh klaim yang bisa dibuktikan on-chain
("supply tidak akan bertambah lagi"). Kalau ada jalur pemulihan, klaim itu tidak
bernilai.

Alasan tidak ada pause/blacklist: perilaku transfer harus dijamin standar. Token
yang butuh pembekuan harus memakai jalur custom ERC20.

## 6. Pesan (MVP)

```proto
MsgCreateNativeToken {
  creator        : string   // bech32
  symbol         : string   // 3..12 karakter, [a-z0-9], unik global
  name           : string   // 1..64 karakter
  initial_supply : string   // math.Int, dicetak ke creator
  immutable      : bool     // true → authority = "" sejak awal
}

MsgMintNativeToken {
  authority : string
  denom     : string
  amount    : string
  recipient : string        // opsional, default = authority
}

MsgBurnNativeToken {
  sender : string
  denom  : string
  amount : string           // dari saldo `sender`
}

MsgUpdateTokenMetadata {
  authority : string
  denom     : string
  name      : string
}

MsgChangeTokenAuthority {
  authority     : string
  denom         : string
  new_authority : string    // alamat biasa atau multisig account
}
```

Semua pesan memvalidasi bahwa `denom` terdaftar sebagai native token Karsa, agar
tidak bisa dipakai untuk mencetak denom lain (mis. `ibc/…` atau `akra`).

`MsgMint` dan `MsgBurn` mengeluarkan event `Transfer` ERC20 (dari/ke alamat nol)
supaya indexer dan explorer melihat perubahan supply seperti token biasa.

## 7. Integrasi dengan AMM

Native token harus bisa menjadi sisi pool tanpa konversi. Saat pembuatan:

```go
erc20Keeper.SetToken(ctx, erc20types.NewTokenPair(address, denom, erc20types.OWNER_MODULE))
erc20Keeper.EnableDynamicPrecompile(ctx, address)
```

Ini jalur yang sama dengan `registerTestPair` di tes AMM, jadi `resolveAsset`
mengenali token sebagai bank-backed (`IsNativeCoin() == true`) dan
`moveIn`/`moveOut` menjadi bank send murni — tanpa konversi, tanpa escrow.

## 8. Persyaratan precompile ERC20

| Item | Persyaratan |
|---|---|
| `name()` `symbol()` `decimals()` | dari metadata bank |
| `totalSupply()` | supply bank denom |
| `balanceOf()` | saldo bank |
| `transfer()` `transferFrom()` | pindah tepat `amount`, kembalikan `true` |
| `approve()` `allowance()` | standar; `max uint256` = tak terbatas (jangan dikurangi) |
| Event `Transfer` | setiap perubahan saldo, termasuk mint/burn (alamat nol) |
| Event `Approval` | setiap perubahan allowance |
| Hook / fee / pause | **tidak ada** |
| `permit` (EIP-2612) | **tidak didukung di MVP** — lihat §11 |

### Alamat terblokir

Transfer yang ditolak oleh kebijakan `config/permissions.go` **harus**:

- mengembalikan error yang jelas (`ErrBlockedAddress` atau sejenis), dan
- **tidak** memancarkan event `Transfer` palsu.

Tidak boleh ada keadaan di mana event tercatat tetapi saldo tidak berpindah, atau
sebaliknya.

## 9. Integrasi explorer

Blockscout mendeteksi token lewat panggilan ERC20 ke alamat. Precompile merespons,
tetapi **belum pernah diuji di Karsa** — ini item verifikasi, bukan asumsi.

Matriks uji minimum sebelum menjanjikan "muncul otomatis di explorer":

| Uji | Kriteria lulus |
|---|---|
| Deteksi token | alamat muncul sebagai token, bukan akun biasa |
| Metadata | nama, simbol, desimal sesuai |
| Event transfer | muncul di tab transfer dan menghitung saldo |
| Perubahan saldo | saldo holder ter-update setelah transfer |
| Mint/burn | supply ter-update di explorer |
| Token holder list | daftar holder terisi |

Jika Blockscout tidak mengindeks precompile dinamis, perlu penanganan khusus —
dan janji "muncul otomatis" tidak boleh dibuat sebelum terbukti.

Sediakan `IERC20.sol` referensi di dokumentasi untuk integrasi, meskipun tidak ada
source yang bisa diverifikasi.

## 10. Item verifikasi lain sebelum implementasi

| Item | Mengapa penting |
|---|---|
| Konversi unit `decimals()` | UI/wallet harus menampilkan angka yang sama dengan bank |
| Infinite approval | Salah implementasi = allowance terkuras atau tidak berkurang |
| Approval race (`approve` 0 dulu) | Perilaku standar yang diandalkan tooling |
| Nilai balik `transfer` | Harus `true`; jangan meniru USDT yang mengembalikan kosong |
| Interaksi `IERC20` dari Solidity | Termasuk `staticcall` untuk `balanceOf` |
| Determinisme panggilan precompile | Tidak boleh ada state bergantung konteks lokal |

## 11. Fase 2

### `permit` (EIP-2612)

Belum didukung di MVP. Menambah nonce, validasi tanda tangan, domain separator,
dan permukaan serangan baru. Dokumentasikan eksplisit agar dApp tidak
mengasumsikan semua token ERC20-compatible mendukung EIP-2612.

### Solidity controller

Memungkinkan logika penerbitan (vesting, cap, bonding curve, penjualan) ditulis di
Solidity, sementara token tetap bank denom.

```
Controller.sol ──mint/burn──► Precompile minter (0x…0901) ──► bank
```

- Precompile minter memeriksa `minter[denom] == msg.sender`.
- Controller **tidak menyimpan saldo** dan **tidak menyentuh transfer**.
- `minter` didaftarkan lewat `MsgChangeTokenAuthority` berupa alamat kontrak.

Prasyarat keamanan sebelum fase ini dikerjakan:

- reentrancy lock pada precompile minter,
- batas supply (`2^256-1`) dan validasi `amount > 0`,
- satu denom hanya boleh punya satu minter,
- keputusan eksplisit siapa yang boleh mengganti minter, diumumkan sebagai
  properti token.

## 12. Parameter modul

| Param | Nilai awal | Catatan |
|---|---|---|
| `creation_fee` | **0 saat launch** | dinaikkan lewat governance bila squatting muncul |
| `creation_fee_denom` | aset stabil (IBC USDC) | agar nilainya tidak ikut volatilitas KRA |
| penerima fee | treasury | bukan burn |
| refund | tidak ada | termasuk setelah renounce |
| `max_name_len` | 64 | |
| `max_symbol_len` | 12 | |
| `min_symbol_len` | 3 | |
| `max_initial_supply` | `2^256-1` | batas representasi EVM |
| `immutable_default` | `false` | pembuat boleh memilih |

### Mengapa fee ada, dan mengapa default-nya 0

Deploy ERC20 tidak kena fee protokol, tetapi memakan ~700k–1.2M gas. Membuat
native token hanya ~100k gas, sehingga tanpa fee **native token lebih murah
daripada ERC20 padahal ia mengklaim nama global yang permanen**. Karena symbol
tidak bisa direbut kembali (keputusan §3), tanpa biaya apa pun ruang nama akan
di-*land rush* dan tidak bisa dibersihkan.

Karena itu fee di sini bukan "biaya membuat token", melainkan biaya mereservasi
nama unik yang permanen. Tetap ada di MVP agar mekanismenya siap, tetapi
default-nya 0 supaya adopsi awal tidak terhalang.

Jalur custom ERC20 **tidak** kena fee protokol — jadi ekspektasi "membuat token
tidak dipungut biaya" tetap terpenuhi, hanya lewat jalur yang berbeda.

## 13. Bukan bagian dari model ini

- desimal selain 18,
- pause, freeze, blacklist, fee-on-transfer, rebasing,
- wrapper ERC20 untuk token native,
- `permit` pada MVP,
- controller pada MVP,
- reclaim symbol, termasuk oleh governance.

## 14. Ringkasan keputusan

| # | Keputusan | Status |
|---|---|---|
| 1 | Denom global `n/{symbol}`, 3–12 karakter, unik, permanen | ditetapkan |
| 2 | `creation_fee` parameter, masuk treasury, default 0, denom stabil | ditetapkan |
| 3 | Tidak ada reclaim symbol, termasuk governance | ditetapkan |
| 4 | `permit` fase 2, didokumentasikan sebagai tidak didukung | ditetapkan |
| 5 | Authority mendukung multisig Cosmos, divalidasi lewat auth SDK | ditetapkan |
