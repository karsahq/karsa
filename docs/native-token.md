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
| Alamat `0x` | dibuat modul, deterministik dari creator | `CREATE` (pengirim + nonce) |
| Logika transfer custom | tidak mungkin | bebas |
| Logika penerbitan custom | authority / controller (fase 2) | bebas |
| Gas swap di pool AMM | ~76k | ~550k |
| Bisa IBC native | ya | tidak (butuh bridge) |
| Source di explorer | tidak ada (precompile) | terverifikasi |
| Biaya protokol saat terbit | opsional, default 0 | tidak ada |
| Biaya gas saat terbit | ~100k | ~700k–1.2M |

**Prinsip identitas aset:** satu alamat, satu denom, satu sumber kebenaran saldo.
Alamat adalah identitas; denom hanyalah representasi bank dari alamat itu. Native
token tidak boleh punya wrapper ERC20 yang bisa diperdagangkan terpisah, dan
custom ERC20 tidak boleh diregistrasi sebagai token native.

## 2. Alamat dibuat lebih dulu, denom mengikuti

Berbeda dari aset `ibc/…` atau `erc20:0x…`, native token **tidak** menurunkan
alamat dari denom. Urutannya dibalik agar alamat menjadi identitas utama — persis
seperti ERC20 di Ethereum.

```
address = hash(creator, sequence)[:20]        // 20 byte, lowercase hex
denom   = "n:" + "0x" + address               // contoh: n:0x1a2b…ef12 (44 byte)
```

`sequence` adalah nomor urut token milik creator tersebut. Algoritma pembuatan:

```
sequence = 0
selama true:
    addr = hash(creator, sequence)[:20]
    denom = "n:0x" + lowercase(addr)
    jika denom sudah ada di bank  → sequence++, ulangi
    jika addr berada di rentang precompile statis (0x1..0x9ff) → sequence++, ulangi
    jika addr sudah terisi akun atau kontrak → sequence++, ulangi
    berhenti
```

Sifat-sifat yang dihasilkan:

| Sifat | Konsekuensi |
|---|---|
| Alamat deterministik dari `(creator, sequence)` | creator bisa menghitung ulang tokennya tanpa menyimpan apa pun |
| Mapping denom ↔ alamat **sintaktis** | denom bisa dihitung dari alamat tanpa membaca state, dan sebaliknya |
| `sequence` retry | tabrakan tidak pernah menjadi kegagalan nyata |
| Lowercase wajib | `n:0xAbC` dan `n:0xabc` adalah denom berbeda — selalu normalisasi |
| Prefiks `n:` **permanen** | konstanta protokol; mengubahnya memutus semua token yang terbit |

Konstanta protokol:

```
NativeTokenDenomPrefix = "n:"
```

Denom 44 byte (sama dengan `erc20:0x…`), biaya tulis pool ~780 gas lebih mahal
daripada denom simbol pendek — sekitar 1% dari biaya swap, dapat diterima.

## 3. Simbol bukan identitas

**Keputusan: simbol tidak unik, tidak ada reservasi, tidak ada reclaim, tidak ada
adjudikasi.**

| Aturan | Nilai |
|---|---|
| Keunikan simbol | tidak ada — "MOMO" boleh dimiliki banyak token |
| Reservasi simbol kanonik | tidak ada |
| Reclaim / pengambilalihan | tidak ada, termasuk oleh governance |
| Probation / jendela sengketa | tidak ada |
| Panjang simbol | 3–12 karakter, `[A-Za-z0-9]` |
| Simbol bisa diubah authority | ya — simbol murni metadata |

### Mengapa simbol tidak eksklusif

Nama yang eksklusif memaksa protokol menjawab pertanyaan yang tidak bisa
dijawabnya dengan baik: siapa yang berhak atas `momo`, bagaimana menyelesaikan
sengketa, dan bagaimana mencabutnya tanpa merusak integrasi. Setiap jawaban
menambah governance, dispute, dan jendela waktu — padahal tujuannya hanya
menghemat gas di pool.

Karena identitas token adalah **alamat**, simbol tidak perlu unik. Ini model
Ethereum: siapa pun boleh punya token bernama "USDC", dan kepercayaan datang dari
token list, bukan dari nama.

Konsekuensi yang harus diterima: tampilan bisa memiliki dua "MOMO" dengan alamat
berbeda. Penyelesaiannya sama seperti Ethereum — alamat adalah kebenaran, dan
explorer memberi badge.

## 4. Desimal

- MVP: **hanya 18 desimal.** Tidak ada scaling antara bank dan EVM; 1 unit base
  bank = 1 unit base EVM.
- `decimals()` pada precompile mengembalikan 18.
- Denom dengan desimal lain (mis. `uusdc` 6 desimal) **tidak** bisa dibuat lewat
  jalur ini. Untuk aset seperti itu, gunakan model token pair `x/erc20` yang ada.
- `totalSupply` maksimum: `2^256-1`, divalidasi saat mint.

## 5. Model otorisasi (authority)

Setiap token punya satu `authority` yang boleh mint dan burn. Semua alamat
disimpan sebagai **20 byte lowercase hex**; bech32 hanya untuk tampilan CLI.

```
CREATE ──► authority = creator (atau "" bila immutable)
              │
              ├─ MintBurn ──► MsgMint / MsgBurn oleh authority
              ├─ Transfer ──► MsgChangeTokenAuthority (tanda tangan authority lama)
              └─ Renounce ──► authority = "" (permanen, tanpa pemulihan)
```

| Keputusan | Nilai |
|---|---|
| Creator | alamat 0x, **immutable** — tidak pernah berubah |
| Authority awal | creator, kecuali `immutable: true` |
| Jenis authority | alamat biasa **atau multisig account** |
| Validasi authority | lewat autentikasi Cosmos SDK (signer check), bukan format alamat |
| Renounce | permanen; tidak ada jalur pemulihan, termasuk governance |
| Nama & simbol | dapat diubah authority |
| Pause / freeze / blacklist | **tidak ada** |
| Burn oleh pemegang | boleh membakar saldo sendiri, siapa pun |

`creator` dan `authority` dipisahkan dengan sengaja: creator tidak berubah,
authority bisa berpindah. Menggabungkan keduanya akan memalsukan sejarah token
setiap kali kendali dialihkan.

Alasan tidak ada pause/blacklist: perilaku transfer harus dijamin standar. Token
yang butuh pembekuan harus memakai jalur custom ERC20.

## 6. Verifikasi sebagai satu-satunya jalur kepercayaan

Karena simbol tidak unik, satu-satunya sinyal kepercayaan adalah flag `verified`
di registry, dikelola governance, dan ditampilkan sebagai badge oleh explorer.

| Keadaan | Tampilan |
|---|---|
| `verified = true` | badge terverifikasi, token muncul di daftar utama |
| `verified = false` | ditandai unverified; tetap bisa dipakai dan di-pool |

Aturan yang tidak boleh dilanggar: **jangan pernah menyimpulkan kepercayaan dari
nama atau simbol.** Explorer dan UI wajib menampilkan alamat di samping simbol.

## 7. Pesan (MVP)

```proto
MsgCreateNativeToken {
  creator        : string   // bech32 signer; disimpan sebagai 0x
  symbol         : string   // 3..12 karakter, TIDAK unik
  name           : string   // 1..64 karakter
  initial_supply : string   // math.Int, dicetak ke creator
  immutable      : bool     // true → authority = "" sejak awal
}
// denom dan alamat dihitung modul; tidak dikirim pemanggil.

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
  symbol    : string        // boleh diubah; tidak memengaruhi identitas
}

MsgChangeTokenAuthority {
  authority     : string
  denom         : string
  new_authority : string
}
```

**Pembuatan hanya lewat kontrak.** `MsgCreateNativeToken` ditolak kecuali param
`open_creation` diaktifkan governance. Default-nya mati, sehingga setiap token
dilacak kembali ke sebuah kontrak: `creator` selalu alamat kontrak, bukan kunci.

Konsekuensi yang perlu disadari: bila semua orang memakai satu launcher bersama,
`creator` menjadi sama untuk semua token dan atribusi manusia hanya terlihat dari
event launcher. Bila tiap proyek men-deploy kontraknya sendiri, `creator` unik per
token tetapi biaya deploy ditanggung masing-masing.

Semua pesan memvalidasi bahwa `denom` terdaftar sebagai native token Karsa, agar
tidak bisa dipakai untuk mencetak denom lain (mis. `ibc/…`, `erc20:…`, `akra`).

`MsgMint` dan `MsgBurn` mengeluarkan event `Transfer` ERC20 (dari/ke alamat nol)
supaya indexer dan explorer melihat perubahan supply seperti token biasa.

## 8. Registry

```go
// x/nativetoken store
token/{denom}            → TokenRecord{
                             Creator    common.Address   // immutable
                             Authority  common.Address   // mutable; zero = immutable
                             Name       string
                             Symbol     string
                             Verified   bool             // governance
                             CreatedAt  int64
                           }
byCreator/{addr}/{denom} → byte{}            // indeks query
```

Registry **tidak** menegakkan keunikan simbol dan tidak menyimpan indeks simbol.
Keunikan denom sudah dijamin `x/bank` dan pemeriksaan saat pembuatan.

## 9. Integrasi dengan AMM

Native token harus bisa menjadi sisi pool tanpa konversi. Saat pembuatan:

```go
erc20Keeper.SetToken(ctx, erc20types.NewTokenPair(address, denom, erc20types.OWNER_MODULE))
erc20Keeper.EnableDynamicPrecompile(ctx, address)
```

Ini jalur yang sama dengan `registerTestPair` di tes AMM, jadi `resolveAsset`
mengenali token sebagai bank-backed (`IsNativeCoin() == true`) dan
`moveIn`/`moveOut` menjadi bank send murni — tanpa konversi, tanpa escrow.

Karena `denom` dan alamat bisa saling dihitung, record pool berpotensi berhenti
menyimpan `denom_a`/`denom_b` untuk aset address-derived. Itu optimasi terpisah
dan belum diukur.

## 10. Persyaratan precompile ERC20

| Item | Persyaratan |
|---|---|
| `name()` `symbol()` `decimals()` | dari metadata registry/bank |
| `totalSupply()` | supply bank denom |
| `balanceOf()` | saldo bank |
| `transfer()` `transferFrom()` | pindah tepat `amount`, kembalikan `true` |
| `approve()` `allowance()` | standar; `max uint256` = tak terbatas (jangan dikurangi) |
| Event `Transfer` | setiap perubahan saldo, termasuk mint/burn (alamat nol) |
| Event `Approval` | setiap perubahan allowance |
| Hook / fee / pause | **tidak ada** |
| `permit` (EIP-2612) | **tidak didukung di MVP** |

### Alamat terblokir

Transfer yang ditolak oleh kebijakan `config/permissions.go` **harus**:

- mengembalikan error yang jelas, dan
- **tidak** memancarkan event `Transfer` palsu.

## 11. Integrasi explorer

Blockscout mendeteksi token lewat panggilan ERC20 ke alamat. Precompile merespons,
tetapi **belum pernah diuji di Karsa** — ini item verifikasi, bukan asumsi.

| Uji | Kriteria lulus |
|---|---|
| Deteksi token | alamat muncul sebagai token, bukan akun biasa |
| Metadata | nama, simbol, desimal sesuai |
| Event transfer | muncul di tab transfer dan menghitung saldo |
| Perubahan saldo | saldo holder ter-update setelah transfer |
| Mint/burn | supply ter-update |
| Token holder list | daftar holder terisi |
| Badge `verified` | ditampilkan dan membedakan unverified |

Jika Blockscout tidak mengindeks precompile dinamis, perlu penanganan khusus —
dan janji "muncul otomatis" tidak boleh dibuat sebelum terbukti.

Sediakan `IERC20.sol` referensi di dokumentasi untuk integrasi, meskipun tidak ada
source yang bisa diverifikasi.

## 12. Item verifikasi lain

| Item | Mengapa penting |
|---|---|
| Konversi unit `decimals()` | UI/wallet harus menampilkan angka yang sama dengan bank |
| Infinite approval | Salah implementasi = allowance terkuras atau tidak berkurang |
| Approval race (`approve` 0 dulu) | Perilaku standar yang diandalkan tooling |
| Nilai balik `transfer` | Harus `true`; jangan meniru USDT yang mengembalikan kosong |
| Interaksi `IERC20` dari Solidity | Termasuk `staticcall` untuk `balanceOf` |
| Determinisme panggilan precompile | Tidak boleh ada state bergantung konteks lokal |

## 13. Fase 2

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

- Precompile minter memeriksa `authority[denom] == msg.sender`.
- Controller **tidak menyimpan saldo** dan **tidak menyentuh transfer**.
- Controller didaftarkan lewat `MsgChangeTokenAuthority` berupa alamat kontrak.

Prasyarat keamanan: reentrancy lock, batas supply, satu denom satu minter, dan
keputusan eksplisit siapa yang boleh mengganti minter.

Factory dan minter bersifat **statis** (satu alamat global, bukan per token), sehingga
keduanya harus didaftarkan di daftar precompile statis — lihat `docs/precompiles.md`
untuk daftar, duplikasi `local_node.sh`, dan checklist penambahannya.

## 14. Parameter modul

| Param | Nilai awal | Catatan |
|---|---|---|
| `creation_fee` | **0** | murni anti-spam; naikkan bila ada penyalahgunaan massal |
| `open_creation` | **false** | pembuatan hanya lewat precompile factory; governance dapat mengaktifkan pesan |
| `creation_fee_denom` | aset stabil (IBC USDC) | agar tidak ikut volatilitas KRA |
| penerima fee | treasury | bukan burn |
| refund | tidak ada | termasuk setelah renounce |
| `min_symbol_len` | 3 | metadata saja |
| `max_symbol_len` | 12 | metadata saja |
| `max_name_len` | 64 | |
| `max_initial_supply` | `2^256-1` | batas representasi EVM |
| `immutable_default` | `false` | |

`creation_fee` tidak lagi berfungsi sebagai harga nama — tidak ada nama yang
langka. Ia hanya menahan pembuatan massal oleh skrip.

## 15. Bukan bagian dari model ini

- desimal selain 18,
- pause, freeze, blacklist, fee-on-transfer, rebasing,
- wrapper ERC20 untuk token native,
- keunikan simbol, reservasi nama, reclaim, probation,
- `permit` pada MVP,
- controller pada MVP.

## 16. Ringkasan keputusan

| # | Keputusan |
|---|---|
| 1 | Alamat adalah identitas; `address = hash(creator, sequence)[:20]` |
| 2 | `denom = "n:0x" + lowercase(address)`, 44 byte, prefiks permanen |
| 3 | Simbol tidak unik, tanpa reservasi/reclaim/adjudikasi |
| 4 | `verified` satu-satunya sinyal kepercayaan + badge explorer |
| 5 | `creation_fee` opsional default 0, treasury, denom stabil |
| 6 | Creator immutable (0x), authority mutable (0x), multisig didukung |
| 7 | Hanya 18 desimal, tanpa scaling bank↔EVM |
| 8 | Tanpa pause/freeze/blacklist; perilaku transfer dijamin standar |
| 9 | `permit` dan controller Solidity pada fase 2 |
