# Karsa Native Token

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
| Logika penerbitan custom | controller, lewat precompile minter | bebas |
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
| Simbol bisa diubah | tidak (metadata immutable di MVP) |

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

## 5. Kepemilikan: kontrak, bukan kunci

Tidak ada `authority` dan tidak ada pesan mint/burn. Supply hanya bisa bergerak
lewat kontrak.

```
CREATE (factory precompile; pemanggil harus kontrak)
   │
   ├─ controller = ""        → supply immutable selamanya
   └─ controller = 0xCtrl    → hanya 0xCtrl yang bisa mint/burn
```

| Keputusan | Nilai |
|---|---|
| Creator | alamat kontrak, **immutable** |
| Controller | ditetapkan saat pembuatan; `""` berarti immutable |
| Siapa boleh mint/burn | hanya `controller`, lewat precompile minter |
| Ganti controller | hanya oleh controller itu sendiri |
| Renounce | controller → `""`, permanen, tanpa pemulihan |
| Metadata | tidak dapat diubah (MVP) |
| Pause / freeze / blacklist | **tidak ada** |
| Burn oleh pemegang | boleh membakar saldo sendiri, siapa pun |

Alasan: kunci bisa hilang, dicuri, atau dipindahkan tanpa jejak. Kontrak bisa
diaudit, dipantau, dan dibatasi oleh kodenya sendiri.

Biaya yang harus diterima: bug pada kontrak berarti kebijakan supply mati permanen.
Itu risiko pemilik token, bukan risiko protokol.

`creator` dan `controller` dipisahkan dengan sengaja: creator tidak pernah berubah,
controller bisa berganti. Menggabungkan keduanya akan memalsukan sejarah token
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

## 7. Pesan

Tidak ada pesan Cosmos untuk membuat, mencetak, atau membakar token. Itu
keputusan, bukan kelalaian:

| Operasi | Jalur |
|---|---|
| Membuat token | precompile **factory** (`0x…0901`) — hanya dari kontrak |
| Mint / burn | precompile **minter** (`0x…0902`) — hanya oleh `controller` |

Kunci tidak bisa melakukan keduanya. Tidak ada saklar governance untuk
mengaktifkannya kembali; membuka jalur berbasis kunci lagi berarti upgrade chain.

Pesan yang tersisa hanya untuk governance:

```proto
MsgSetTokenVerified { authority, denom, verified }
MsgUpdateParams    { authority, params }
```

**Konsekuensi `creator`.** Karena pembuatan hanya lewat kontrak, `creator` selalu
alamat kontrak, bukan kunci. Bila semua orang memakai satu launcher bersama,
`creator` menjadi sama untuk semua token dan atribusi manusia hanya terlihat dari
event launcher. Bila tiap proyek men-deploy kontraknya sendiri, `creator` unik per
token tetapi biaya deploy ditanggung masing-masing.

Precompile factory menolak pemanggil yang bukan kontrak, sehingga aturan ini tidak
bisa dilewati lewat EOA.

Precompile minter hanya bekerja untuk denom yang `controller`-nya sama dengan
pemanggil, sehingga tidak bisa dipakai mencetak denom lain.

Mint dan burn mengeluarkan EVM log `Mint` / `Burn` dari precompile minter, supaya
indexer EVM melihat perubahan supply tanpa membaca event Cosmos. Perubahan
`totalSupply` pada precompile ERC20 terjadi di bank ledger, jadi precompile ERC20
tidak memancarkan `Transfer` untuk mint/burn yang dipicu dari luar dirinya.

## 8. Registry

```go
// x/nativetoken store (prefix → isi)
0x01 token/{denom}          → Token{ Creator, Controller, Name, Symbol, Verified, CreatedAt }
0x05 list/{denom}           → byte{}             // enumerasi untuk query & genesis
0x02 sequence/{creator}     → uint64             // per creator, dasar derivasi alamat
0x03 address/{0x…}          → denom              // dipakai precompile minter
0x04 params                 → Params
```

- `Creator` dan `Controller` disimpan sebagai string lowercase `0x…`.
- `sequence/{creator}` **wajib** ikut genesis export: alamat diturunkan darinya.
- `address/{0x…}` memungkinkan precompile minter menemukan denom hanya dari
alamat token.

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

Blockscout mendeteksi token lewat `eth_getCode` dan panggilan ERC20 (`eth_call`),
lalu mengikuti perpindahan saldo lewat `eth_getLogs` dan
`eth_getTransactionReceipt`. Permukaan RPC itu **sudah diuji di Karsa** lewat
`tests/e2e/smoke.sh`; instance Blockscout penuh belum dijalankan di CI karena
butuh Postgres/Redis/Docker.

| Uji | Status | Bukti |
|---|---|---|
| Deteksi token (`eth_getCode`) | **lulus** | precompile mengembalikan bytecode ERC20 |
| Metadata (`name`, `symbol`, `decimals`) | **lulus** | nilai sesuai metadata bank (`USDC`, 6) |
| Event transfer (`eth_getLogs`) | **lulus** | topik `Transfer` ditemukan |
| Perubahan saldo (`balanceOf`) | **lulus** | saldo penerima berubah setelah transfer |
| Receipt transaksi | **lulus** | `status=0x1`, log transfer ada di receipt |
| Mint/burn di explorer | belum diuji | log EVM sudah ada; indexing explorer belum |
| Token holder list | belum diuji | butuh indexer Blockscout |
| Badge `verified` | belum diimplementasikan | butuh integrasi registry → explorer |

**Syarat metadata.** Precompile ERC20 mengambil `name`/`symbol`/`decimals`
dari metadata bank. Denom bank tanpa metadata akan **revert** pada ketiga
panggilan itu, sehingga Blockscout tidak bisa menampilkan token. Native token
Karsa selalu menulis metadata saat pembuatan; aset yang didaftarkan manual
harus melakukan hal yang sama.

Langkah berikutnya adalah menjalankan instance Blockscout sungguhan terhadap
node Karsa dan memverifikasi holder list serta badge. Sampai itu dilakukan,
janji "token otomatis muncul di explorer" tetap belum boleh dibuat.

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
Controller.sol ──mint/burn──► Precompile minter (0x…0902) ──► bank
```

- Precompile minter memeriksa `controller[denom] == msg.sender`.
- Controller **tidak menyimpan saldo** dan **tidak menyentuh transfer**.
- Controller ditetapkan saat pembuatan dan hanya bisa menggantikan dirinya sendiri;
  tidak ada kunci atau governance yang bisa mengambil alih.

Prasyarat keamanan: reentrancy lock, batas supply, satu denom satu minter, dan
keputusan eksplisit siapa yang boleh mengganti minter.

Factory dan minter bersifat **statis** (satu alamat global, bukan per token), sehingga
keduanya harus didaftarkan di daftar precompile statis — lihat `docs/precompiles.md`
untuk daftar, duplikasi `local_node.sh`, dan checklist penambahannya.

## 14. Parameter modul

| Param | Nilai awal | Catatan |
|---|---|---|
| `creation_fee` | **0** | murni anti-spam; naikkan bila ada penyalahgunaan massal |
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
| 6 | Creator = kontrak, immutable; controller opsional (kontrak), hanya bisa menggantikan dirinya sendiri |
| 7 | Hanya 18 desimal, tanpa scaling bank↔EVM |
| 8 | Tanpa pause/freeze/blacklist; perilaku transfer dijamin standar |
| 9 | `permit` pada fase 2 |
| 10 | Tidak ada pesan Cosmos untuk create/mint/burn; creation hanya lewat precompile factory `0x…0901`, supply hanya lewat precompile minter `0x…0902` |
| 11 | Precompile factory dan minter **statis**; token itu sendiri **dinamis** per denom |
| 12 | Mint dibatasi `2^256-1`; burn hanya dari saldo controller sendiri |
