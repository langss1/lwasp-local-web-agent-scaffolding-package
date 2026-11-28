# Peta Reviewer → Hasil Uji (FINAL, angka aktual)
### IJIES 20267726 — pod campaign selesai 2026-11-26 (8/8 poin pod TERJAWAB)

> Pembaruan dari `PETA_REVIEWER_KE_EKSPERIMEN.md` (yang masih "[akan dihasilkan]").
> Di sini tiap poin reviewer dipetakan ke **angka aktual** + status.
> Unit = **OSR** (objective success rate) yang dikreditkan **oracle bukti deterministik independen**.

## Ringkasan status

| Poin | Inti komentar reviewer | Fase | Hasil aktual | Status |
|---|---|---|---|---|
| **R2-D** | uji **interaksi** komponen multiseed, preregistered (bukan LOO single-seed) | P0/P1 | Interaksi RAG×Guardrail **0.0pp** CI[−10.3,+10.3]; RAG main **+8.6pp** tapi **+0.6pp tanpa XSS**; guardrail ≈0 | ✅ **TERJAWAB** |
| **R2-A** | pisahkan **orkestrasi** vs **akses** eksekusi/verifikasi; +simple agent tool-matched; 36/63 gain di XSS | P2 + P4 | base 33.3 / **simple 59.3** / full 63.0. Akses(base→simple) +25.9pp, **orkestrasi(simple→full) +3.7pp p=1.0 n.s.** | ✅ **TERJAWAB** |
| **R2-B** | bukti penegasan dipilih **sebelum** lihat hasil, paket+scoring **dibekukan**, arm jalan bareng state identik | P2 | prereg beku `freeze_sha=b80a1a58`, interleaved reset/unit, 81/81 sel valid | ✅ **TERJAWAB** |
| **R1-B** | Full punya browser+verify, Base HTTP saja — kesempatan dikreditkan **sama**? | P2 + P4 | opportunity-parity: kelas xss_* ditandai, base tak berkesempatan → klaim orkestrasi hanya dari simple→full (bukti setara) | ✅ **TERJAWAB** |
| **R1-E** | bandingkan dari **snapshot bersih** di fresh interleaved run; rekam reset (cookie/konten/stored-XSS) | P2 + P4 | `confirmatory_tierB_reset_log.csv` (reset/unit); P4 guestbook di-truncate **per-case** di instance terisolasi | ✅ **TERJAWAB** |
| **R1-A** | dokumentasikan **oracle** tiap skenario (efek/prasyarat/bukti/reset) — khusus stored/DOM | P4 | **40/51 (78%)** sukses stored/DOM XSS **terkonfirmasi independen** + screenshot (dom 22/27, stored 18/24) | ✅ **TERJAWAB** |
| **R1-I** | pisah waktu **generasi/aksi/verifikasi**; kenapa Base 15 iter, Full stop lebih awal | **P3** | 10 run instrumen (base+full×5 skenario×q35×s42). **Base mean it=15.0 SEMUA exhausted, ver=0.00** (bahkan saat sukses) — tak punya verifier → tak bisa early-stop. **Full mean it=4.8 SEMUA success** (early-stop). gen=73% wall (base). Dekomposisi eksak (resid 0.000s, 10/10) | ✅ **TERJAWAB** |
| **R1-G** | artefak reproduksi + run-ledger per-run + digest bobot | P8 | `repro_artifact/`: ledger **3908 run** + `digests.json` (sha256 bobot+versi) + oracle_spec(68) + tarball | ✅ **TERJAWAB** (tinggal rilis GitHub) |

## Benang merah (konsisten di semua fase)
Semua bukti menunjuk satu kesimpulan: **akses/tool adalah bottleneck, orkestrasi scaffolding TIDAK terkonfirmasi signifikan** pada skala ini. Diperkuat lintas:
- q25 2×2 (R2-D): manfaat RAG terkonsentrasi di XSS, interaksi nol.
- P2 confirmatory (R2-A/B): orkestrasi simple→full p=1.0.
- confirm3 cross-app (lama): akses p=0.016 sig, orkestrasi p=0.375 n.s.
- K1 interleaved (lama): full vs simple n.s.

Dan sukses XSS yang jadi tumpuan gain itu **terbukti nyata** (P4, 78% reconfirmed) → bukan artifact crediting.

## R1-I — SELESAI (2026-11-26)
Dijalankan di pod (10 run, base+full × 5 skenario × q35 × seed42). Hasil di `P3_TIMING_BREAKDOWN_HASIL.md`:
- **Base: mean it=15.0, finish_reason=exhausted 5/5, verify_time=0.00s** — termasuk 3 run yang SUKSES tapi tetap habiskan 15 iter → Base tak bisa mengenali suksesnya sendiri (tak ada verifier) → tak pernah early-stop.
- **Full: mean it=4.8, finish_reason=success 5/5** (early-stop).
- **Generasi dominan** (73% wall Base vs 31% Full); Full ~2.8× lebih cepat per attempt **murni karena early-stop**, bukan generasi lebih cepat.
- Validitas: `gen+action+verify+other = wall` resid 0.000s di 10/10.
- Catatan jujur: verify_time kecil (~0 kecuali full/xss_reflected 2.5s) → ini **asimetri kontrak-stopping** (punya sinyal stop atau tidak), bukan "verifikasi mahal".

## Poin non-pod (ranah tulisan/editorial — bukan ranah Claude nulis naskah)
| Poin | Penanganan | Status |
|---|---|---|
| R1-C audit-buta | analisis lokal, sampel+kunci ada | belum dijalankan |
| R1-D manifest + tanggal freeze | tulis di naskah §4.1 | naskah |
| R1-F rekonsiliasi 35 vs 76 (116/120) | `cumulative_coverage_linkage.csv` → tabel | data ada, prosa belum |
| R1-H pemisahan fold C2/N3 | prosa §3.4/3.5 + tabel per-kelas | belum |
| R2-C controller publik (CVE-Bench/PentestGPT) | 1 controller legacy subset / fallback dokumentasi batas | keputusan GPT |
| R2-E pairing retry + canary | `k2_retry_paired.csv`, `k2_canary.csv` | data ada, prosa belum |
| R2-F bWAPP matched + sensitivitas | `external_*.csv` | sebagian |
| Editor CoI + Author Contributions | tambah 2 bagian + URL repo | belum |

## File hasil (lokal `revision/ijies426/results/`)
- `K2B_Q25_INTERACTION_HASIL.md` (R2-D) · `K2_P2_CONFIRMATORY_TIERB_HASIL.md` (R2-A/B/R1-B/E) · `P4_STORED_DOM_XSS_ADJUDICATION_HASIL.md` (R1-A) · `repro_artifact/` (R1-G)
