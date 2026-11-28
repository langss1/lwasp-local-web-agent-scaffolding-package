# Data untuk 6 poin sisa (R1-D, R1-F, R1-H, R2-E, R2-F, R1-C)
### IJIES 20267726 — angka aktual dari file lokal, dengan catatan JUJUR
> Dihitung 2026-11-26 dari: `analysis/cumulative_coverage_linkage.csv`, `k2_retry_paired.csv`, `k2_canary.csv`, `results/confirm3_bwapp.csv`, `reproduction/analysis/c2_reconstructed_fold_membership.csv`, `results/k1_stored_dom_adjudicated.csv`, `k1_data/freeze_manifest.json`.
> ⚠️ = temuan yang MENGUBAH narasi; harus diframing jujur, jangan diklaim mulus.

---

## R1-F — Rekonsiliasi akun run + 116/120 ✅ (bersih)
Dari `cumulative_coverage_linkage.csv` (**120 sel = 40 skenario × 3 seed**):
- initial_status: **success 94**, observed_failure 23, no_report 3.
- Canonical-probe: **26 sel** diprobe-ulang → **22 sukses**.
- **Cumulative coverage = 116/120**; **remaining_unresolved = 4** (3 no_report + 1 gagal-tak-terpulihkan).
- Rekonsiliasi: **94 (sukses awal) + 22 (terpulihkan via probe) = 116.** "Unresolved" = sel yang tak pernah membuahkan bukti tereksekusi (4).
- **Penting (jawab kritik "run vs cell"):** angka 116/120 adalah **CELL** (skenario×seed), bukan eksekusi. Satu cell unresolved bisa punya >1 eksekusi (awal + probe). Tabel linkage memetakan tiap cell → `original_run_id` + `canonical_probe_run_id`.

**Untuk prosa §4.1/§5.5:** sajikan dua kolom — "distinct executions" vs "cells" — supaya 35 (§4.1) dan enumerasi §5.5 tak dibaca sebagai set terpisah yang dijumlahkan. Linkage per-cell ada di CSV.

---

## R1-H — Pemisahan fold C2 + N3 ✅ (dengan caveat)
C2 (`c2_reconstructed_fold_membership.csv`): **42 baris, 10 run unik, 5 fold ber-grup** (ukuran 8–9/fold), label **13 positif / 29 negatif**.
- ⚠️ **Caveat jujur (ada di kolom `provenance`):** fold ini **rekonstruksi deterministik dari kode+jejak arsip, BUKAN manifest fold historis yang tersimpan**. Harus ditulis apa adanya: "grouped-fold composition reconstructed from archived traces; the original saved fold manifest was not recovered."
- Fitur C2 & seleksi model dilakukan **di dalam fold** (grouped by run_id → payload berulang tak bocor lintas fold).

N3 (sudah, `n3_independent.csv`): **P0 macro-F1 0.684 ≫ N3 0.157** di XVWA (app dikecualikan). N3 kolaps ke `blind_bit_true`. → N3 = **auxiliary**, bukan oracle lintas-app.

---

## R1-C — Audit konsistensi buta-arm ✅ (jujur tentang batasnya)
Dari `k1_stored_dom_adjudicated.csv` (**51 adjudikasi**):
- **40 credited-positif**: **40/40** punya sinyal deterministik + screenshot.
- **11 credited-negatif**: **11/11** memang TAK punya sinyal terverifikasi.
- **Isolation proof: 51/51** (DB `dvwa_iso` terpisah, guestbook truncated per-case).
- **Konsistensi 100%** antara verdict ↔ bukti deterministik.

⚠️ **Framing jujur (WAJIB):** ini **audit konsistensi yang buta-terhadap-arm secara konstruksi** (oracle tak pernah membaca label arm / klaim FINISH agen), **bukan** re-adjudikasi oleh auditor manusia pihak-ketiga. Tulis sebagai: "oracle is blind-by-construction to the agent condition; a consistency audit of 40 positive and 11 negative adjudications showed 100% agreement between verdict and deterministic evidence. A separate third-party human blind audit was not conducted (limitation)." → **memenuhi semangat R1-C tanpa overclaim.**

---

## R1-D — Manifest fase + tanggal pembekuan 🟡 (parsial jujur)
- **K1:** `freeze_manifest.json` → **frozen_utc = 2026-11-22**, pod/pin model (Qwen2.5 845dbda0ea48, Qwen3.5 56671c2ab938, nomic 0a109f422b47), Q4_K_M, budget, stopping_contract, seeds — **LENGKAP & berdate** ✅.
- **K2:** `freeze_sha = b80a1a58` (paket+scoring beku sebelum run) ✅.
- ⚠️ **K3 & K4:** file `k3_prereg.draft.json` / `k4_prereg.draft.json` masih **berstatus DRAFT "NOT final, NOT freezable yet"** — **prareg formal tak pernah dibekukan+ditanggali**. K3/K4 dijalankan dengan **kondisi terpin** (app/testbed/commit pinned di manifest) tapi **bukan** prareg bertanggal.
  - **Framing jujur:** "K1 and the K2 2×2 were pre-registered and frozen (2026-11-22; freeze_sha b80a1a58). K3 (N3 independent testbed) and K4 (controller) were executed under pinned, documented conditions (testbed commit and model digests fixed in the manifests) but a formal dated pre-registration was not finalized for these two; their estimates are reported as confirmatory-descriptive accordingly." → **jangan klaim K3/K4 preregistered.**

---

## R2-E — Efek remediasi (pairing) + canary ⚠️ TEMUAN NULL (harus jujur)
`k2_retry_paired.csv` (10 pasang tercocok, kohort MEDIUM-level yang gagal awal: cmdi/csrf/fi/js/sqli_medium):
- **fix-OFF sukses 0/10, fix-ON sukses 0/10, recovered 0/10, rule_fired = "none" di SEMUA 10.**
- → Pada kohort berpasangan ini, **mekanisme fix tak terpicu dan TIDAK ada efek remediasi terukur (nol).**

`k2_canary.csv` (12 sel yang SEBELUMNYA sukses, dijalankan ulang di jalur fix-eligible):
- **still_success = 2/12** (hanya open_redirect_medium ×2); 2 sel xss_dom tak ada data; **8/12 sel sukses-sebelumnya TIDAK reproduksi.**
- → Menunjukkan **variansi run-ke-run tinggi** (ketidakstabilan stokastik), bukan efek fix.

⚠️ **Ini TIDAK kontradiktif dengan 116/120 bila diframing benar:**
- 116/120 (R1-F) = **cakupan kumulatif** (cell yang pernah terpecahkan di attempt mana pun, arm FULL, skenario primer) → `dfail-FULL-*`.
- R2-E = **estimasi efek-fix berpasangan** pada kohort medium yang lebih sulit (`k2retry-coh-*`) → **nol + canary tak stabil.**
- **Framing jujur (ini justru yang diminta R2):** "Under matched pairing on a harder medium-level cohort, the remediation rule did not fire and produced no measurable recovery effect (0/10); a canary regression check reproduced only 2/12 previously-successful cells, indicating run-to-run stochasticity. We therefore report cumulative coverage (116/120) as a coverage metric under repeated attempts, NOT as a validated remediation-fix effect." → **menghapus risiko overclaim "fix memulihkan".**

---

## R2-F — Sensitivitas bWAPP ⚠️ (base-success semua ambigu; angka "3" tak cocok)
`results/confirm3_bwapp.csv` (10 skenario × 3 seed × 2 arm = 60 run):
| Arm | OSR (oracle-credited) | OSR (self-verified only) |
|---|---|---|
| base | **15/30 = 0.500** | **0/30 = 0.000** |
| full | **25/30 = 0.833** | **22/30 = 0.733** |

- ⚠️ **SEMUA 15 "sukses" Base ber-`finish_reason=exhausted`** (base tak pernah verifikasi-diri; jalan penuh 15 iter, dikreditkan oracle eksternal) — identik pola DVWA (R1-I).
- **Sensitivitas:** kalau kriteria sukses menuntut verifikasi-diri agen, **Base OSR jatuh 0.500 → 0.000** (Δ −0.500); Full 0.833 → 0.733. → Keunggulan apparent Base di bWAPP **seluruhnya** artefak crediting-eksternal run exhausted.
- ⚠️ **Diskrepansi angka:** reviewer menyebut **"three unreconciled bWAPP Base runs"**, tapi kohort `confirm3_bwapp` ini punya **15 run Base ambigu** (semua sukses Base). Kemungkinan "3" merujuk kohort bWAPP lama yang berbeda. **Perlu direkonsiliasi oleh penulis** — jangan diam-diam ganti 3→15 tanpa penjelasan.
- **Framing jujur:** laporkan matched per-skenario + sensitivitas di atas; nyatakan transfer bWAPP **terbatas** (konsisten OR lemah di memo lama), bukan bukti pentest penuh.

---

## Ringkasan aksi
| Poin | Data | Status jujur |
|---|---|---|
| R1-F | 116/120 linkage bersih | ✅ tinggal prosa (run-vs-cell) |
| R1-H | C2 5-fold (rekonstruksi) + N3 | ✅ dgn caveat "reconstructed" |
| R1-C | konsistensi buta-arm 100% (40/40, 11/11) | ✅ dgn batas "bukan audit manusia pihak-3" |
| R1-D | K1/K2 beku+berdate; **K3/K4 DRAFT** | 🟡 jangan klaim K3/K4 preregistered |
| **R2-E** | **recovery NULL 0/10, canary 2/12** | ⚠️ frame sbg coverage, BUKAN efek-fix |
| **R2-F** | **base 0.5→0.0 sensitivitas; "3"≠15** | ⚠️ rekonsiliasi angka + transfer terbatas |

**Intinya (fakta):** 3 poin bersih (R1-F/H/C) siap prosa; R1-D jujur-parsial (K3/K4 tak ter-prareg); **R2-E dan R2-F mengandung temuan yang membatasi klaim** (recovery tak terbukti sbg efek-fix; keunggulan Base bWAPP artefak crediting). Semua ini **memperkuat kredibilitas** kalau ditulis jujur — tak satu pun menggugurkan temuan inti (akses > orkestrasi).
