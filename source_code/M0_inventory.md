# M0 — Definisi & Inventaris (deliverable gate, plan9.md §12)

> 2026-10-18. Observasi-saja (belum training/pentest). Output M0 wajib tuntas sebelum M1.
> Keputusan: **HOLDOUT = bWAPP** (modul paling mirip DVWA → perbandingan paling adil).
> **Scope N3 awal = SQLi + boolean-blind SQLi + reflected XSS.**

---

## 1. TEMUAN KRITIS — trace lama TIDAK cukup untuk fitur ML
388 run di `runs/`. Tiap record `trace.jsonl` cuma menyimpan:

| Tersimpan (observation) | Buat ML? |
|---|---|
| `success` (label lemah dari regex), `signal`, `error_sig` (1 marker) | label lemah OK |
| `http_status`, `resp_len` (panjang saja) | fitur kasar OK |
| `prior_response_sig` = `"status:len:hash16"` | signature, bukan isi |
| `screenshot` (path) | bukti visual |
| timestamp per-record (wall-clock tulis trace) | bukan latency per-request |

**Yang TIDAK ada di trace lama (padahal dibutuhkan N3/N2):**
1. **Body respons mentah** attempt serangan — hanya ada `body_excerpt[:1500]` untuk aksi **OBSERVE** saja
   (orchestrator.py:811), BUKAN untuk HTTP_REQUEST. → fitur refleksi/char-diff/row-recount **tak bisa** dari trace lama.
2. **Timing per-request** (`elapsed_s`) — ADA di objek `HttpResponse` (http_client.py:26) tapi **tak ditulis** ke trace. → fitur time-based blind **tak tersedia** di data lama.
3. **Baseline/kontrol** (respons benign / pasangan true-false predicate) — **tak pernah disimpan**. → diferensial N3 **tak bisa** direkonstruksi.

**KESIMPULAN (konfirmasi warning audit #8):** `runs/` lama = **hanya** untuk audit label/skenario, **BUKAN**
sumber fitur N3/N2. Asumsi lama "data latih gratis dari runs/" → **GUGUR.** Dataset harus dibangun lewat
**instrumentasi + data-collection pass di DEV**.

## 2. Kabar baik — instrumentasi MURAH (runtime sudah punya datanya)
- `HttpResponse` sudah bawa `body`, `status_code`, `elapsed_s`, `length` (http_client.py:22-31).
- Orchestrator sudah pegang `self._last_resp_body` (orchestrator.py:508).
→ Tinggal **persist** `body` + `elapsed_s` + rekam **baseline/kontrol** ke trace. Observation-only, nol ubah perilaku agent.

## 3. Manifest model & resource (dibekukan)
| Item | Nilai |
|---|---|
| LLM | `qwen2.5:latest` **digest `845dbda0ea48`**, arch qwen2, **7.6B**, **Q4_K_M**, ctx-model 32768 |
| Runtime cap | num_ctx **5120**, num_predict 800, num_thread 8, temp 0.2, top_p 0.9 |
| Embedding | nomic-embed-text (Ollama, dim 3584) / all-MiniLM-L6-v2 (offline) |
| Host | Ollama @127.0.0.1:11434; RTX 2050 **4GB VRAM** + CPU offload; **ukur RAM sistem + waktu end-to-end**, bukan cuma VRAM |
| Offline | matikan SEMUA fallback cloud saat kondisi "offline" diklaim |
| Catatan | ada juga `qwen3.5:latest` (6488c96fa5fa) di mesin — **JANGAN** kepakai; kunci ke qwen2.5 digest di atas |

## 4. Objective + verifier per keluarga (scope awal) — verifier INDEPENDEN, bukan N3
| Keluarga | Objective (sama di semua kondisi) | Verifier independen (ground-truth) |
|---|---|---|
| SQLi (union/error) | ekstrak baris > 1 baris sah | hitung baris + konten DB-backed; **bukan** prediksi N3 |
| boolean-blind SQLi | buktikan kendali boolean via pasangan predicate true/false terkontrol | diff respons pasangan terkontrol; objektif = kendali boolean (BUKAN ekstraksi penuh) |
| reflected XSS | eksekusi skrip di browser | **Playwright** eksekusi nyata (bukan sekadar refleksi string) |

Aturan: model yang diuji (N3) **tak boleh** jadi ground-truth bagi dirinya sendiri. Verifier di atas =
sumber label & penilaian sukses, terpisah dari N3 & dari evaluator.

## 5. Budget & reset (dibekukan, disamakan antar-kondisi)
- Budget iterasi: ditetapkan sama per sel matriks (pilih di pilot DEV; catat berapa kali controller aktif).
- `max_wall_clock_s` konsisten; reset password DVWA MD5('password') tiap run (`eval/reset_dvwa.sh`); set security-level eksplisit tiap run.
- Biaya verifikasi & aksi kontrol dihitung ke dalam budget secara konsisten (jangan ada oracle tersembunyi).

## 6. Daftar DELTA kode (yang akan disentuh di M1+; semua di belakang toggle)
| Tujuan | File | Perubahan | Jenis |
|---|---|---|---|
| Rekam body+timing | `src/orchestrator.py` (jalur HTTP_REQUEST ~935-975) | tulis `body` (atau excerpt cukup panjang) + `elapsed_s` ke observation trace | observation-only |
| Rekam baseline/kontrol | `src/orchestrator.py` + `src/action/http_client.py` | per attempt, simpan respons benign/pasangan predicate | observation-only |
| N3 oracle (toggle) | `src/orchestrator.py` `interpret_*` | bungkus di balik toggle `eyes=ml|regex` | fitur baru, default OFF |
| N2 controller (toggle) | `src/reasoning/state_graph.py` (`branch_dead`,`unexplored_nodes`,`jumpable_nodes`,`jump_to`,`update_node`) + loop orchestrator | kebijakan progress-protection + isi `node.score` dgn promise; **satukan di 4 jalur** | fitur baru, default OFF |
| requirements | `requirements.txt` | tambah `scikit-learn` | dependency |

## 7. Status gate M0
- [x] Field trace aktual terinventaris → **tidak cukup untuk fitur** (butuh instrumentasi).
- [x] Manifest model/resource dibekukan.
- [x] Objective + verifier independen per keluarga (scope awal) terdefinisi.
- [x] Aturan budget/reset terdefinisi.
- [x] Daftar delta kode tersusun.
- [x] Keputusan: holdout=bWAPP; scope N3=SQLi/blind/reflected-XSS.

**→ Lanjut M1:** tambah instrumentasi (delta #1 & #2, observation-only) → jalankan **data-collection pass
di DVWA** (localhost) untuk membangun dataset fitur+label terverifikasi. Ini eksekusi agent pertama
(observasi, bukan uji metode) — localhost, sesuai policy.
