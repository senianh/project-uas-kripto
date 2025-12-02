# Nama Program  : app.py
# Nama Anggota  : Adelia Felisha | Nikita Putri Prabowo | Senia Nur Hasanah 
# NPM           : 140810230003   |      140810230010    |   140810230021
# Tanggal Buat  : Jumat, 19 November 2025
# Deskripsi     : Membuat Program Vigenere Cipher

import streamlit as st
import string
import hashlib
import binascii
import math
import secrets


# ==============================
# PAGE CONFIG 
# ==============================
st.set_page_config(page_title="VigiVault – Vigenere Classic & Bytewise", page_icon="🔐", layout="wide")


ACCENT = {
    "primary": "#2563eb",
    "primarySoft": "#eaf2ff",
    "ink": "#0b1220",
    "bg": "#f8fafc",
    "card": "#ffffff",
    "muted": "#64748b",
    "border": "#e5e7eb",
    "good": "#16a34a",
    "warn": "#d97706",
    "bad": "#dc2626",
}

# ==============================
# INJECT CSS VARIABLES
# ==============================
st.markdown(f"""
<style>
:root {{
  --primary: {ACCENT['primary']};
  --primarySoft: {ACCENT['primarySoft']};
  --ink: {ACCENT['ink']};
  --bg: {ACCENT['bg']};
  --card: {ACCENT['card']};
  --muted: {ACCENT['muted']};
  --border: {ACCENT['border']};
  --good: {ACCENT['good']};
  --warn: {ACCENT['warn']};
  --bad: {ACCENT['bad']};
}}
</style>
""", unsafe_allow_html=True)


# ==============================
# LOAD EXTERNAL CSS
# ==============================
def load_css():
    with open("style.css") as f:
        css = f.read()
        st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)

load_css()


# ==============================
# HEADER
# ==============================
st.markdown(
    f"""
    <div class="app-title">
      <h1>🔐 VigiVault — Vigenere Classic (Text) & Byte-wise (File)</h1>
      <div class="subtitle">Mode TEKS mengikuti Vigenere klasik (A–Z, mod 26). Mode FILE memakai Vigenere byte-wise (0–255, mod 256).</div>
      <div style="margin-top:10px; display:flex; gap:8px; flex-wrap:wrap">
        <div class="badge"><span class="dot"></span> A–Z mod 26</div>
        <div class="badge"><span class="dot"></span> Bytes mod 256</div>
        <div class="badge"><span class="dot"></span> Hex Preview</div>
        <div class="badge"><span class="dot"></span> Re-encrypt Verify</div>
        <div class="badge"><span class="dot"></span> Compare Mode</div>
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# ==============================
# UTILS
# ==============================
def hex_preview(b: bytes, n: int = 64) -> str:
    if not b:
        return "(kosong)"
    head = b[:n]
    hx = binascii.hexlify(head).decode("ascii")
    bytes_list = [hx[i:i+2] for i in range(0, len(hx), 2)]
    lines = []
    for i in range(0, len(bytes_list), 16):
        chunk = bytes_list[i:i+16]
        raw = head[i:i+16]
        ascii_col = "".join([chr(c) if 32 <= c <= 126 else "." for c in raw])
        lines.append(f"{i:04x}  " + " ".join(chunk).ljust(16*3-1) + "  |" + ascii_col + "|")
    return "\n".join(lines)

def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def shannon_entropy(b: bytes) -> float:
    if not b:
        return 0.0
    from collections import Counter
    cnt = Counter(b); total = len(b); ent = 0.0
    for c in cnt.values():
        p = c / total
        ent -= p * math.log2(p)
    return ent

def clean_filename(name: str, remove_spaces: bool = False) -> str:
    if not name:
        return name
    base = name
    if remove_spaces:
        base = base.replace(" ", "_")
    return base.replace("(", "").replace(")", "")

def estimate_key_strength(key: str) -> dict:
    length = len(key)
    classes = {
        "lower": any(c.islower() for c in key),
        "upper": any(c.isupper() for c in key),
        "digit": any(c.isdigit() for c in key),
        "other": any(not c.isalnum() for c in key),
    }
    pool = (26 if classes["lower"] else 0) + (26 if classes["upper"] else 0) + (10 if classes["digit"] else 0) + (32 if classes["other"] else 0)
    entropy_bits = length * (math.log2(pool) if pool>0 else 0)
    if length == 0: level = "empty"
    elif entropy_bits < 32: level = "weak"
    elif entropy_bits < 64: level = "fair"
    elif entropy_bits < 96: level = "strong"
    else: level = "very strong"
    return {"length": length, "pool": pool, "entropy_bits": entropy_bits, "level": level}

def random_key(n: int, include_symbols: bool=True) -> str:
    alphabet = string.ascii_letters + string.digits + ("!@#$%^&*()-_=+[]{};:,.?/" if include_symbols else "")
    return "".join(secrets.choice(alphabet) for _ in range(n))

# ==============================
# VIGENERE CLASSIC (A–Z)
# ==============================
ALPHABET = string.ascii_uppercase
def _clean_key_alpha(key: str) -> str:
    return "".join([c for c in key.upper() if c.isalpha()])

def vigenere_encrypt_classic(pt: str, key: str, keep_non_letters: bool = True) -> str:
    key = _clean_key_alpha(key)
    if not key:
        raise ValueError("Key harus berisi huruf A–Z.")
    res = []; j = 0
    for ch in pt:
        if ch.isalpha():
            p = (ord(ch.upper()) - 65)
            k = (ord(key[j % len(key)]) - 65)
            c = (p + k) % 26
            out = chr(c + 65)
            out = out if ch.isupper() else out.lower()
            res.append(out); j += 1
        else:
            res.append(ch if keep_non_letters else "")
    return "".join(res)

def vigenere_decrypt_classic(ct: str, key: str, keep_non_letters: bool = True) -> str:
    key = _clean_key_alpha(key)
    if not key:
        raise ValueError("Key harus berisi huruf A–Z.")
    res = []; j = 0
    for ch in ct:
        if ch.isalpha():
            c = (ord(ch.upper()) - 65)
            k = (ord(key[j % len(key)]) - 65)
            p = (c - k) % 26
            out = chr(p + 65)
            out = out if ch.isupper() else out.lower()
            res.append(out); j += 1
        else:
            res.append(ch if keep_non_letters else "")
    return "".join(res)

# ==============================
# VIGENERE BYTE-WISE (0–255)
# ==============================
def vigenere_encrypt_bytes(data: bytes, key: str) -> bytes:
    if not key:
        raise ValueError("Key tidak boleh kosong.")
    key_bytes = key.encode("utf-8")
    out = bytearray(); klen = len(key_bytes)
    for i, b in enumerate(data):
        out.append((b + key_bytes[i % klen]) % 256)
    return bytes(out)

def vigenere_decrypt_bytes(data: bytes, key: str) -> bytes:
    if not key:
        raise ValueError("Key tidak boleh kosong.")
    key_bytes = key.encode("utf-8")
    out = bytearray(); klen = len(key_bytes)
    for i, b in enumerate(data):
        out.append((b - key_bytes[i % klen]) % 256)
    return bytes(out)

# ==============================
# SIDEBAR (SETTINGS)
# ==============================
st.sidebar.header("⚙️ Pengaturan")
mode = st.sidebar.radio("Pilih Mode", ["Teks (Vigenere klasik A–Z)", "File (Byte-wise 0–255)"])
st.sidebar.markdown("---")
st.sidebar.write("**Catatan**")
st.sidebar.write("• Mode TEKS: hanya huruf A–Z diproses (mod 26).")
st.sidebar.write("• Mode FILE: seluruh byte diproses (mod 256), aman untuk semua tipe file.")
st.sidebar.write("• Simpan hasil enkripsi sebagai **.enc** (biner).")
st.sidebar.markdown("---")

with st.sidebar.expander("🔑 Manajemen Key"):
    c1, c2 = st.columns([2,1])
    with c1:
        key_len = st.slider("Panjang random key", min_value=8, max_value=64, value=16, step=1)
    with c2:
        inc_sym = st.checkbox("Pakai simbol", value=True)
    if st.button("Generate Random Key"):
        st.session_state["random_key"] = random_key(key_len, inc_sym)
        st.toast("Random key digenerate. Scroll ke panel key untuk melihat.", icon="🧪")

# ==============================
# MODE TEKS
# ==============================
if mode.startswith("Teks"):
    st.subheader("📝 Vigenere Klasik (A–Z, mod 26)")
    keep_non = st.checkbox("Pertahankan spasi/tanda baca (lewati non-huruf)", value=True)

    with st.container():
        st.markdown("**Key (huruf A–Z saja)**")
        colk1, colk2, colk3 = st.columns([2,1,1])
        with colk1:
            key_input_text = st.text_input("Key klasik", placeholder="Contoh: LUL", label_visibility="collapsed")
        with colk2:
            if st.session_state.get("random_key"):
                st.info(f"Random: {st.session_state['random_key']}", icon="🎲")
        with colk3:
            st.caption("Gunakan huruf A–Z saja.")

    tab_enc, tab_dec = st.tabs(["🔒 Enkripsi Teks", "🔓 Dekripsi Teks"])

    with tab_enc:
        pt = st.text_area("Plaintext", height=160, placeholder="Contoh: OMEGA atau kalimat bebas…")
        if st.button("🔒 Enkripsi", key="enc_text_btn"):
            if not pt:
                st.warning("Plaintext tidak boleh kosong.")
            elif not key_input_text:
                st.warning("Key tidak boleh kosong.")
            else:
                try:
                    ct = vigenere_encrypt_classic(pt, key_input_text, keep_non_letters=keep_non)
                    st.success("Berhasil dienkripsi (Vigenere klasik).")
                    st.markdown("**Ciphertext**")
                    st.code(ct)
                    st.download_button("💾 Download Ciphertext (.txt)", data=ct.encode("utf-8"),
                                       file_name="ciphertext_vigenere_classic.txt", mime="text/plain")
                except Exception as e:
                    st.error(f"Gagal enkripsi: {e}")

    with tab_dec:
        ct_in = st.text_area("Ciphertext", height=160, placeholder="Contoh: ZGPRU")
        if st.button("🔓 Dekripsi", key="dec_text_btn"):
            if not ct_in:
                st.warning("Ciphertext tidak boleh kosong.")
            elif not key_input_text:
                st.warning("Key tidak boleh kosong.")
            else:
                try:
                    pt_out = vigenere_decrypt_classic(ct_in, key_input_text, keep_non_letters=keep_non)
                    st.success("Berhasil didekripsi (Vigenere klasik).")
                    st.markdown("**Plaintext**")
                    st.code(pt_out)
                except Exception as e:
                    st.error(f"Gagal dekripsi: {e}")

# ==============================
# MODE FILE
# ==============================
else:
    st.subheader("📁 Vigenere Byte-wise (0–255, mod 256) untuk File")

    with st.container():
        st.markdown("**Key (byte-wise, bebas karakter)**")
        col1, col2 = st.columns([3,1])
        with col1:
            show_key = st.toggle("Tampilkan key", value=False)
            default_key = st.session_state.get("random_key", "")
            keyf = st.text_input("Key", value=default_key, type=("default" if show_key else "password"),
                                 placeholder="Masukkan key", label_visibility="collapsed")
        with col2:
            kinfo = estimate_key_strength(keyf)
            level_color = {"empty":"#94a3b8","weak":ACCENT["bad"],"fair":ACCENT["warn"],"strong":ACCENT["good"],"very strong":ACCENT["primary"]}[kinfo["level"]]
            st.markdown(f"""
            <div class="soft-card kpi">
                <div class="muted">Kekuatan Key</div>
                <div style="font-size:1.15rem; font-weight:800; color:{level_color}">{kinfo['level'].upper()}</div>
                <div class="muted">Entropi ≈ {kinfo['entropy_bits']:.1f} bit</div>
            </div>
            """, unsafe_allow_html=True)

    tab_enc_f, tab_dec_f, tab_examples, tab_compare = st.tabs(["🔒 Enkripsi File", "🔓 Dekripsi File", "📦 Contoh File", "🆚 Compare Mode"])

    # -------- ENKRIPSI --------
    with tab_enc_f:
        st.markdown("**Upload file** untuk dienkripsi")
        f = st.file_uploader("Pilih file", type=None, key="enc_file")

        ctop1, ctop2 = st.columns([1,1])
        with ctop1:
            show_preview = st.checkbox("Preview 64B & info file", value=True, key="pv_enc")
        with ctop2:
            rename_opt = st.checkbox("Bersihkan nama (.enc): ganti spasi & hapus ( )", value=False)

        if f is not None and show_preview:
            data0 = f.getvalue()
            e0 = shannon_entropy(data0)
            a, b, c = st.columns([1,1,2])
            with a:
                st.markdown('<div class="soft-card"><h4>Info Asli</h4><div class="muted">Size</div><div class="kpi">'
                            f'{len(data0)}</div><div class="muted">SHA-256</div><div class="kpi">{sha256(data0)[:16]}…</div></div>', unsafe_allow_html=True)
            with b:
                st.markdown(f'<div class="soft-card"><h4>Entropy Asli</h4><div class="kpi">{e0:.3f}</div><div class="muted">maks 8</div></div>', unsafe_allow_html=True)
            with c:
                st.markdown('<div class="soft-card"><h4>64 byte pertama (hex)</h4>', unsafe_allow_html=True)
                st.markdown(f'<div class="hexbox">{hex_preview(data0, 64)}</div>', unsafe_allow_html=True)
                st.markdown('</div>', unsafe_allow_html=True)

        if st.button("🔒 Enkripsi Sekarang"):
            if f is None:
                st.warning("Silakan upload file terlebih dahulu.")
            elif not keyf:
                st.warning("Key tidak boleh kosong.")
            else:
                try:
                    data = f.getvalue()
                    cipher = vigenere_encrypt_bytes(data, keyf)
                    out_name = f.name + ".enc"
                    if rename_opt:
                        out_name = clean_filename(out_name, remove_spaces=True)

                    st.session_state["last_original_name"] = f.name
                    st.session_state["last_encrypted_name"] = out_name

                    e1 = shannon_entropy(cipher)
                    s1, s2, s3 = st.columns([1,1,2])
                    with s1:
                        st.markdown('<div class="soft-card"><h4>Info Cipher</h4><div class="muted">Size</div>'
                                    f'<div class="kpi">{len(cipher)}</div><div class="muted">SHA-256</div>'
                                    f'<div class="kpi">{sha256(cipher)[:16]}…</div></div>', unsafe_allow_html=True)
                    with s2:
                        st.markdown(f'<div class="soft-card"><h4>Entropy Cipher</h4><div class="kpi">{e1:.3f}</div></div>', unsafe_allow_html=True)
                    with s3:
                        st.markdown('<div class="soft-card"><h4>64 byte pertama Cipher (hex)</h4>', unsafe_allow_html=True)
                        st.markdown(f'<div class="hexbox">{hex_preview(cipher, 64)}</div>', unsafe_allow_html=True)
                        st.markdown('</div>', unsafe_allow_html=True)

                    st.success("File berhasil dienkripsi!")
                    st.download_button("💾 Download File Terenkripsi (.enc)", data=cipher,
                                       file_name=out_name, mime="application/octet-stream")
                    st.info(f"Nama asli disimpan: `{f.name}` → otomatis dipakai sebagai prefill di tab Dekripsi.", icon="💡")
                except Exception as e:
                    st.error(f"Gagal enkripsi file: {e}")

    # -------- DEKRIPSI --------
    with tab_dec_f:
        st.markdown("**Upload file terenkripsi (.enc)** untuk didekripsi")
        fenc = st.file_uploader("Pilih file terenkripsi .enc", type=None, key="dec_file")

        colh1, colh2 = st.columns([2,1])
        with colh1:
            default_hint = st.session_state.get("last_original_name", "")
            hint = st.text_input("Nama file asli (opsional – untuk mengembalikan ekstensi)", value=default_hint, placeholder="misal: gambar.png")
        with colh2:
            show_preview_dec = st.checkbox("Preview 64B & info cipher", value=True, key="pv_dec")

        if fenc is not None and show_preview_dec:
            enc0 = fenc.getvalue()
            e0 = shannon_entropy(enc0)
            a, b, c = st.columns([1,1,2])
            with a:
                st.markdown('<div class="soft-card"><h4>Info Cipher (Input)</h4><div class="muted">Size</div>'
                            f'<div class="kpi">{len(enc0)}</div><div class="muted">SHA-256</div>'
                            f'<div class="kpi">{sha256(enc0)[:16]}…</div></div>', unsafe_allow_html=True)
            with b:
                st.markdown(f'<div class="soft-card"><h4>Entropy Cipher</h4><div class="kpi">{e0:.3f}</div></div>', unsafe_allow_html=True)
            with c:
                st.markdown('<div class="soft-card"><h4>64 byte pertama Cipher (hex)</h4>', unsafe_allow_html=True)
                st.markdown(f'<div class="hexbox">{hex_preview(enc0, 64)}</div>', unsafe_allow_html=True)
                st.markdown('</div>', unsafe_allow_html=True)

        if st.button("🔓 Dekripsi Sekarang"):
            if fenc is None:
                st.warning("Silakan upload file terenkripsi terlebih dahulu.")
            elif not keyf:
                st.warning("Key tidak boleh kosong.")
            else:
                try:
                    enc = fenc.getvalue()
                    plain = vigenere_decrypt_bytes(enc, keyf)

                    if hint.strip():
                        out_name = hint.strip()
                    else:
                        base = fenc.name[:-4] if fenc.name.endswith(".enc") else fenc.name
                        out_name = "decrypted_" + base

                    recheck = vigenere_encrypt_bytes(plain, keyf)
                    ok = (recheck == enc)

                    x1, x2, x3 = st.columns([1,1,2])
                    with x1:
                        st.markdown('<div class="soft-card"><h4>Info Plain (Output)</h4><div class="muted">Size</div>'
                                    f'<div class="kpi">{len(plain)}</div><div class="muted">SHA-256</div>'
                                    f'<div class="kpi">{sha256(plain)[:16]}…</div></div>', unsafe_allow_html=True)
                    with x2:
                        msg = "✅ Re-encrypt cocok" if ok else "❌ Re-encrypt TIDAK cocok"
                        color = ACCENT["good"] if ok else ACCENT["bad"]
                        st.markdown(f'<div class="soft-card"><h4>Verifikasi</h4><div class="kpi" style="color:{color}">{msg}</div></div>', unsafe_allow_html=True)
                    with x3:
                        st.markdown('<div class="soft-card"><h4>64 byte pertama Plain (hex)</h4>', unsafe_allow_html=True)
                        st.markdown(f'<div class="hexbox">{hex_preview(plain, 64)}</div>', unsafe_allow_html=True)
                        st.markdown('</div>', unsafe_allow_html=True)

                    st.success("File berhasil didekripsi!" if ok else "Dekripsi selesai, namun verifikasi ulang gagal.")
                    st.download_button("💾 Download File Hasil Dekripsi", data=plain,
                                       file_name=out_name, mime="application/octet-stream")

                    if not hint.strip():
                        st.info("Isi kolom **Nama file asli** agar ekstensi kembali seperti semula (misal `.pdf`, `.png`).", icon="💡")
                except Exception as e:
                    st.error(f"Gagal dekripsi file: {e}")

    # -------- CONTOH FILE --------
    with tab_examples:
        st.markdown("### 📦 Contoh File Kecil untuk Uji")
        sample_txt = (
            "OMEGA\n"
            "Ini contoh file teks sederhana untuk uji Vigenere byte-wise.\n"
            "Baris 3: 1234567890 !@#$%^&*()_+[]\n"
        ).encode("utf-8")
        sample_csv = (
            "id,name,price\n"
            "p001,Laptop,15000000\n"
            "p002,Keyboard,800000\n"
            "p003,Mouse,250000\n"
        ).encode("utf-8")

        cA, cB = st.columns(2)
        with cA:
            st.markdown('<div class="soft-card"><h4>sample_text.txt</h4>'
                        f'<div class="muted">Size</div><div class="kpi">{len(sample_txt)}</div>'
                        f'<div class="muted">SHA-256</div><div class="kpi">{sha256(sample_txt)[:16]}…</div></div>', unsafe_allow_html=True)
            st.markdown(f'<div class="hexbox">{hex_preview(sample_txt, 64)}</div>', unsafe_allow_html=True)
            st.download_button("⬇️ Download sample_text.txt", data=sample_txt,
                               file_name="sample_text.txt", mime="text/plain")
        with cB:
            st.markdown('<div class="soft-card"><h4>sample_data.csv</h4>'
                        f'<div class="muted">Size</div><div class="kpi">{len(sample_csv)}</div>'
                        f'<div class="muted">SHA-256</div><div class="kpi">{sha256(sample_csv)[:16]}…</div></div>', unsafe_allow_html=True)
            st.markdown(f'<div class="hexbox">{hex_preview(sample_csv, 64)}</div>', unsafe_allow_html=True)
            st.download_button("⬇️ Download sample_data.csv", data=sample_csv,
                               file_name="sample_data.csv", mime="text/csv")

    # -------- COMPARE MODE --------
    with tab_compare:
        st.markdown("Bandingkan dua file: apakah **identik**?")
        c1, c2 = st.columns(2)
        with c1:  fa = st.file_uploader("File A", type=None, key="cmp_a")
        with c2:  fb = st.file_uploader("File B", type=None, key="cmp_b")

        if st.button("🔎 Compare"):
            if not fa or not fb:
                st.warning("Unggah kedua file terlebih dahulu.")
            else:
                A = fa.getvalue(); B = fb.getvalue(); same = (A == B)
                ca, cb, cc = st.columns([1,1,2])
                with ca:
                    st.markdown('<div class="soft-card"><h4>File A</h4>'
                                f'<div class="muted">Size</div><div class="kpi">{len(A)}</div>'
                                f'<div class="muted">SHA-256</div><div class="kpi">{sha256(A)[:16]}…</div></div>', unsafe_allow_html=True)
                with cb:
                    st.markdown('<div class="soft-card"><h4>File B</h4>'
                                f'<div class="muted">Size</div><div class="kpi">{len(B)}</div>'
                                f'<div class="muted">SHA-256</div><div class="kpi">{sha256(B)[:16]}…</div></div>', unsafe_allow_html=True)
                with cc:
                    if same:
                        st.success("✅ IDENTIK (byte-by-byte sama).")
                    else:
                        st.error("❌ BERBEDA.")
                        first_diff = next((i for i in range(min(len(A), len(B))) if A[i] != B[i]), None)
                        if first_diff is not None:
                            st.info(f"Byte pertama yang berbeda pada offset: `{first_diff}`")
                        st.markdown('<div class="soft-card"><h4>Preview A (64B)</h4>', unsafe_allow_html=True)
                        st.markdown(f'<div class="hexbox">{hex_preview(A, 64)}</div>', unsafe_allow_html=True)
                        st.markdown('</div>', unsafe_allow_html=True)
                        st.markdown('<div class="soft-card"><h4>Preview B (64B)</h4>', unsafe_allow_html=True)
                        st.markdown(f'<div class="hexbox">{hex_preview(B, 64)}</div>', unsafe_allow_html=True)
                        st.markdown('</div>', unsafe_allow_html=True)

# ==============================
# FOOTER
# ==============================
st.markdown("---")
st.caption(
    "Mode TEKS: E(x)=(x+K) mod 26, D(x)=(x−K) mod 26, hanya huruf A–Z diproses. "
    "Mode FILE: adaptasi byte-wise (0–255) untuk semua tipe data. "
    "Simpan hasil enkripsi sebagai .enc (biner). Saat dekripsi, isi 'Nama file asli' agar ekstensi kembali."
)
