# 🔐 VigiVault (Vigenere Cipher (Text & File Encryption)

VigiVault adalah aplikasi enkripsi berbasis algoritma **Vigenere Cipher** yang digunakan untuk mengenkripsi dan mendekripsi teks serta file dengan dua mode yang berbeda: **Vigenere klasik (A-Z)** dan **Vigenere byte-wise (0-255)**. 

## 👩‍💻 Anggota

| Adelia Felisha | Nikita Putri Prabowo  | Senia Nur Hasanah | 
|-------------------|-------------------|-------------------|
| 140810230003 |  140810230010 |  140810230021 |

---

## Deskripsi
VigiVault adalah aplikasi enkripsi berbasis algoritma **Vigenere Cipher**, yang memungkinkan pengguna untuk mengenkripsi dan mendekripsi **teks** dan **file** menggunakan dua mode yang berbeda: **Vigenere klasik (A-Z)** dan **Vigenere byte-wise (0-255)**. Aplikasi ini memungkinkan enkripsi teks dan file secara aman dan memverifikasi hasil dekripsi melalui re-enkripsi dan perhitungan entropi.

---

## Fitur Utama
1. **🔤 Mode Teks (Vigenere Klasik A-Z)**
   - Menggunakan Vigenere Cipher dengan mod 26 untuk mengenkripsi teks.
   - Mendukung enkripsi dan dekripsi teks hanya menggunakan huruf A-Z.
   - Mempertahankan spasi dan tanda baca dalam proses enkripsi.
   - Hasil enkripsi dapat diunduh dalam format `.txt`.


2. **📁 Mode File (Vigenere Byte-wise 0-255)**
   - Menggunakan Vigenere Cipher dengan mod 256 untuk mengenkripsi file apa pun.
   - File yang terenkripsi akan disimpan dalam format `.enc`.
   - Fitur preview memungkinkan pengguna melihat informasi tentang file asli dan terenkripsi (ukuran, hash SHA-256, dan entropi).
   - Fitur re-enkripsi digunakan untuk memverifikasi dekripsi dengan membandingkan hasil re-enkripsi dengan file terenkripsi asli.


3. **🎲 Pembuatan Key Acak**
   - Pengguna dapat menghasilkan **key acak** dengan panjang yang dapat dikustomisasi (8 hingga 64 karakter), yang mencakup simbol, angka, dan huruf besar/kecil.
   - Key acak digunakan untuk mode enkripsi teks dan file.


4. **✔️ Verifikasi Enkripsi dan Dekripsi**
   - Setelah dekripsi, sistem memverifikasi keakuratan hasil dekripsi dengan cara re-enkripsi dan membandingkan hash SHA-256 dari hasil re-enkripsi dengan file yang asli.
   - Entropi juga dihitung untuk memastikan bahwa hasil dekripsi cocok dengan data asli.


5. **🔑 Manajemen Key**
   - Pengguna dapat melihat dan mengelola key acak yang digunakan dalam enkripsi dan dekripsi.
   - Aplikasi memberikan indikator kekuatan key berdasarkan entropi key.


6. **📝 Perbandingan File**
   - Pengguna dapat membandingkan dua file untuk memverifikasi apakah mereka identik (byte-by-byte).
   - Aplikasi akan menampilkan perbedaan byte pertama yang berbeda antara kedua file.

---

##🧭 Cara Penggunaan
Pengguna dapat memilih mode yang digunakan, yaitu menggunakan algoritma “Teks (Vigenere klasik A–Z)” atau “File (Byte-wise 0–255)” melalui sidebar untuk mengenkripsi dan mendekripsi teks.

---

### 1. Pemilihan Mode Teks (Vigenere klasik A–Z)###
#### Langkah-langkah:
1. Pilih **"Teks (Vigenere klasik A–Z)"** pada sidebar.
2. Masukkan **plaintext** yang ingin Anda enkripsi.
3. Masukkan **key** (pastikan hanya menggunakan huruf A-Z).
4. Klik **Enkripsi** untuk menghasilkan ciphertext.
5. Jika ingin mendekripsi, masukkan **ciphertext** dan **key** yang sama, kemudian klik **Dekripsi**.


**Fitur Tambahan:**
- Anda dapat memilih untuk **mempertahankan spasi/tanda baca** selama proses enkripsi dan dekripsi.

---

### 2. Pemilihan Mode File (Byte-wise 0–255)###
#### Langkah-langkah:
1. Pilih **"File (Byte-wise 0–255)"** pada sidebar.
2. Unggah **file** yang ingin Anda enkripsi.
3. Masukkan **key** (key dapat mencakup simbol, angka, dan huruf).
4. Klik **Enkripsi Sekarang** untuk mengenkripsi file.
5. File terenkripsi akan diunduh dalam format `.enc`.
6. Untuk dekripsi, unggah file terenkripsi, masukkan **key** yang sama, dan klik **Dekripsi Sekarang**.

**Fitur Tambahan:**
- **Preview file** akan menampilkan informasi seperti ukuran file, SHA-256 hash, dan entropi dari file asli dan file terenkripsi.

---

### 3. Membuat Key Acak
Anda dapat membuat **key acak** untuk digunakan dalam enkripsi:

1. Pada sidebar, pilih **"Manajemen Key"**.
2. Gunakan **slider** untuk memilih panjang key yang diinginkan (8–64 karakter).
3. Pilih apakah Anda ingin key mencakup **simbol** atau tidak.
4. Klik **Generate Random Key** untuk membuat key acak.
5. Key acak ini akan ditampilkan di sidebar dan bisa digunakan untuk enkripsi.

---

### 4. Verifikasi Enkripsi dan Dekripsi
Setelah mendekripsi file atau teks, sistem akan **memverifikasi** hasil dekripsi dengan cara re-enkripsi:

- Jika hasil re-enkripsi cocok dengan file yang terenkripsi asli, maka dekripsi dianggap berhasil.
- Jika tidak cocok, aplikasi akan menampilkan pesan **verifikasi gagal**.

---

### 5. Perbandingan File
Untuk membandingkan dua file:

1. Pilih **"Compare Mode"** pada tab **"Perbandingan File"**.
2. Unggah **dua file** yang ingin dibandingkan.
3. Klik **Compare** untuk memverifikasi apakah kedua file identik.
4. Aplikasi akan menampilkan informasi seperti ukuran file dan SHA-256 hash, serta perbedaan byte pertama yang berbeda jika ada.

---

## 🧩 Contoh Alur Penggunaan
