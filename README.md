# CyberShield (Supabase + JavaScript)

Aplikasi simulasi firewall dan pemantauan traffic. Frontend HTML/CSS/JavaScript murni,
database online Supabase (PostgreSQL), dan bisa di-deploy ke Vercel tanpa build.

## Struktur
- `index.html`        : halaman aplikasi
- `css/style.css`     : tema gelap
- `js/config.js`      : isi URL dan anon key Supabase di sini
- `js/firewall.js`    : logika pemeriksaan paket dan skenario serangan
- `js/app.js`         : tampilan, grafik, dan koneksi ke database
- `database.sql`      : tabel, data awal, Realtime, dan RLS

## Urutan setup
1. Buat project di https://supabase.com (New project), tunggu sampai siap.
2. Buka SQL Editor > New query, tempel isi `database.sql`, klik Run.
3. Cek tabel `firewall_rules`, `security_logs`, `blacklist_ips` di Table Editor.
4. Buka Project Settings > API, salin Project URL dan anon public key.
5. Isi keduanya di `js/config.js`.
6. Coba lokal: jalankan `npx serve` di folder ini, atau pakai Live Server di VS Code.
7. Upload folder ke repository GitHub baru.
8. Di https://vercel.com: Add New > Project > import repo tersebut.
   Framework Preset: Other. Build Command dan Output Directory dikosongkan. Klik Deploy.
9. Buka link `.vercel.app`, lalu jalankan simulasi untuk mengisi log dan grafik.

## Catatan keamanan
Kebijakan RLS di `database.sql` mengizinkan siapa pun yang memegang anon key membaca dan
menulis tabel. Ini cukup untuk tugas kuliah, tetapi jangan dipakai untuk data sungguhan.
