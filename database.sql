-- ============================================================
-- CyberShield - Database Supabase (PostgreSQL)
-- Jalankan seluruh file ini di Supabase > SQL Editor > Run
-- ============================================================

-- 1. Tabel aturan firewall
create table if not exists firewall_rules (
  id        bigint generated always as identity primary key,
  nama      text        not null,
  ip_sumber text        not null default '*',   -- boleh wildcard: 192.168.1.*
  port      integer     check (port between 1 and 65535), -- null = semua port
  protokol  text        not null default 'ANY' check (protokol in ('TCP','UDP','ANY')),
  aksi      text        not null check (aksi in ('ALLOW','BLOCK')),
  aktif     boolean     not null default true,
  dibuat    timestamptz not null default now()
);

-- 2. Tabel log keamanan
create table if not exists security_logs (
  id          bigint generated always as identity primary key,
  waktu       timestamptz not null default now(),
  ip_sumber   text        not null,
  port_tujuan integer     not null,
  jenis       text        not null,             -- contoh: Traffic Normal, Port Scan
  aksi        text        not null check (aksi in ('ALLOW','BLOCK')),
  alasan      text        not null
);

-- 3. Tabel blacklist IP
create table if not exists blacklist_ips (
  id     bigint generated always as identity primary key,
  ip     text        not null unique,
  alasan text        not null default 'Ditambahkan manual',
  dibuat timestamptz not null default now()
);

-- 4. Data awal aturan firewall
insert into firewall_rules (nama, ip_sumber, port, protokol, aksi) values
  ('Izinkan HTTP',  '*', 80,   'TCP', 'ALLOW'),
  ('Izinkan HTTPS', '*', 443,  'TCP', 'ALLOW'),
  ('Izinkan DNS',   '*', 53,   'UDP', 'ALLOW'),
  ('Blokir Telnet', '*', 23,   'TCP', 'BLOCK'),
  ('Blokir MySQL dari luar', '*', 3306, 'TCP', 'BLOCK');

-- 5. Aktifkan Realtime untuk log (agar dashboard update otomatis)
alter publication supabase_realtime add table security_logs;

-- 6. Row Level Security (RLS)
-- Untuk tugas kuliah: anon key boleh baca/tulis ketiga tabel.
-- Jangan dipakai apa adanya untuk aplikasi produksi.
alter table firewall_rules enable row level security;
alter table security_logs  enable row level security;
alter table blacklist_ips  enable row level security;

create policy "akses_anon_rules" on firewall_rules for all to anon using (true) with check (true);
create policy "akses_anon_logs"  on security_logs  for all to anon using (true) with check (true);
create policy "akses_anon_black" on blacklist_ips  for all to anon using (true) with check (true);
