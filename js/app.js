// ============================================================
// Tampilan dan interaksi CyberShield
// ============================================================
const db = supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
const $ = (id) => document.getElementById(id);

// ---------- Fungsi bantu ----------
function esc(teks) {                       // cegah XSS saat menampilkan data dari database
  const el = document.createElement("div");
  el.textContent = teks ?? "";
  return el.innerHTML;
}
const waktuLokal = (iso) => new Date(iso).toLocaleString("id-ID", { dateStyle: "short", timeStyle: "medium" });
const tag = (aksi) => `<span class="tag ${aksi}">${aksi === "ALLOW" ? "Diizinkan" : "Diblokir"}</span>`;

function toast(pesan, galat = false) {
  const el = $("toast");
  el.textContent = pesan;
  el.className = "toast" + (galat ? " galat" : "");
  el.hidden = false;
  setTimeout(() => (el.hidden = true), 3500);
}

// Bungkus aksi agar error dari Supabase tampil sebagai toast
async function jalankan(fungsi) {
  try { await fungsi(); } catch (e) { toast(e.message, true); }
}
function cek({ error }) { if (error) throw new Error(error.message); }

const namaPort = { 22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP", 443: "HTTPS", 3306: "MySQL" };

function isiBar(idBar, idNilai, persen) {
  $(idBar).style.width = persen + "%";
  $(idNilai).textContent = persen + "%";
}
function setStatusDb(ok) {
  $("chip-db").className = "chip " + (ok ? "ok" : "galat");
  $("teks-db").textContent = ok ? "Database terhubung" : "Database terputus";
}
// Tambahkan hasil pemeriksaan paket ke tabel aliran traffic (maks. 40 baris)
function tampilkanFeed(logs) {
  const baris = logs.slice().reverse().map((l) => `<tr><td>${esc(l.ip_sumber)}</td><td>${l.port_tujuan}</td><td>${esc(l.jenis)}</td><td>${tag(l.aksi)}</td><td class="alasan">${esc(l.alasan)}</td></tr>`).join("");
  const tbody = $("feed-traffic");
  tbody.innerHTML = baris + tbody.innerHTML;
  while (tbody.rows.length > 40) tbody.deleteRow(-1);
}

// ---------- Navigasi ----------
const MUAT = { dashboard: () => muatDashboard().catch((e) => { setStatusDb(false); throw e; }), firewall: muatAturan, logs: muatLog, blacklist: muatBlacklist, simulasi: () => {} };

function bukaHalaman(nama) {
  document.querySelectorAll("main > section").forEach((s) => (s.hidden = s.id !== "hal-" + nama));
  document.querySelectorAll(".nav").forEach((n) => n.classList.toggle("aktif", n.dataset.halaman === nama));
  jalankan(MUAT[nama]);
}
document.querySelectorAll(".nav, .lihat").forEach((n) => n.addEventListener("click", () => bukaHalaman(n.dataset.halaman)));

// ---------- Dashboard ----------
let grafik = null;

async function muatDashboard() {
  const hitung = async (query) => { const r = await query; cek(r); return r.count; };
  const semua = () => db.from("security_logs").select("*", { count: "exact", head: true });

  const hitungAturan = () => db.from("firewall_rules").select("*", { count: "exact", head: true });
  const [total, izin, blokir, aturan, semuaAturan] = await Promise.all([
    hitung(semua()),
    hitung(semua().eq("aksi", "ALLOW")),
    hitung(semua().eq("aksi", "BLOCK")),
    hitung(hitungAturan().eq("aktif", true)),
    hitung(hitungAturan()),
  ]);
  const persen = (n) => (total ? Math.round((n / total) * 100) : 0);
  const angka = (n) => n.toLocaleString("id-ID");
  $("s-total").textContent = angka(total);
  $("s-izin").textContent = angka(izin);
  $("s-blokir").textContent = angka(blokir);
  $("s-aturan").textContent = aturan;
  $("s-izin-sub").textContent = persen(izin) + "% dari total paket";
  $("s-blokir-sub").textContent = persen(blokir) + "% dari total paket";
  $("s-aturan-sub").textContent = "dari " + semuaAturan + " aturan terdaftar";
  isiBar("bar-aturan", "v-aturan", semuaAturan ? Math.round((aturan / semuaAturan) * 100) : 0);
  isiBar("bar-ancaman", "v-ancaman", persen(blokir));
  setStatusDb(true);

  await gambarGrafik();
  await isiPortDanPeringatan();
}

// Grafik: jumlah paket per menit selama 15 menit terakhir
async function gambarGrafik() {
  const sejak = new Date(Date.now() - 15 * 60000).toISOString();
  const r = await db.from("security_logs").select("waktu, aksi").gte("waktu", sejak).limit(2000);
  cek(r);

  const label = [], izin = [], blokir = [];
  const awalMenit = Math.floor(Date.now() / 60000) * 60000;
  for (let i = 14; i >= 0; i--) {
    const mulai = awalMenit - i * 60000;
    const dalamMenit = r.data.filter((l) => { const t = new Date(l.waktu).getTime(); return t >= mulai && t < mulai + 60000; });
    label.push(new Date(mulai).toLocaleTimeString("id-ID", { hour: "2-digit", minute: "2-digit" }));
    izin.push(dalamMenit.filter((l) => l.aksi === "ALLOW").length);
    blokir.push(dalamMenit.filter((l) => l.aksi === "BLOCK").length);
  }

  if (!grafik) {
    grafik = new Chart($("grafik"), {
      type: "line",
      data: { labels: label, datasets: [
        { label: "Diizinkan", data: izin, borderColor: "#34d399", backgroundColor: "#34d39933", fill: true, tension: .3 },
        { label: "Diblokir", data: blokir, borderColor: "#f87171", backgroundColor: "#f8717133", fill: true, tension: .3 },
      ] },
      options: { maintainAspectRatio: false, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } },
        plugins: { legend: { labels: { color: "#e6edf5" } } } },
    });
    Chart.defaults.color = "#8da0b6";
  } else {
    grafik.data.labels = label;
    grafik.data.datasets[0].data = izin;
    grafik.data.datasets[1].data = blokir;
    grafik.update();
  }
}

async function isiPortDanPeringatan() {
  const r = await db.from("security_logs").select("*").eq("aksi", "BLOCK").order("waktu", { ascending: false }).limit(500);
  cek(r);

  const hitungPort = {};
  r.data.forEach((l) => (hitungPort[l.port_tujuan] = (hitungPort[l.port_tujuan] || 0) + 1));
  const urut = Object.entries(hitungPort).sort((a, b) => b[1] - a[1]).slice(0, 5);
  const maks = urut.length ? urut[0][1] : 1;
  $("top-port").innerHTML = urut.length
    ? urut.map(([port, n]) => `<div class="port"><div><span>Port ${esc(port)} <small>${esc(namaPort[port] || "")}</small></span><b>${n}</b></div><div class="batang"><i class="merah" style="width:${Math.round((n / maks) * 100)}%"></i></div></div>`).join("")
    : `<p class="kosong">Belum ada paket yang diblokir.</p>`;

  $("peringatan").innerHTML = r.data.length
    ? r.data.slice(0, 6).map((l) => `<tr><td>${waktuLokal(l.waktu)}</td><td>${esc(l.ip_sumber)}</td><td>${l.port_tujuan}</td><td>${esc(l.jenis)}</td><td>${tag(l.aksi)}</td></tr>`).join("")
    : `<tr><td colspan="5" class="kosong">Belum ada peringatan. Jalankan simulasi untuk mengisi data.</td></tr>`;
}

// ---------- Aturan firewall ----------
async function muatAturan() {
  const r = await db.from("firewall_rules").select("*").order("id");
  cek(r);
  $("tabel-aturan").innerHTML = r.data.map((a) => `
    <tr>
      <td>${esc(a.nama)}</td><td>${esc(a.ip_sumber)}</td><td>${a.port ?? "Semua"}</td>
      <td>${a.protokol}</td><td>${tag(a.aksi)}</td>
      <td><button data-toggle="${a.id}" data-aktif="${a.aktif}">${a.aktif ? "Aktif" : "Nonaktif"}</button></td>
      <td><button data-hapus="${a.id}">Hapus</button></td>
    </tr>`).join("") || `<tr><td colspan="7" class="kosong">Belum ada aturan.</td></tr>`;
}

$("form-aturan").addEventListener("submit", (e) => {
  e.preventDefault();
  jalankan(async () => {
    const f = new FormData(e.target);
    const ip = f.get("ip").trim() || "*";
    const port = f.get("port") ? Number(f.get("port")) : null;
    if (ip !== "*" && !ipValid(ip, true)) throw new Error("Format IP tidak valid.");
    if (port !== null && !portValid(port)) throw new Error("Port harus 1 - 65535.");
    cek(await db.from("firewall_rules").insert({
      nama: f.get("nama").trim(), ip_sumber: ip, port, protokol: f.get("protokol"), aksi: f.get("aksi"),
    }));
    e.target.reset();
    toast("Aturan ditambahkan.");
    await muatAturan();
  });
});

$("tabel-aturan").addEventListener("click", (e) => {
  const tombol = e.target.closest("button");
  if (!tombol) return;
  jalankan(async () => {
    if (tombol.dataset.toggle) {
      const aktifBaru = tombol.dataset.aktif !== "true";
      cek(await db.from("firewall_rules").update({ aktif: aktifBaru }).eq("id", tombol.dataset.toggle));
    } else if (tombol.dataset.hapus) {
      cek(await db.from("firewall_rules").delete().eq("id", tombol.dataset.hapus));
    }
    await muatAturan();
  });
});

// ---------- Simulasi ----------
document.querySelectorAll("[data-skenario]").forEach((tombol) =>
  tombol.addEventListener("click", () => jalankan(async () => {
    tombol.disabled = true;
    try {
      const { logs, blacklistBaru } = await prosesPaket(SKENARIO[tombol.dataset.skenario]());
      const izin = logs.filter((l) => l.aksi === "ALLOW").length;
      let teks = `<b>${logs.length}</b> paket dikirim: <b>${izin}</b> diizinkan, <b>${logs.length - izin}</b> diblokir.`;
      if (blacklistBaru.length) teks += ` IP ${esc(blacklistBaru[0].ip)} otomatis masuk blacklist.`;
      $("hasil-simulasi").innerHTML = teks;
      tampilkanFeed(logs);
    } finally { tombol.disabled = false; }
  })));

$("form-uji").addEventListener("submit", (e) => {
  e.preventDefault();
  jalankan(async () => {
    const f = new FormData(e.target);
    const ip = f.get("ip").trim(), port = Number(f.get("port"));
    if (!ipValid(ip)) throw new Error("Format IP tidak valid, contoh: 10.0.0.5");
    if (!portValid(port)) throw new Error("Port harus 1 - 65535.");
    const { logs } = await prosesPaket([{ ip, port, protokol: f.get("protokol"), jenis: "Uji Manual" }]);
    $("hasil-uji").innerHTML = `${tag(logs[0].aksi)} ${esc(logs[0].alasan)}`;
    tampilkanFeed(logs);
  });
});

// Traffic otomatis: kirim 1-3 paket tiap 2,5 detik, sesekali ke port yang tidak diizinkan
let timerAuto = null;
$("auto-traffic").addEventListener("click", () => {
  const tombol = $("auto-traffic");
  if (timerAuto) {
    clearInterval(timerAuto);
    timerAuto = null;
    tombol.textContent = "Mulai traffic otomatis";
    return;
  }
  tombol.textContent = "Hentikan traffic otomatis";
  timerAuto = setInterval(() => jalankan(async () => {
    const paket = SKENARIO.normal().slice(0, acak(1, 3));
    if (Math.random() < 0.3) {
      paket.push({ ip: ipAcak("203.0.113"), port: [23, 3306, 8080][acak(0, 2)], protokol: "TCP", jenis: "Traffic Mencurigakan" });
    }
    const { logs } = await prosesPaket(paket);
    tampilkanFeed(logs);
  }), 2500);
});

// ---------- Log keamanan ----------
async function muatLog() {
  let q = db.from("security_logs").select("*").order("waktu", { ascending: false }).limit(200);
  if ($("filter-aksi").value) q = q.eq("aksi", $("filter-aksi").value);
  const kata = $("cari-log").value.replace(/[,()%]/g, "").trim();
  if (kata) q = q.or(`ip_sumber.ilike.%${kata}%,jenis.ilike.%${kata}%`);
  const r = await q;
  cek(r);
  $("tabel-log").innerHTML = r.data.map((l) => `
    <tr><td>${waktuLokal(l.waktu)}</td><td>${esc(l.ip_sumber)}</td><td>${l.port_tujuan}</td>
    <td>${esc(l.jenis)}</td><td>${tag(l.aksi)}</td><td class="alasan">${esc(l.alasan)}</td></tr>`).join("")
    || `<tr><td colspan="6" class="kosong">Tidak ada log yang cocok.</td></tr>`;
}
$("filter-aksi").addEventListener("change", () => jalankan(muatLog));
$("cari-log").addEventListener("input", () => jalankan(muatLog));
$("hapus-log").addEventListener("click", () => jalankan(async () => {
  if (!confirm("Hapus semua log keamanan?")) return;
  cek(await db.from("security_logs").delete().gte("id", 0));
  await muatLog();
}));

// ---------- Blacklist ----------
async function muatBlacklist() {
  const r = await db.from("blacklist_ips").select("*").order("dibuat", { ascending: false });
  cek(r);
  $("tabel-blacklist").innerHTML = r.data.map((b) => `
    <tr><td>${esc(b.ip)}</td><td class="alasan">${esc(b.alasan)}</td><td>${waktuLokal(b.dibuat)}</td>
    <td><button data-hapus="${b.id}">Hapus</button></td></tr>`).join("")
    || `<tr><td colspan="4" class="kosong">Blacklist kosong.</td></tr>`;
}

$("form-blacklist").addEventListener("submit", (e) => {
  e.preventDefault();
  jalankan(async () => {
    const f = new FormData(e.target);
    const ip = f.get("ip").trim();
    if (!ipValid(ip)) throw new Error("Format IP tidak valid.");
    const r = await db.from("blacklist_ips").insert({ ip, alasan: f.get("alasan").trim() || "Ditambahkan manual" });
    if (r.error?.code === "23505") throw new Error("IP sudah ada di blacklist.");
    cek(r);
    e.target.reset();
    toast("IP ditambahkan ke blacklist.");
    await muatBlacklist();
  });
});

$("tabel-blacklist").addEventListener("click", (e) => {
  const tombol = e.target.closest("button[data-hapus]");
  if (!tombol) return;
  jalankan(async () => {
    cek(await db.from("blacklist_ips").delete().eq("id", tombol.dataset.hapus));
    await muatBlacklist();
  });
});

// ---------- Mulai ----------
const perbaruiJam = () => ($("jam").textContent = new Date().toLocaleString("id-ID", { dateStyle: "medium", timeStyle: "medium" }));
perbaruiJam();
setInterval(perbaruiJam, 1000);
$("nama").textContent = NAMA;
$("nim").textContent = NIM;
$("banner").hidden = !SUPABASE_URL.includes("XXXXXXXX");

// Realtime: dashboard dan log ikut berubah saat ada log baru
let tunda;
db.channel("log-baru")
  .on("postgres_changes", { event: "INSERT", schema: "public", table: "security_logs" }, () => {
    clearTimeout(tunda);
    tunda = setTimeout(() => {
      if (!$("hal-dashboard").hidden) jalankan(muatDashboard);
      if (!$("hal-logs").hidden) jalankan(muatLog);
    }, 600);
  })
  .subscribe();

bukaHalaman("dashboard");
