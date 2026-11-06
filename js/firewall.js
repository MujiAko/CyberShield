const POLA_SQLI = /(\bunion\b.*\bselect\b|\bor\b\s+1\s*=\s*1|--|'\s*or\s*')/i;
const BATAS_AUTO_BLACKLIST = 10; // IP diblacklist setelah 10 paket serangan

// Cocokkan pola IP (boleh wildcard *) dengan IP sebenarnya
function ipCocok(pola, ip) {
  if (pola === "*") return true;
  const regex = "^" + pola.replace(/\./g, "\\.").replace(/\*/g, "\\d+") + "$";
  return new RegExp(regex).test(ip);
}

function aturanCocok(aturan, paket) {
  const portCocok = aturan.port === null || aturan.port === paket.port;
  const protoCocok = aturan.protokol === "ANY" || aturan.protokol === paket.protokol;
  return ipCocok(aturan.ip_sumber, paket.ip) && portCocok && protoCocok;
}

// Periksa satu paket. Urutan: blacklist -> signature -> blokir -> izinkan -> default tolak
function periksaPaket(paket, aturan, blacklist) {
  if (blacklist.has(paket.ip)) {
    return { aksi: "BLOCK", alasan: "IP ada di blacklist" };
  }
  if (paket.payload && POLA_SQLI.test(paket.payload)) {
    return { aksi: "BLOCK", alasan: "Pola SQL Injection terdeteksi" };
  }
  const aktif = aturan.filter((a) => a.aktif);

  const blokir = aktif.find((a) => a.aksi === "BLOCK" && aturanCocok(a, paket));
  if (blokir) return { aksi: "BLOCK", alasan: "Aturan blokir: " + blokir.nama };

  const izin = aktif.find((a) => a.aksi === "ALLOW" && aturanCocok(a, paket));
  if (izin) return { aksi: "ALLOW", alasan: "Aturan izinkan: " + izin.nama };

  return { aksi: "BLOCK", alasan: "Kebijakan default: tolak" };
}

// Validasi input form
function ipValid(ip, bolehWildcard = false) {
  const bagian = ip.split(".");
  if (bagian.length !== 4) return false;
  return bagian.every((b) =>
    (bolehWildcard && b === "*") || (/^\d{1,3}$/.test(b) && Number(b) <= 255)
  );
}
function portValid(p) {
  return Number.isInteger(p) && p >= 1 && p <= 65535;
}

// Proses banyak paket sekaligus: ambil aturan -> periksa -> simpan log
async function prosesPaket(daftarPaket) {
  const [r1, r2] = await Promise.all([
    db.from("firewall_rules").select("*"),
    db.from("blacklist_ips").select("ip"),
  ]);
  if (r1.error || r2.error) throw new Error((r1.error || r2.error).message);

  const aturan = r1.data;
  const blacklist = new Set(r2.data.map((b) => b.ip));
  const jumlahPaket = {};    // hitung paket serangan per IP
  const blacklistBaru = [];
  const logs = [];

  for (const paket of daftarPaket) {
    const hasil = periksaPaket(paket, aturan, blacklist);
    logs.push({
      ip_sumber: paket.ip, port_tujuan: paket.port,
      jenis: paket.jenis, aksi: hasil.aksi, alasan: hasil.alasan,
    });

    // Auto-blacklist berbasis jumlah paket: IP yang mengirim terlalu banyak paket
    // serangan dalam satu rentetan diblacklist, walaupun port tujuannya diizinkan
    // (contoh: SYN Flood ke port 80).
    if (paket.jenis !== "Traffic Normal" && paket.jenis !== "Uji Manual") {
      jumlahPaket[paket.ip] = (jumlahPaket[paket.ip] || 0) + 1;
      if (jumlahPaket[paket.ip] >= BATAS_AUTO_BLACKLIST && !blacklist.has(paket.ip)) {
        blacklist.add(paket.ip);
        blacklistBaru.push({ ip: paket.ip, alasan: "Auto-blacklist: " + paket.jenis });
      }
    }
  }

  const simpanLog = await db.from("security_logs").insert(logs);
  if (simpanLog.error) throw new Error(simpanLog.error.message);
  if (blacklistBaru.length) {
    await db.from("blacklist_ips").upsert(blacklistBaru, { onConflict: "ip", ignoreDuplicates: true });
  }
  return { logs, blacklistBaru };
}

// ------------------------------------------------------------
// Pembuat skenario simulasi
// ------------------------------------------------------------
const acak = (a, b) => Math.floor(Math.random() * (b - a + 1)) + a;
const ipAcak = (prefix) => `${prefix}.${acak(2, 250)}`;

const SKENARIO = {
  normal: () => Array.from({ length: 10 }, () => {
    const port = [80, 443, 53][acak(0, 2)];
    return { ip: ipAcak("192.168.1"), port, protokol: port === 53 ? "UDP" : "TCP", jenis: "Traffic Normal" };
  }),
  portscan: () => {
    const ip = ipAcak("203.0.113");
    return Array.from({ length: 15 }, (_, i) => ({
      ip, port: 20 + i, protokol: "TCP", jenis: "Port Scan",
    }));
  },
  ssh: () => {
    const ip = ipAcak("198.51.100");
    return Array.from({ length: 15 }, () => ({
      ip, port: 22, protokol: "TCP", jenis: "SSH Brute Force",
    }));
  },
  synflood: () => {
    const ip = ipAcak("45.33.32");
    return Array.from({ length: 30 }, () => ({
      ip, port: 80, protokol: "TCP", jenis: "SYN Flood",
    }));
  },
  sqli: () => {
    const ip = ipAcak("185.220.101");
    const payload = ["' OR 1=1 --", "admin'--", "1 UNION SELECT user,pass FROM users", "x' or 'a'='a"];
    return payload.map((p) => ({
      ip, port: 80, protokol: "TCP", jenis: "SQL Injection", payload: p,
    }));
  },
};

// Dukungan pengujian di Node (tidak berpengaruh di browser)
if (typeof module !== "undefined") module.exports = { periksaPaket, ipCocok, ipValid, portValid };