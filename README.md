# DNStrike ⚡

**DNStrike** is a web-based DNS stress-testing, resilience auditing, and security assessment platform built with a high-performance Go engine and a modern React interface.

---

## 🎯 Test Scenarios & Attack Simulations / Test Senaryoları & Saldırı Simülasyonları

DNStrike offers specialized attack simulations, resilience benchmarks, and security audits to test DNS servers against real-world attack vectors and high-volume traffic.

---

### 1. 🛡️ Security Audit (`security-audit`)
* **Category / Kategori:** `audit`
* **Risk Level:** `LOW`
* **Config Parameters:** `domain` (Default: `example.com`)
* **Description (EN):** Evaluates DNS server configuration for critical security posture vulnerabilities including:
  1. **Open Recursion Check:** Tests whether external domain recursion (`google.com A`) is enabled for unauthorized clients (Open Resolver vulnerability).
  2. **Version Disclosure (CHAOS):** Probes `version.bind TXT CHAOS` query leakage to detect DNS software version exposure.
  3. **AXFR Zone Transfer Leak:** Attempts unauthorized full zone transfer (`AXFR`) via TCP to verify if domain records and internal IP maps are exposed.
* **Açıklama (TR):** DNS sunucusunun temel güvenlik açıklarını ve yapılandırma hatalarını denetler (Açık özyineleme / Open Resolver, yazılım versiyonu sızıntısı ve yetkisiz AXFR alan adı transferi testi).

---

### 2. 🔓 AXFR Zone Transfer Leak Audit (`zone-transfer-audit`)
* **Category / Kategori:** `audit`
* **Risk Level:** `LOW`
* **Config Parameters:** `domain` (Default: `example.com`)
* **Description (EN):** Probes the DNS server over TCP 53 to check if unauthorized clients can execute an AXFR/IXFR full zone transfer and siphon complete domain database records (internal IPs, subdomains, MX, TXT, NS).
* **Açıklama (TR):** Hedef DNS sunucusuna TCP Port 53 üzerinden yetkisiz `AXFR` (Full Zone Transfer) isteği göndererek alan adına ait tüm veritabanı kayıtlarının sızdırılıp sızdırılamadığını denetler.

---

### 2. 🚀 DNS Amplification & RRL Audit (`amplification-audit`)
* **Category / Kategori:** `audit`
* **Risk Level:** `MEDIUM`
* **Config Parameters:** `domain` (Default: `example.com`)
* **Description (EN):** Evaluates the server's susceptibility to being weaponized as a reflector in DNS Amplification DDoS attacks:
  1. **Payload & Multiplier Analysis:** Measures request vs response size in bytes across `A`, `TXT`, `ANY`, `DNSKEY`, and `EDNS0 (4096B)` query types to calculate the exact **Amplification Multiplier (e.g. 45.2x)**.
  2. **Response Rate Limiting (RRL) Posture:** Fires a 50-query UDP burst under 500ms to detect active RRL rules (`RRL ACTIVE` vs `NO RRL DETECTED`).
* **Açıklama (TR):** Sunucunun Amplification (Yansıma/Büyütme) DDoS saldırılarında piyon olarak kullanılıp kullanılamayacağını `ANY`, `TXT`, `DNSKEY` ve `EDNS0` paket boyutlarıyla ölçer ve RRL (Response Rate Limiting) koruma mekanizmasını 50 sorguluk hızlı burst testi ile denetler.

---

### 3. 🐢 DNS TCP Slowloris / Connection Exhaustion (`tcp-slowloris`)
* **Category / Kategori:** `volume`
* **Risk Level:** `HIGH`
* **Config Parameters:** `connections` (Default: 20), `hold_duration` (Default: 10s)
* **Description (EN):** Evaluates DNS TCP Port 53 socket exhaustion handling:
  1. Opens concurrent slow TCP connections sending partial 2-byte DNS headers and periodic heartbeat bytes.
  2. Probes the target server with a parallel legitimate TCP DNS query to verify if connection exhaustion blocks authorized traffic or if TCP idle timeouts are properly enforced.
* **Açıklama (TR):** TCP Port 53 üzerinden eşzamanlı yavaş TCP soketleri açarak sunucunun maksimum TCP bağlantı limitini, soket zaman aşımı (Timeout) politikasını ve DoS saldırısı altındayken yasal TCP sorgularına yanıt verip vermediğini test eder.

---

### 3. 📊 Performance Benchmark (`benchmark`)
* **Category / Kategori:** `performance`
* **Risk Level:** `MEDIUM`
* **Config Parameters:** `qps`, `duration`, `workers`, `source_ip_pool`
* **Description (EN):** Generates a sustained, rate-limited DNS query workload to measure query latency distribution (average, min, max), throughput stability, and packet loss under baseline loads.
* **Açıklama (TR):** Sabit ve belirlenen bir QPS hızında (örn. 500 QPS) sürekli sorgu göndererek sunucunun ortalama gecikme (latency), başarım ve paket kaybı performansını ölçer.

---

### 4. 📈 QPS Ramp Up (`qps-ramp`)
* **Category / Kategori:** `performance`
* **Risk Level:** `HIGH`
* **Config Parameters:** `start_qps`, `step_qps`, `max_qps`, `step_duration`, `source_ip_pool`
* **Description (EN):** Stepwise traffic escalation test designed to find the maximum stable query capacity and breaking point of the DNS server before packet drops or latency spikes occur.
* **Açıklama (TR):** Trafik yükünü kademeli olarak artırarak (örn. 100 -> 200 -> 300 -> 1000 QPS) DNS sunucusunun dayanabileceği maksimum sorgu kapasitesini ve tıkanma noktasını tespit eder.

---

### 5. ❌ NXDOMAIN Resilience (`nxdomain`)
* **Category / Kategori:** `resolver-cache`
* **Risk Level:** `HIGH`
* **Config Parameters:** `base_domain`, `qps`, `duration`, `workers`, `source_ip_pool`
* **Description (EN):** Sends a high-frequency stream of non-existent domain names to evaluate negative cache memory handling, CPU consumption, and RFC 2308 compliance.
* **Açıklama (TR):** Var olmayan alan adlarıyla (NXDOMAIN) yüksek hızlı sorgu üreterek sunucunun negatif önbellekleme (Negative Caching) performansını ve hafıza/CPU tüketimini ölçer.

---

### 6. 🎲 Random Subdomain Attack / Water Torture (`random-subdomain`)
* **Category / Kategori:** `resolver-cache`
* **Risk Level:** `HIGH`
* **Config Parameters:** `base_domain`, `qps`, `duration`, `workers`, `source_ip_pool`
* **Description (EN):** Simulates a Pseudo-Random Subdomain (PRSD) / Water Torture attack by generating unique subdomains (`rnd123.domain.com`). Bypasses recursive resolver cache layers and stresses upstream authoritative DNS infrastructure directly.
* **Açıklama (TR):** Sürekli rastgele alt alan adları (`a1b2.domain.com`) üreterek DNS önbelleğini (cache) bypass eden Water Torture / PRSD saldırısını simüle eder ve yetkili DNS sunucusuna binen yükü ölçer.

---

### 7. 🌊 Query Flood (`query-flood`)
* **Category / Kategori:** `volume`
* **Risk Level:** `HIGH`
* **Config Parameters:** `domain_list`, `query_type`, `qps`, `duration`, `workers`, `source_ip_pool`
* **Description (EN):** High-volume single or multi-record-type DNS traffic flood to evaluate firewalls, OS socket buffers, and DDoS mitigation hardware under heavy load.
* **Açıklama (TR):** Belirlenen sorgu tiplerinde (A, TXT, MX vb.) yüksek hacimli trafik göndererek güvenlik duvarlarının (Firewall/IPS) ve sunucu UDP soket tamponlarının dayanıklılığını ölçer.

---

## 🔒 Safety & Authorization Model

- DNStrike is built strictly for authorized testing on infrastructure you own or have explicit permission to test.
- Target IP validator restricts targets to RFC1918 private IPs (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.1`), link-local, and IPv6 ULA.

---

## 🏗️ Architecture & Stack

```text
React UI (Vite + TS) → Gin REST API (Go) → SQLite Persistence
                           ├── DNS Engine (miekg/dns)
                           ├── Scenario Execution Orchestrator
                           └── WebSocket Event Hub
```

- **Backend:** Go 1.24+ (Gin Framework, miekg/dns, SQLite)
- **Frontend:** React 19, TypeScript, TanStack Query, Lucide Icons, jsPDF
- **Realtime:** WebSockets for live execution logs and progress streaming

## 🚀 Quick Start (Docker)

```bash
# Clone repository and launch containers
docker compose up -d --build

# Open Web Interface
http://localhost:8080
```

---

## 🛠️ Local Development

Requires Go 1.24+ and Node.js 24+.

```bash
# Install dependencies & run server
go mod download
cd web && npm install && npm run build && cd ..
go run ./cmd/server
```

---

## 🔌 REST API Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/health` | Service health |
| `GET` | `/api/targets` | List targets |
| `POST` | `/api/targets` | Create and validate a target |
| `GET` | `/api/targets/:id` | Fetch a target |
| `DELETE` | `/api/targets/:id` | Delete a target |
| `POST` | `/api/targets/:id/check` | Run UDP/TCP discovery |
| `GET` | `/api/scenarios` | List scenario capabilities |
| `POST` | `/api/tests` | Create a pending test record |
| `GET` | `/api/tests` | List and filter test history |
| `GET` | `/api/tests/:id` | Fetch test configuration and lifecycle state |
| `DELETE` | `/api/tests/:id` | Delete test record from history |
| `GET` | `/ws/tests/:id` | Test event WebSocket |

---

## 📄 License & Legal Notice

DNStrike is provided for educational, security research, and authorized network resilience auditing purposes only. Always obtain written authorization before conducting DNS load tests or security assessments.
