# DNStrike Çalışma Notları

## Çalışma Kuralı

- Her uygulama adımı başlamadan önce kullanıcıdan açık onay alınacak.
- Onay yalnızca sorulan adım için geçerli sayılacak.
- Onay verilmeden kaynak kod, yapılandırma veya bağımlılıklar değiştirilmeyecek.
- Her adım sonunda yapılan değişiklikler ve doğrulama sonucu raporlanacak.
- Gerçek bir DNS hedefinde trafik testi, ayrıca açıkça onaylanmadıkça yapılmayacak.

## İlk İnceleme Özeti

- API üzerinde kimlik doğrulama/yetkilendirme bulunmuyor.
- Docker Compose servisi host ağı, `0.0.0.0:8888` dinleme adresi ve `NET_ADMIN` yetkisiyle çalıştırıyor.
- Orchestrator için global eşzamanlı test sınırı bulunmuyor.
- Çalışan testler iptal edilebilir context ile yönetilmiyor ve düzgün kapanış sırasında beklenmiyor.
- Süreç yeniden başladığında `RUNNING` durumunda kalmış testler için recovery mekanizması yok.
- Çalışan test veya hedef silinirse ağ işlemi arka planda devam edebilir.
- Private/local hedef politikası loopback, link-local ve tüm portları kabul ediyor.
- Frontend lint kontrolü başarılı.
- Ortamda Go aracı bulunmadığından backend testleri henüz çalıştırılamadı.

## Planlanan İşlemler

### 1. API erişim koruması

- Ortam değişkeninden alınan bir API anahtarıyla HTTP ve WebSocket erişimini koru.
- Sabit zamanlı anahtar karşılaştırması kullan.
- Health endpoint'inin erişim politikasını açıkça tanımla.
- Backend ve frontend istemci entegrasyonunu ekle.
- Yetkili/yetkisiz istek testlerini yaz.

Durum: Tamamlandı.

Uygulananlar:

- Zorunlu, en az 32 karakterlik `DNSTRIKE_API_KEY` yapılandırması eklendi.
- REST istemcileri için Bearer ve `X-DNStrike-API-Key` desteği eklendi.
- Tarayıcı için 8 saatlik, imzalı, `HttpOnly`, `SameSite=Strict` oturum eklendi.
- Health ve giriş dışındaki REST endpoint'leri ile WebSocket korumaya alındı.
- Giriş/çıkış arayüzü ve oturum süresi dolduğunda otomatik giriş ekranına dönüş eklendi.
- Auth yanıtlarına `Cache-Control: no-store` eklendi.
- Docker Compose anahtar olmadan başlamayacak şekilde güncellendi.
- Backend auth testleri, frontend lint/build ve Compose doğrulaması başarılı.

### 2. Güvenli ağ ve Docker varsayılanları

- Varsayılan dinleme adresini yalnızca yönetim arayüzüne uygun hâle getir.
- `network_mode: host` ve `NET_ADMIN` kullanımını varsayılan kurulumdan ayır.
- Source IP alias özelliğini açıkça etkinleştirilen bir seçenek yap.
- Dağıtım dokümantasyonuna güvenlik uyarıları ekle.

Durum: Tamamlandı.

Uygulananlar:

- Varsayılan Compose host network yerine bridge network kullanacak şekilde değiştirildi.
- Varsayılan port yalnızca `127.0.0.1` üzerinde yayımlanıyor.
- Varsayılan konteyner tüm Linux capability'lerini düşürüyor ve `no-new-privileges` kullanıyor.
- Source-IP pool varsayılan olarak backend seviyesinde kapatıldı; yeni ve eski test kayıtları için savunma eklendi.
- Host network ve `NET_ADMIN` gerektiren özellik ayrı `docker-compose.source-ip.yml` dosyasına taşındı.
- Docker'ın non-root süreçte `NET_ADMIN`ı efektif vermediği doğrulandı; ileri mod UID 0, yalnızca `NET_ADMIN`, `cap_drop: ALL` ve `no-new-privileges` ile sınırlandı.
- `IPManager` shell pipeline kullanmadan arayüz keşfedecek ve kapalı durumda işlem yapmayacak şekilde güncellendi.
- Runtime imajına source-IP modu için gereken `iproute2` eklendi.
- Varsayılan/ileri mod capability davranışı tek kullanımlık konteyner ağında doğrulandı.

### 3. Global çalışma sınırları

- Aynı anda çalışabilecek test sayısını yapılandırılabilir semaphore ile sınırla.
- Bekleyen test kuyruğu ve kaynak limitlerini belirginleştir.
- Aşırı kuyruk oluşturmayı API seviyesinde sınırla.

Durum: Tamamlandı.

Uygulananlar:

- Global eşzamanlı test limiti eklendi (`DNSTRIKE_MAX_CONCURRENT_TESTS`, varsayılan 2, aralık 1-32).
- Bekleyen test kuyruğu limiti eklendi (`DNSTRIKE_MAX_QUEUED_TESTS`, varsayılan 100, aralık 1-10000).
- Kuyruk kapasitesi SQLite transaction içinde atomik olarak denetleniyor.
- Kuyruk doluyken `POST /api/tests`, HTTP 429 ve `QUEUE_FULL` hata kodu döndürüyor.
- Orchestrator yalnızca boş slot sayısı kadar testi seçiyor ve goroutine başlatmadan önce atomik durum geçişiyle sahipleniyor.
- Servis, SQLite, HTTP API, ortam yapılandırması ve orchestrator concurrency testleri eklendi.
- Tüm Go testleri, Docker build ve iki Compose yapılandırması başarılı.

### 4. İptal ve düzgün kapanış

- Her çalışan test için iptal edilebilir context sakla.
- Orchestrator `Stop` sırasında yeni iş almayı durdursun, çalışan işleri iptal edip beklesin.
- `time.Sleep` gibi iptali dinlemeyen noktaları context-aware beklemeye dönüştür.
- Ayrı bir test iptal endpoint'i ekle.

Durum: Bekliyor.

### 5. Yeniden başlatma recovery'si

- Başlangıçta sahipsiz `RUNNING` kayıtları güvenli biçimde `FAILED` veya yeniden kuyruğa alınmış duruma geçir.
- Sonuç ve hata nedenini kalıcı olarak sakla.
- Recovery davranışını test et.

Durum: Bekliyor.

### 6. Güvenli silme davranışı

- Çalışan testlerin doğrudan silinmesini engelle veya önce iptal et.
- Aktif testi bulunan hedefin silinmesini engelle.
- Veritabanı işlemleri ile orchestrator durumunu tutarlı hâle getir.

Durum: Bekliyor.

### 7. Hedef politikasını sıkılaştırma

- İzin verilen CIDR ve portları yapılandırılabilir allowlist yap.
- Link-local ve loopback hedefleri varsayılan politikadan ayır.
- Hedefi her senaryonun ağ bağlantısından hemen önce yeniden doğrula.
- IPv4/IPv6 ve özel adres sınırları için testleri genişlet.

Durum: Bekliyor.

### 8. Son doğrulama ve dokümantasyon

- Go kurulumu mevcut olduğunda unit ve race testlerini çalıştır.
- Frontend lint/build kontrollerini çalıştır.
- Docker imajını oluşturup yalnızca yerel, zararsız test hedefiyle smoke test yap.
- README ve örnek ortam yapılandırmasını güncelle.

Durum: Bekliyor.

Not: 2. adım Docker build'i sırasında npm, mevcut frontend bağımlılıklarında bir adet yüksek önem seviyeli audit bulgusu raporladı. Bağımlılık değişikliği yapılmadı; 8. adımda ayrıntılı incelenecek.

## Değişiklik Günlüğü

- 2026-10-26: İlk kaynak kod incelemesi tamamlandı ve aşamalı iyileştirme planı oluşturuldu.
- 2026-10-26: 1. adım tamamlandı; API ve WebSocket erişim koruması eklendi.
- 2026-10-26: 2. adım tamamlandı; güvenli ağ varsayılanları ve ayrı source-IP laboratuvar modu eklendi.
- 2026-10-26: 3. adım tamamlandı; global çalışma ve atomik kuyruk sınırları eklendi.
