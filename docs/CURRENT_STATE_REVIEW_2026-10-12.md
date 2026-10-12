# CrimsonWeb — Güncel durum, gizlilik eleştirisi ve yol haritası

Tarih: **12 Ekim 2026**, Europe/Istanbul.

Bu inceleme tarihsel snapshot'tır. Daha sonraki [Faz 4C.1 teslimi](PHASE4C1.md)
CLI stop/retry, ortak secret redaksiyonu, credential HTTPS, verification audit
minimization ve sınırlı admission maddelerinde düzeltmeler içerir. Yeni standart
test sonucu 785'tir; aşağıdaki 759 sonucu inceleme anına aittir. Retention, RBAC,
disk/yedek gizliliği ve diğer açık maddeler devam eder.

Bu inceleme kaynak kod, Git durumu, mevcut test/benchmark raporları ve yalnızca
sentetik bellek içi tanılama üzerinden yapıldı. Üçüncü taraf hedeflere istek
gönderilmedi. Ollama kontrolü yalnız localhost üzerinde yapıldı. Üretim kodu,
testler, model ayarları ve gerçek veritabanı değiştirilmedi; bu rapor eklendi.
Bu bir bağımsız tam penetrasyon testi veya gizlilik sertifikası değildir.

## 1. Ürün şu anda nerede?

CrimsonWeb artık yalnız port tarayıcısı değil. Mevcut kod şu temelleri içeriyor:

| Katman | Mevcut durum | Sınır |
|---|---|---|
| CLI ve servis analizi | Port/servis keşfi, web kontrolleri, raporlama, CVE eşleştirme | Eski CLI ile yeni kapsam motoru aynı güvenlik sınırına sahip değil. |
| API ve veri | FastAPI, SQLite/SQLAlchemy, Alembic, geçmiş kayıtları | Mevcut disk DB'si güncel şemaya taşınmamış. |
| Yerel AI | Ollama, JSON Schema, kanıt referansları, maskeleme, dil/iddia kontrolleri | Şema başarısı teknik doğruluk kanıtı değil. |
| Faz 4A | Workspace, politikalar, merkezi kapsam/DNS/SSRF/bütçe denetimi | Workspace qualifier, kullanıcı bazlı tenant yetkisi değil. |
| Faz 4B | Kontrollü keşif, OpenAPI içe aktarma, endpoint ve kaynak kanıtları | HAR/Burp/ZAP ve kapsamlı kimlikli tarayıcı keşfi yok. |
| Faz 5A/5A.1 | Minimal privacy observations, Host allowlist, API token, migration öncesi yedek | Retention enforcement, disk şifreleme ve OS route enforcement yok. |
| Faz 4C | Onaylı, iki kimlikle üç GET üzerinden BOLA/IDOR karşılaştırması | Tek katalog testi, tek üst seviye yanıt alanı ve tüm plan için tek nesne çifti. |

**Değerlendirme:** Tek operatörlü, kontrollü laboratuvar ve sınırlı yetkili API
incelemesi için sağlam bir temel var. Şirketlerin çok kullanıcılı biçimde
çalıştıracağı, kapsamlı web zafiyetlerini keşfedip doğrulayacak ürün henüz tamamlanmış
değil. LLM'nin mevcut Faz 4C katkısı bilinen tek testin adaylara atanmasıyla sınırlı;
uygulama iş mantığını anlayan araştırma döngüsü henüz yok.

### Git, deployment ve doğrulama

- Branch: `phase1-5a1-local`.
- HEAD: `f820229`, `CrimsonWeb Phase 1-5A.1 snapshot`, 9 Ekim 2026.
- Faz 4C kodu/migration/testleri çalışma ağacında; henüz commit edilmemiş.
- Gerçek `data/crimsonweb.sqlite`, read-only bağlantıyla kontrol edildi:
  **`0002_phase3`**, 6 tablo. Yeni kodun migration head'i **`0006_phase4c`**.
  Test DB'lerinin migration başarısı, gerçek DB'nin yükseltildiği anlamına gelmez.
- Bu oturumda aynı kaynak kod için elde edilen son standart test artefaktı:
  **759 başarılı, 0 failure, 0 error**, 5 opt-in deselected. Süre 77,27 saniye.
  XML zamanı 12 Ekim 2026 00:56:40 +03:00; kaynak:
  `reports/phase4c/standard_tests.xml`.
- 677 önceki standart test + 82 Faz 4C testi. Bu incelemede aynı suite yeniden
  çalıştırılmadı; önceki çalışmadan sonra üretim/test kodu değiştirilmedi.
- Yeni/değiştirilen Python dosyalarının Ruff ve `compileall -q src tests`
  kontrolleri önceki teslimde geçti. Bütün depo için **124 mevcut Ruff bulgusu**
  var; `reports/phase4c/ruff_summary.json`.
- Gerçek model suite'i önceki teslimde **5 skipped**. Bu incelemede de localhost
  Ollama endpoint'ine erişilemedi. Faz 4C'nin gerçek Gemma planlama uyumluluğu
  henüz doğrulanmadı. Geçmiş model benchmark başarıları bunu yerine geçmez.
- `.github/workflows/ci.yml` pytest çalıştırıyor; Ruff/compile/migration doğrulaması
  ayrı release gate olarak eklenmemiş. Bu yerel branch için CI başarısı doğrulanmadı.
- API metadata'sı hâlâ `CrimsonWeb Phase 3` / `0.3.0`; paket sürümü `2.1.0`.
  Ürün sürümü, faz ve API sözleşmesi sürümü ayrı ve tutarlı yönetilmeli.

## 2. Güçlü güvenlik ve gizlilik kararları

- Faz 4C istekleri merkezi kapsam motorundan geçiyor; model ağ yetkisi almıyor.
- Model çıktısındaki endpoint/kanıt kimlikleri deterministik doğrulanıyor.
- Kimlik bilgilerinin DB'ye yazılmaması ve ham yanıt saklanmaması iyi varsayılanlar.
- Cookie değerleri API cookie-flag bulgularında saklanmıyor; yalnız özellikler tutuluyor.
- İptal/kapanış ve kapsam dışı DNS/IP/CNAME senaryoları için otomatik testler var.
- 403 tek başına WAF ya da güvenli erişim kontrolü diye etiketlenmiyor.
- Privacy alanları ölçülmeyen anonimlik/route/retention garantilerini `False` olarak
  ifade ediyor. Bu dürüst sınırlar korunmalı.

## 3. Öncelikli kod bulguları

Öncelikler geliştirme sırasını belirtir; CVSS veya doğrulanmış dış saldırı puanı değildir.

### P0 — Eski CLI engellenmiş isteği retry ile sürdürebiliyor

Kaynak: `src/crimsonweb/core_engine.py:492`, `:501`, `:564`, `:579`.
`is_blocked` kontrolü retry döngüsünden önce. Engelleme sırasında hedef işaretleniyor
ama `continue`, döngünün sonraki denemesine geçiyor; işaret yeniden denetlenmiyor.

**Tanılama:** Ağ göndermeyen mock `_send_request` ile ilk yanıt blok sinyali,
`max_retries=1` için **iki gönderim çağrısı** gözlendi. Varsayılan retry 0 olduğundan
bu aynı-istek tekrarının oluşması retry ayarına bağlı. Ayrıca durdurma anahtarı
`netloc + path`; tüm engagement için ortak kalıcı durdurma değil.

`egress.py:343`, ban sırasında Tor kimlik değişimini çağırabiliyor. Legacy
`block_on_ban=False` yolu blok sinyalini yalnız gözlem olarak döndürüyor. Eski CLI
decoy/fingerprint/proxy özellikleri de yeni API'nin deterministik sınırından ayrı.
Bu davranışları yeni Verification Engine'e bağlamak doğru olmaz.

**İş:** CLI ve API için ortak engagement düzeyinde safe-stop; blok sonrası retry,
kimlik değiştirme ve diğer yollarla devam etmeyi engelleyen sözleşme testleri.
Eski kullanıcı seçenekleri için açık deprecation/migration davranışı tanımlansın.

### P1 — Genel maskeleme sırları tam kapsamıyor

Kaynak: `src/crimsonweb/privacy.py:10`, `:28`, `src/crimsonweb/audit.py:34`,
`src/crimsonweb/api/ai/security.py:77`.

**Sentetik tanılama:** `Authorization` ve `access_token` maskelendi;
`X-API-Key`, `client_secret`, `id_token` anahtarlarındaki sentetik değerler hem
`sanitize` hem `mask_data` içinde korundu. `sanitize` düz metindeki `Authorization:
Bearer ...` değerini de koruyor. CLI log filtresi bu string sanitizer'ı kullanıyor.
Bu, helper seviyesinde doğrulanan eksik; mevcut Faz 4C'de gerçek credential'ın
LLM'ye sızdığı gösterilmedi. Faz 4C bu başlıkları model girdisine hiç dahil etmiyor.

`egress.py:249/252` geçersiz proxy hatalarında tam proxy URL'sini formatlıyor;
userinfo içeren girdiler exception mesajında açığa çıkabilir.

**İş:** Ortak yapılandırılmış log alan allowlist'i; anahtar alias'ları, bearer/JWT,
userinfo ve hata redaksiyonu; tüm persistence/export sınırlarında aynı politika;
log enjeksiyonu ve sentetik sırların bütün log/DB/rapor katmanlarında yokluğu testleri.
Regex maskeleme tek başına bütün keyfi sırlar için garanti sayılmasın.
Referans: [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).

### P1 — Kimlik bilgisi taşıyan hedef isteğinde HTTPS zorunlu değil

Kaynak: `src/crimsonweb/api/engine.py:80`, `src/crimsonweb/api/scope.py` içindeki
HTTP(S) kabulü; `verification/models.py:158`.

Yetkili ve kapsam içi bir `http://` hedefe auth header eklenebiliyor. Kapsamda olmak
taşıma gizliliği sağlamaz. Yerel lab örnekleri için HTTP yararlı ama gerçek şirket
ve bounty hedeflerinde token/cookie'nin düz metin aktarımı gizlilik açığıdır.

**İş:** Credential içeren ağ isteklerinde HTTPS varsayılan zorunluluk; yalnız
açıkça onaylı, dar yerel lab istisnası. TLS hata sonrası HTTP/verify=False fallback
olmamalı. Yerel API dışarı açılacaksa API token'ı için de TLS ve deployment politikası.
Referans: [OWASP REST Security](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html).

### P1 — Faz 4C privacy minimization, kapsam audit'ine tam taşınmıyor

Kaynak: `src/crimsonweb/api/workspaces/store.py:426`.
Audit yalnız `privacy_owner` olduğunda resolved IP listesini boş bırakıyor.
Faz 4C ownerless lease kullanıyor; scope audit kayıtları gözlenen IP'leri saklıyor.
`workspaces/service.py:94` request URL'sini düz SHA-256 ile özetliyor; düşük entropili
nesne kimlikleri için bu kriptografik anonimlik sağlamaz ve kayıtları ilişkilendirir.

**İş:** Lease sahipliğinden bağımsız, ortak veri sınıflandırma/minimizasyon arayüzü.
Gerekli değilse IP kaydetme; korelasyon gerekiyorsa workspace bazlı anahtarlı
pseudonymization ve uygun key storage. Scope CIDR konfigürasyonu ile gözlenen
istemci/hedef geçmişi ayrı veri sınıfları olsun.

### P1 — Retention ve silme henüz gerçek bir yaşam döngüsü değil

Kaynak: `src/crimsonweb/api/privacy/models.py:27`, `:28`,
`src/crimsonweb/api/privacy/store.py:210`.
`retention_days=7` var ama `retention_enforced=False`. Profil silme tombstone;
geçmiş ve anahtar kalıyor. Verification plan/kanıtları için de otomatik purge yok.
Legacy ScanReport hedef URL, IP, seçilmiş başlık ve bulgu değerlerini kalıcı tutuyor
(`database.py:618/633`, `api/models.py`); AI öncesi masking bunu geriye dönük temizlemiyor.

**İş:** Aktif iş/lease koruyan preview'li batch purge; çalışma alanına göre saklama
politikası; DB, export, log ve yedek kapsamı; kanıt legal hold tercihi. SQLite/WAL,
SSD ve yedekler nedeniyle DELETE işlemi fiziksel secure erasure diye sunulmamalı.

### P1 — Kuyruk beklerken kimlik bilgileri bellekte birikebilir

Kaynak: `src/crimsonweb/api/verification/routes.py:26`,
`src/crimsonweb/api/verification/service.py:130`.
Execute payload önce okunuyor, sonra ortak `_execution_gate` bekleniyor.
Bekleyen execution sayısına sınır yok; her bekleyen task iki credential referansı
tutabiliyor. Bu, doğrulanmış bir yük testi sonucu değil; koddan görülen kaynak ve
secret-lifetime riski. API ingest sınırı 1 MiB ama toplam kabul edilen task sayısını
tek başına sınırlamıyor.

**İş:** Bounded admission, queue-full 409/429 ve credential TTL; mümkünse execute
slotu hazır olmadan credential kabul etme. Ham credential durable kuyruğa taşınmasın.
Process crash/OS dump/swap için Python'un fiziksel bellek silme garantisi olmadığı
belgelenmeye devam etsin.

### P1, şirket kullanımında — Ortak token kullanıcı sahipliği sağlamıyor

Kaynak: `src/crimsonweb/api/app.py:135`, `verification/models.py:110`.
Tek API token'ı bütün workspace'lere operatör yetkisi veriyor. Workspace izolasyonu
yanlış qualifier ile bir kaydı okumayı engelliyor ama kullanıcı/workspace üyeliği
modeli yok. `approved_by` istemcinin gönderdiği metin; doğrulanmış kullanıcı kimliği
ve ayrı reviewer onayı değil. Bu, mevcut tek-operatör güven sınırının belgelenmiş
bir sınırı; bugünkü cross-workspace FK korumasının kırıldığı iddiası değil.

**İş:** Takım kullanımından önce principal, üyelik/RBAC, server-derived approver,
token rotation/revocation ve gerektiğinde ayrı onay rolü. Host allowlist client
kimlik doğrulamasının yerine geçmez. API docs/OpenAPI erişim politikası da açık olsun.

### P1 operasyon — Şifresiz DB/yedekler ve OneDrive çalışma yolu

Kaynak: `src/crimsonweb/api/database.py:508`, `:525`, `:554`.
SQLite ve backup dosyaları uygulama düzeyinde şifrelenmiyor. Proje OneDrive dizininde;
gerçek senkronizasyonun açık olduğu doğrulanmadı, ancak data/log/export/backup'ın
bu ağaç altında olması olası cloud sync/yerel hesap paylaşımı sınırıdır. `.gitignore`
Git commit'ini engeller; OneDrive sync veya dosya ACL'si sağlamaz.

Privacy HMAC anahtarı aynı DB'de (`database.py:301`, `privacy/store.py:151`): bu
pseudonymization'dır; DB ele geçirilmesine karşı güçlü anonimleştirme değildir.

**İş:** Runtime verisini senkronize olmayan ayrı dizine taşıma, dar Windows ACL,
disk şifreleme, yedek/export erişim ve retention politikası; gerekiyorsa DPAPI veya
ayrı key-management tasarımı. Kaynak repo ayrı kalabilir.

### P2 — Migration backup bütünlüğü çok-process için kanıtlanmamış

`backup_sqlite` DB/WAL/SHM'yi sırayla `copy2` ile kopyalıyor ve boyutu karşılaştırıyor.
Mevcut engine'i dispose etmek başka process'in yazmadığını kanıtlamaz. Şu anda
bozuk backup gözlenmedi; eşzamanlı yazma altında tutarlılık garantisi eksik.

**İş:** Kontrollü bakım modu ve tek migration owner; SQLite online backup yaklaşımını
değerlendir; açılıp integrity-check yapılan restore testleri. Manuel Alembic komutu
otomatik backup'ı atladığı için explicit backup gerektirir.

### P2 — Kanıt/LLM ve onay semantiği sınırlı

Faz 4C `confirmed`, doğru private-record/ownership beklentisinin operatörden geldiği
varsayımına bağlı. Aynı nesne çifti ve binding alanı tüm planda kullanılıyor;
iş mantığı paylaşım yetkisini sistem bağımsız olarak bilmiyor. 403'te durma güvenli
ama normal yetki reddini ölçen planlarda kapsamı kısıtlıyor; bu sonuçlar doğru şekilde
inconclusive kalmalı, blok atlanarak devam edilmemeli.

Plan approval mevcut origin/alanı bağlıyor ama policy revision'ını onay snapshot'ına
bağlamıyor. Her istek güncel politikayla yetkilendirildiği için bu doğrudan scope
bypass değildir; operatörün onayladığı planın anlamı değişebilir.

Model fallback tüm hataları tek limitation altında topluyor. Input limiti aday
metadata'sını ölçüyor, schema/system prompt toplam token maliyetini değil.
Başlık enum'ları ve referans doğrulaması teknik yorum doğruluğunu kanıtlamaz.

**İş:** Endpoint/test bazında nesne çiftleri, beklenen izinler, immutable approval
revision; güvenli sabit planner error-code ayrımı; prompt+schema token bütçesi;
ground-truth laboratuvar değerlendirmesi ve insan incelemesi.

## 4. Performans değerlendirmesi

### Koddan görülen darboğazlar

- `api/engine.py:85`: her istek yeni `httpx.AsyncClient`; TCP/TLS pooling yok.
  Kontrollü canlı RTT/TLS ölçümü yapılmadı, dolayısıyla kazanç oranı bilinmiyor.
  Pooling ancak credential/cookie/workspace izolasyonu ve her istekte taze scope/DNS
  admission korunarak yapılmalı; ortak cookie jar oluşturulmamalı.
- Verification execution tüm workspace'ler için tek process-içi lock ile seri.
  Güvenli başlangıç; takım iş yükünde head-of-line bekleme yaratır. Kuyruk önce
  bounded olmalı; concurrency yalnız ölçüm ve politika izinleriyle artırılmalı.
- `verification/service.py` içinde senkron store çağrıları async event loop üzerinde.
  Paylaşılan Repository RLock / SQLite busy timeout 5 saniye ile DB beklemesi API
  polling/iptal yanıtlarını geciktirebilir. Bu risk yük altında ölçülmedi.
- DB işlemleri `BEGIN IMMEDIATE` ve aynı repository lock ile serileşiyor. SQLite
  tek-host ürün için uygun; WAL/indeks/transaction süresi ölçülmeden sırf performans
  için başka veritabanına geçmek gereksiz.
- Her test en çok 3 HTTP okuması. 50 proposal sınırı, bütçe izin verirse 150
  istek anlamına geliyor. Aynı kontrol sonuçlarını yeniden kullanmak stale veri ve
  yanlış pozitif riski yaratır; rastgele global cache eklenmemeli.
- Network timeout transportta 5 saniye, dış okuma sınırı 30 saniye.
  Plan toplam deadline'ı ve kuyruk bekleme metriği ayrı tanımlanmamış.
- Report farklı store okumalarından kuruluyor; execution sürerken tutarlı snapshot
  garantisi yok. Uzun raporlar için tek snapshot ve sorgu/bellek maliyeti ölçümleri.
- `.github/workflows/ci.yml` kalite borcunu tek başına yakalamıyor; yeni kontrol
  adımları ve değiştirilmiş alanlar için no-new-lint baseline gerekiyor.

### Ölçülmüş değerler ve sınırları

Bu inceleme anındaki sistem snapshot'ı: **31,62 GiB toplam RAM, 12,06 GiB boş RAM**;
GPU **8188 MiB toplam, 2179 MiB kullanım, %4 utilization, 43 °C**. Bunlar bütün
sisteme ait anlık sayaçlar; CrimsonWeb veya yüklü model maliyeti olarak sunulamaz.
Ollama erişilemedi; yeni inference, VRAM veya planlama benchmark'ı yapılmadı.

9 Ekim raporu `docs/QWEN_VS_GEMMA.md` tarihsel, n=3 sentetik karşılaştırma:

| Metrik | Qwen 3.5 9B | Gemma 4 26B |
|---|---:|---:|
| Soğuk bulgu duvar süresi medyanı | 43,718 s | 55,632 s |
| Sıcak tam tarama analizi | 56,252 s | 41,949 s |
| Sıcak WAF analizi | 39,968 s | 30,063 s |
| Sıcak API/BOLA salt analiz | 69,537 s | 54,327 s |
| Soğuk model load medyanı | 5,415 s | 28,338 s |
| Gözlenen minimum boş sistem RAM | 14,695 GiB | 0,891 GiB |

Her model 12/12 yapılandırılmış analiz vakasında geçti; teknik metin hataları ayrıca
raporlanmış. Bu Faz 4C executor/planlayıcısının gerçek-model değerlendirmesi değil.
İki model de yaklaşık 7,6 GiB toplam GPU kullanımına ulaştı; Qwen avantajı bu
raporda esasen RAM ve soğuk yükleme. Üretim modeli bu incelemede değiştirilmedi.

Faz 5A eski mock benchmark'ında startup 22,453 ms, egress medyanı 57,126 ms ve
working-set artışı yaklaşık 2,37 MiB: yalnız 7 seri mock iş, AI/GPU yok.
Bu sonuçlar Faz 4C'nin canlı hızını veya bütün ürünün bellek maliyetini göstermiyor.

**Ölçüm planı:** Aynı lokal fixture ile 1/10/50 test planı; AI açık/kapalı;
soğuk/sıcak model; request/queue/DB/model süreleri ayrı; p50/p95, event-loop gecikmesi,
RSS/VRAM, peak pending jobs. Secret/body loglama olmadan sabit metrikler.
İlk hedef concurrency'yi yükseltmek değil, sınırsız birikmeyi önlemek olmalı.

## 5. Önceliklendirilmiş yol haritası

Aşağıdaki sıra öneridir. Bu incelemede hiçbir yeni faz uygulanmadı.

| Sıra | Teslim dilimi | Somut işler | Geçiş ölçütü |
|---|---|---|---|
| 1 | Faz 4C.1: privacy ve safe-stop bütünlüğü | CLI blok/retry davranışı, auth için HTTPS, ortak log redaksiyonu, scope audit minimization, queue sınırı, güvenli proxy hataları | Mock blok sonrası yeni istek 0; sentetik sırlar tüm persist/log/export'ta yok; kuyruk sınırı ve TLS lab istisnası testli. |
| 2 | Runtime ve veri yaşam döngüsü | Nonsync data dizini/ACL, backup+restore, kontrollü gerçek DB upgrade, retention preview/purge, crash reconciliation | Test migration/restore başarılı; gerçek DB upgrade ayrı kayıtlı; aktif lease kaybı yok; silmenin sınırları açık. |
| 3 | Faz 4D ilk dilim: tekrar üretilebilir verification işleri | Bounded background run/worker, endpoint bazlı nesne çiftleri/izin beklentileri, onay revision binding, minimal rapor snapshot | Crash sonrası otomatik kontrolsüz resume yok; iptal/onay/policy değişimi fence testleri; güvenli laboratuvar tekrar üretimi. |
| 4 | Araştırmacı keşif iş akışı | Redakte edilen HAR/Burp/ZAP importer, OpenAPI+trafik birleştirme, endpoint/rol/parametre envanteri, izinli oturum keşfi | Ham session/PII içe alma sınırında temizleniyor; kaynak kanıtları ve tüm workspace ilişkileri testli. |
| 5 | LLM araştırma kalitesi | Aday önceliklendirme, testable hypothesis, mevcut katalogdan plan, sabit hata teşhisi, token/RAM bütçesi, Gemma/Qwen yeni eval | Gerçek lokal model yeni şemada başarılı; ground truth ile precision/recall, Türkçe ve prompt-injection sonuçları ayrı raporlu. |
| 6 | Kontrollü test kataloğu ve bounty raporu | Önce ek salt okunur yetki/rol kontrolleri; sonra izole labda ayrı test aileleri; dedup, etki ve redakte tekrar adımları | Zafiyetli ve güvenli fixture'lar birlikte; kanıtsız doğrulama yok; program kuralları ve onay sınırları değişmiyor. |
| Takım kullanımı öncesi zorunlu | Kimlik ve tenant yetkisi | Principal, workspace üyeliği/RBAC, doğrulanmış approver, token lifecycle | İki farklı kullanıcıyla bütün endpoint'lerde cross-tenant ret testleri; ortak token'a güvenerek tenant ayrımı iddiası yok. |
| Pilot öncesi | Release ve performans kapıları | CI lint/compile/migration, dependency değerlendirmesi, versiyonlama, lokal yük benchmark'ı, operasyon kılavuzu | Test artefaktları versioned; eski Ruff borcu açık; latency/bellek hedefleri ölçüme dayalı. |

Managed egress gerekiyorsa ayrı bir route enforcement dilimi olarak tasarlansın:
önceden onaylı sabit rota, DNS/SNI/certificate/scope koruması ve rota başarısızlığında
direct fallback olmaması. IP rotasyonu, engel aşma veya gizli tarama bu yol
haritasının parçası değildir. Privacy observation anonimlik veya OS kill switch
sağlamadığı için bu iddialar ürün diline eklenmemeli.

## 6. Önerilen bir sonraki görev

Yeni zafiyet aileleri eklemeden önce **Faz 4C.1 gizlilik ve güvenli durdurma**.
Önce sentetik tekrar testleri, ardından dar kod düzeltmeleri; mevcut CLI sözleşmeleri
için açık uyumluluk planı. Aynı dilimde veri saklama/şifreleme çözümünü aceleyle
genişletmek yerine runtime verisi yerleşimini ve deletion politikası tasarımını
somutlaştır. Faz 4D ancak bu kapılar ve gerçek lokal model şema testi tamamlanınca.

Bu yaklaşım CrimsonWeb'in araştırmacıya değerini artırır: daha çok HTTP isteği
göndermenin ötesinde, doğru kapsam içinde tekrarlanabilir ve gizliliği korunmuş
kanıt üretme; LLM'nin teknik varsayımı ile gerçekten gözlenen sonucu ayırma.
