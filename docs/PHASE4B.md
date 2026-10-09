# CrimsonWeb Faz 4B — AI-ready web ve API keşfi

Tarih: 9 Ekim 2026. Yalnız Faz 4B uygulanmıştır; Faz 4C/4D başlatılmadı.
Başlangıçta `PHASE4A.md`, `QWEN_VS_GEMMA.md`, mevcut kod ve Git çalışma ağacı incelendi.
Önceki fazlardan kalan değişiklikler korunmuştur. Yeni bağımlılık eklenmedi.

## Gerçekten çalışan bileşenler

| Bileşen | Uygulanan davranış |
|---|---|
| DiscoveryJobManager | SQLite kalıcı görev, en fazla 8 bekleyen/çalışan yerel task, tek seri worker, iptal ve cleanup |
| AuthorizedCrawler | GET ile aynı origin HTML/API gözlemi; her gerçek gönderim ortak WorkspaceService guard'ından geçer |
| EndpointInventory | Job içinde origin özeti + maskeli path + method için deterministik UUID5; tekrar kayıtları birleştirir |
| FormAnalyzer | Form action/method, alan adları ve tip göstergeleri; değerler ve metinler atılır, form gönderilmez |
| OpenAPIImporter | JSON OpenAPI 3.0/3.1 ve Swagger 2.0; yerel `$ref`, parametreler, method ve security göstergeleri |
| ApplicationSurfaceGraph | Endpoint, resource, authentication, parameter, olası owner, link, redirect ve evidence ilişkileri |
| DiscoveryEvidenceStore | Workspace/job ile nitelendirilmiş kayıtlar, atomik SQLite işlemleri, bileşik foreign key ve referans kontrolleri |
| Discovery summary | En fazla 32 KiB maskeli JSON; güvenilmeyen gözlem verisi olarak işaretlenir; AI çağırmaz |

Crawler bütün HTTP istemcilerini mevcut `pinned_response()` üzerinden kullanır. Ayrı bir
izin sistemi, bağımsız ağ istemcisi veya legacy CLI ağ yolu eklenmedi. Eski header/TLS/CORS
analiz fonksiyonları yeniden yazılmadı. Workspace keşif sonuçları yeni tablolardadır;
legacy scan/finding/WAF/AI kayıtları otomatik workspace'e taşınmaz.

## Kapsam ve gönderim güvenliği

1. Başlatma için aktif workspace, onaylı ve geçerli politika ve açık `crawl` kategorisi
   gerekir. Seed ön kontrolü DNS yapabilir ama HTTP veya request rezervasyonu oluşturmaz.
2. Her gönderim `WorkspaceService.stream()` ile yeniden doğrulanır: domain, CNAME,
   IP/CIDR, port, path, method, kategori, izin süresi, çalışma zamanı, workspace durumu ve halt.
   DNS her gönderimde yenilenir; bağlantı doğrulanmış IP'ye sabitlenir, Host/SNI korunur.
3. Policy ve discovery job bütçesi, worker kimliği, iptal ve policy revision aynı SQLite
   admission transaction'ında kontrol edilir. Eski policy revision ile oluşturulmuş job
   politika güncellenince sonraki gönderimde durur; yeni politikanın kendisi bu yüzden halt edilmez.
4. HTTPX otomatik redirect, proxy ortamı, cookie/session aktarımı veya retry kullanmaz.
   Keşif `Accept-Encoding: identity` ister; legacy scanner'ın Origin davranışı korunur,
   discovery gözlemlerine CORS probe Origin başlığı eklenmez.
5. Redirect'in her hop'u ayrıca guard'dan geçer. Scheme/host/port değişimi aynı origin
   değildir; HTTP→HTTPS geçişi de bu sürümde durur. Dış scope linkler ağ isteği olmadan atılır.
6. 403/429 politikayı kalıcı olarak durdurur, güvenli HTTP metadata kanıtı kaydedilir ve
   görev `halted_by_policy` olur. 403 tek başına WAF veya IP engeli olarak kesin sınıflanmaz.
   Faz 4A'nın `notify_defense()` arayüzünden bildirilen WAF/IP/authorization halt'ı sonraki
   admission'ı engeller. IP rotasyonu, engel aşma ve gizli tarama eklenmedi.
7. Policy budget/rate/concurrency veya job budget kapasitesi bitince görev kısmî sonuçla
   durur. Limit dolduğu için otomatik bekleme, yeniden deneme veya bütçe iadesi yapılmaz.

Query ve percent-encoded path için Faz 4A'nın yasakları **açılmadı**. Aktif URL'de query
(boş `?` dahil), credentials, dot segment, backslash, çift slash path, whitespace,
non-ASCII/encoded/reserved path yazımı reddedilir; HTTPX'in normalize ettiği yazımlar
izinli URL'ye dönüştürülerek gönderilmez. HTML fragment yalnız ağ anlamı taşımadığı için atılır.
Query isimleri ve gözlenen primitive tipleri envantere alınabilir; URL değerleri atılır,
bu linkler HTTP'de denenmez. Formlar yalnız adaydır. Sayısal/UUID/owner resource yolları
ve bilinen mutation/action yolları da ağda denenmez; seed olarak verilirse açıkça reddedilir.
Bu konservatif kontroller GET'in her uygulamada yan etkisiz olduğunu ispatlamaz: program
politikası güvenli olmayan GET yollarını ayrıca yasaklamalıdır.

Özel ağ ancak Faz 4A'nın owned/lab + açık private network izni + açık CIDR koşullarıyla
erişilebilir. Metadata servisleri ve bilinmeyen/karışık DNS cevapları için mevcut reddetme
kuralları korunur. Keşif engelliyse aşağıdaki offline import kullanılabilir; onaysız politika
aktif crawl başlatamaz, offline import ise DNS/HTTP yapmaz.

## Kaynak, veri ve envanter sınırları

| Limit | Varsayılan | Kabul edilen aralık |
|---|---:|---:|
| max_depth | 2 | 0–8 |
| max_pages | 20 | 1–200 |
| max_requests | 40 | 1–500 |
| max_body_bytes | 262144 | 1024–1048576 |
| max_endpoints | 200 | 1–500 |
| max_redirects | 5 | 0–10 |

Policy limitleri daima ayrıca uygulanır; küçük olan sınır belirleyicidir. Job
`requests_made` sayacı admission sayısıdır; başarısız bağlantı veya iptal edilmiş bir
admission da bütçe tüketir. `pages_processed` ise başarılı gözlem/persist sonrası ilerler;
engelde veya gövde limitinde request sayısından küçük olabilir.

HTML/JSON gövdeleri stream olarak okunur, Content-Length ve gerçek okunan byte kontrol
edilir. Sıkıştırılmış gövde işlenmez; genel gövde okumasında 10 saniye sınırı vardır,
mevcut HTTP transport timeout'u 5 saniyedir. Diğer content-type gövdeleri indirilmez.
HTML'de en fazla 128 link, 10 form, form başına 50 alan; frontier en fazla 500 öğe;
job başına en fazla 1000 evidence ve 4000 ilişki saklanır. Envanter/graph sınırı dolunca
önceden doğrulanmış kısmî veri korunur; atılan endpoint'e dangling relation yazılmaz.

Ham HTML/JSON, form değerleri, query değerleri, cookie/token, challenge header içeriği,
OpenAPI örnek/description/contact/security scope değerleri, server URL ve harici ref
URL'leri kalıcılaştırılmaz. URL/origin/source için SHA-256 özeti, maskeli path,
method, alan adı/tip, status, content-type, zaman ve sabit limitation kodları tutulur.
Alan adları sınırlı ASCII identifier kabul listesiyle filtrelenir; tüm Unicode alan
adlarının envanteri desteklenmez.
Bilinen resource kimlikleri `{id}`, olası secret/uzun/uygunsuz segmentler `{redacted}` olur.
Kısa ve alışılmadık uygulama slug'larının tamamının kişisel veri olup olmadığını bu
heuristic anlayamaz; metadata sınıflandırması evrensel PII/DLP garantisi değildir.
Ham input seed/spec worker RAM'inde geçici olarak tutulur, diske yazılmaz.
Hata yanıtları ve loglarda raw prompt, response veya secret input echo edilmez.

Endpoint kaydında `observation_status=request_guarded`, bu sürümde gerçekten guard ile
istenmiş GET'i belirtir. `candidate_only`, link/form/OpenAPI yapısındaki ağda doğrulanmamış
adayı belirtir. OpenAPI POST/PUT/DELETE route'ları method envanteri sağlar; çağrılmazlar.
OpenAPI ilanı için policy veya scope doğrulanmış kabul edilmez. `base_url` yalnız relative
route origin özetidir; hedef eklemez ve fetch yapmaz. Advertised servers her zaman yok sayılır.

## Veritabanı ve kanıt sözleşmesi

Alembic head: `0004_phase4b`, önceki revision: `0003_phase4a`.

- `discovery_jobs`: workspace/policy, durum, private worker UUID, iptal, sayaç, zaman,
  revision, seed özeti, limit ve limitation alanları.
- `discovery_endpoints`: workspace/job + route fingerprint ile dedup ve güvenli JSON metadata.
- `discovery_evidence`: `discovery_evidence:<UUID>`, kaynak özeti, zaman, status/mime ve byte sayısı.
- `discovery_relations`: workspace/job endpoint ve evidence bileşik FK'leriyle ilişkiler.
- `scope_request_leases`: nullable discovery job/worker sahipliği; eski lease'ler null kalır.

Job-policy FK workspace'i, endpoint/evidence FK job+workspace'i, relation FK'leri
endpoint/evidence+job+workspace'i eşleştirir. Evidence store, evidence UUID/ref eşleşmesini,
batch relation ref'lerini ve endpoint ref'lerinin aynı job'daki mevcut/yeni evidence'e ait
olduğunu işlemden önce kontrol eder. Sahte ref atomik olarak reddedilir. Endpoint'in
20 referanslık listesi dolduğunda en güncel gözlemin referansı öncelikle korunur;
evidence kayıtlarının kendisi bu liste sınırı nedeniyle silinmez.
Kaynak/endpoint/resource kimlikleri job'a aittir; iki job arasında UUID eşitliği beklenmez.
Resource node'ları endpoint'lerden deterministik olarak üretilir; `potential_owner`
ilişkisi `source_resource_id` taşır ve aynı job endpoint/evidence kaydıyla desteklenir.
Owner/authentication/type bilgilerinin tamamı araştırma adayıdır, IDOR/BOLA bulgusu değildir.

## Worker, iptal ve recovery

Durumlar: `queued`, `running`, `completed`, `partially_completed`, `cancelled`,
`failed`, `halted_by_policy`. Başlatma ve terminal kararlar scope audit'e yazılır.

Bir local SQLite veritabanı için yalnız bir cooperating discovery worker, işletim sistemi
file lock'unu tüm worker ömrü boyunca tutar. SQLite dosyasının yanında `.discovery.lock`
bulunur; Windows byte-range lock, POSIX flock kullanılır. In-memory test DB'si engine'e
bağlı process lock kullanır. Worker kilidi alamayan API instance listeleme/iptal yapabilir
ama yeni job başlatamaz (409). Önerilen sunucu topolojisi bir Uvicorn worker'dır.

Restart'ta **otomatik devam yoktur**: seed/spec diske yazılmadığından frontier tekrar
oluşturulmaz. Fresh exclusive OS lock acquisition eski cooperating worker'ın sona erdiğini
kanıtlar. Ancak bundan sonra queued/running kayıtlar `failed/worker_interrupted_verified`
yapılır; doğru job/workspace/policy/worker sahibi bilinen eski discovery rezervasyonları
serbest bırakılır, recovery audit'i yazılır. Terminal job'un DB cleanup hatası nedeniyle
kalmış lease'i de aynı sahiplik şartlarıyla kurtarılır. Eski/unknown legacy lease'ler korunur.
Bütçe geri verilmez. PID reuse, heartbeat veya timeout süreç ölümü kanıtı sayılmaz.
Recovery izni her fresh lock acquisition için tek kullanımlıktır; aynı manager'ın yeniden
startup çağrısı çalışan job'u veya lease'ini değiştirmez.

Yerel task iptali, HTTP response kapanışı ve guard lease cleanup tamamlandıktan sonra
terminal durum bildirir. İkinci iptal cleanup'ı tekrar kesmez. Başka API process'inden gelen
iptal SQLite flag'i ile iletilir; admission/observation öncesi ve persist'te kontrol edilir.
Worker shutdown task'ları kapatıp join etmeden lifetime lock'u bırakmaz. DB hatası sırasında
shutdown cancellation yazımı başarısız olsa bile HTTP task'ları join edilir. Sürekli storage
arızasında terminal durumu yazmak mümkün olmayabilir; stale kayıtlar bir sonraki kanıtlı
recovery'de işlenir, başarısız iş tamamlandı diye gösterilmez.

Bu protokol aynı local DB ve aynı lock dosyasını kullanan cooperating süreçler içindir;
distributed worker, birden fazla host, network filesystem veya cloud sync aracılığıyla
kilit koordinasyonu sağlamaz. Lifetime lock dosyası çalışan süreç varken silinmemelidir.

## API

Prefix: `/api/v1/workspaces/{workspace_id}/discovery`.
Mevcut app authentication dependency tüm route'larda uygulanır. Ortak operatör token'ı
korunur; workspace object isolation servis/API/DB katmanındadır. User/tenant ownership
ve kullanıcı bazlı RBAC bu fazda eklenmedi; token sahibi workspace yönetebilir.

| Method | Suffix | Sonuç |
|---|---|---|
| POST | `/jobs` | Crawl kabulü, 202 |
| POST | `/openapi` | Offline JSON spec kabulü, 202 |
| GET | `/jobs` | Liste, `status`, `limit=1..100`, `offset=0..1000000` |
| GET | `/jobs/{job_id}` | Durum/sayaç/limit, private worker bilgisi yok |
| POST | `/jobs/{job_id}/cancel` | İptal isteği/cleanup; terminal job idempotent |
| GET | `/jobs/{job_id}/endpoints` | Sayfalı metadata |
| GET | `/jobs/{job_id}/evidence` | Sayfalı güvenli evidence |
| GET | `/jobs/{job_id}/graph` | Sınırlı endpoint/resource/ilişki graph |
| GET | `/jobs/{job_id}/summary` | Maskeli ve güvenilmeyen discovery JSON |

Hatalar: 401 authentication, 403 aktif yetki reddi, 404 farklı workspace/bilinmeyen kayıt,
409 worker/queue/ownership/policy conflict, 413 input >1 MiB, 415 JSON dışı request,
422 UUID/model/URL/spec doğrulaması, 503 storage hatası. Eski global Conflict yanıt metni
policy conflict formatını korur; discovery tarafında 409 için worker/queue durumu da
kontrol edilmelidir. Input request schema'ları `/openapi.json` içinde inline limits ile
tanımlıdır; raw input validation hatalarda geri yansıtılmaz. Optional policy ID, offline
import'ta da başka workspace'ten alınamaz.

### Kurulum ve migration

```powershell
.venv\Scripts\python.exe -m pip install -e ".[api,dev]"
# Gerçek veritabanını backup aldıktan sonra, çalışan uygulamayı durdurarak:
$env:CRIMSON_DATABASE_URL = "sqlite:///data/crimsonweb.sqlite"
.venv\Scripts\python.exe -m alembic -c alembic.ini upgrade head
.venv\Scripts\python.exe -m alembic -c alembic.ini current
# CRIMSON_API_TOKEN'u mevcut güvenli operatör token'ıyla process ortamında ayarla.
.venv\Scripts\python.exe -m uvicorn crimsonweb.api.app:app --app-dir src --host 127.0.0.1 --port 8000 --workers 1 --no-proxy-headers
```

Mevcut app startup migration'ı head'e yükseltir; canlı çoklu süreçte migration çalıştırmak
yerine bakım sırasında yukarıdaki komutu kullanın. Testler gerçek çalışma veritabanını
değiştirmez. `alembic downgrade 0003_phase4a` yalnız sunucu/worker durdurulmuş, aktif job ve
açık discovery lease kalmamışken mümkündür. Geri alma **discovery tablolarını ve discovery
verisini siler**, eski scan/AI/workspace/policy/audit/legacy lease ve tüketilmiş bütçeyi korur.
Tekrar `upgrade head` şemayı kurar, silinen discovery verisini geri getirmez.

### API kullanımı — yalnız kendi izinli laboratuvarınız

Mevcut Faz 4A API'siyle lab workspace ve açık onaylı politika oluşturun. Politikada
`crawl`, tam domain/IP/CIDR/port/path, izinli `GET`, zaman ve limitler belirtilmelidir.
`CRIMSON_ALLOWED_HOSTS` legacy allowlist ayarı workspace crawl onayı yerine geçmez.

```powershell
$base = "http://127.0.0.1:8000/api/v1/workspaces/$workspaceId/discovery"
$headers = @{ Authorization = "Bearer $env:CRIMSON_API_TOKEN" }
$body = @{
    policy_id = $policyId
    seeds = @("http://localhost:8001/")
    limits = @{ max_depth = 2; max_pages = 10; max_requests = 15; max_body_bytes = 131072 }
} | ConvertTo-Json -Depth 6
$job = Invoke-RestMethod "$base/jobs" -Method Post -Headers $headers -ContentType "application/json" -Body $body
Invoke-RestMethod "$base/jobs/$($job.id)" -Headers $headers
Invoke-RestMethod "$base/jobs/$($job.id)/endpoints?limit=20" -Headers $headers
Invoke-RestMethod "$base/jobs/$($job.id)/summary" -Headers $headers
Invoke-RestMethod "$base/jobs/$($job.id)/cancel" -Method Post -Headers $headers

# Crawl izni olmayan programlarda: yerel JSON spec, hiçbir server/ref fetch yapılmaz.
$document = Get-Content -Raw -LiteralPath .\lab-openapi.json | ConvertFrom-Json
$body = @{ document = $document } | ConvertTo-Json -Depth 60
$offline = Invoke-RestMethod "$base/openapi" -Method Post -Headers $headers -ContentType "application/json" -Body $body
```

Yeni CLI crawl komutu eklenmedi. Mevcut CLI workspace/policy job arayüzünü taşımadığı için
keşif operatörün mevcut doğrulanan API'si üzerinden sunulur. Eski CLI komutları değişmedi.

## LLM hazırlığı ve Faz 4C geçiş koşulları

Summary alanları: `schema_version=discovery.v1`, workspace/job UUID,
`discovered_endpoints`, `discovered_resources`, `authentication_indicators`,
`resource_relationships`, `potentially_sensitive_operations`, `evidence_refs`,
`discovery_limitations`. En fazla 32 endpoint, endpoint başına 12 parametre/3 form,
form başına 10 alan, 64 ilişki; byte sınırı aşılırsa ilişkileri/resources/ref'leriyle
birlikte endpoint'ler çıkarılır ve `summary_truncated` yazılır. Tam envanter API'de kalır.

`untrusted_discovery_data=true`, `model_claims_verified=false`,
`network_execution_permitted=false` değişmez sözleşmedir. HTML text/script/style/template
ve OpenAPI description/examples prompt olarak geçirilmez. Route/alan adı gibi kalan
etiketler yine untrusted veri sayılır; prompt injection'ın semantik olarak tamamının
temizlendiği iddia edilmez. Şu anda discovery için **hiçbir model çağrısı yoktur**.
Mevcut AI production kodu, OllamaProvider, Faz 3.5 JSON schema/ref doğrulaması ve model
ayarları değiştirilmedi. Gemma 4 ana, Qwen alternatif model profili korunur.

Somut sonraki faz ön koşulları (bu teslimde uygulanmadı):

1. Ayrı `discovery.v1` input adapter ve ayrı AI yorum sözleşmesi tasarla. Mevcut
   finding/WAF ref schema'sına discovery ref'lerini sessizce ekleme; her yorumun aynı
   workspace/job evidence'ine bağlanmasını deterministik olarak test et.
2. İnsan tarafından onaylanan test planı, kategori/method/path/budget ve kanıtlı
   gerçek rol/nesne sahipliği ground truth'u olmadan adaydan IDOR/BOLA sonucuna geçme.
   Yetkilendirilmiş iki lab identity ve sentetik nesnelerle test fixture'ları oluştur.
3. Aktif test executor yalnız ortak WorkspaceService üzerinden çalışmalı; AI
   scope değiştiremez, yeni hedef ekleyemez veya doğrudan ağ aracı kullanamaz.
4. Query/encoded-path/session desteği gerekiyorsa ayrı canonicalization/SSRF,
   redirect/CNAME/rebinding, credential lifecycle ve cross-workspace test planı geliştir.
   Bu fazın kapalı URL sözleşmesini otomatik genişletme.
5. Mutating operasyon, authentication ve storage/worker kapasitesi için açık approval,
   isolation, iptal/recovery ve kaynak limitlerini release gate yap. Çok host gerekiyorsa
   local file lock yerine kanıtlanmış koordinasyon tasarla; SQLite protokolünü varsayma.
6. Yeni Faz 4C release'i mevcut 469 standart test, opt-in gerçek Gemma testleri ve
   hedefli Ruff/compile kontrollerinden geçirmeden ilerletme.

Sınırlı kalan alanlar: JavaScript/SPA execution, login/session yönetimi, form submission,
YAML/remote OpenAPI ref, tam schema validator, kapsam dışı schema route'una aktif izin,
otomatik API/BOLA testi, distributed worker, disk encryption/retention ve AI discovery
yorumu yoktur. OpenAPI parametre/security ilanları veya HTML alan tipleri çalışma anında
doğrulanmış kabul edilmez. Browser DOM/XML parser çalıştırılmaz.

## Doğrulama ve dosyalar

| Kontrol | Gerçek sonuç |
|---|---|
| Değişiklik öncesi standart suite | 365 geçti, 4 opt-in atlandı; 19,39 s |
| Son standart suite | **469 geçti, 0 başarısız, 4 opt-in atlandı; 31,18 s** |
| Önceki 365 standart test | Tamamı başarılı, regresyon yok |
| Yeni Faz 4B testleri | 104 başarılı |
| Gemma 4 gerçek bulgu/tarama/WAF testleri | **3/3 başarılı**, ayrı opt-in koşu; 130,15 s |
| API/faz/benchmark/helper dosyalarında Ruff | Exit 0, temiz |
| Python `compileall -q src tests` | Exit 0, başarılı |
| Alembic head | `0004_phase4b` |
| Depo genelinde Ruff 0.16.10 | **Exit 1, 127 ihlal; tüm depo temiz değil** |

Yeni test dağılımı: parser 40, crawler 21, jobs 10, database 11, API 21, gerçek loopback
lab 1. Mock/sentetik testler harici DNS/HTTP kullanmaz; canlı HTTP testi yalnız dinamik
127.0.0.1 portu ve açık owned lab policy ile çalışır. Crash testi gerçek bir alt süreci
başlatır; canlı process'in OS kilidi varken lease'in korunmasını ve yalnız süreç
sonlandıktan sonra fresh lock acquisition ile kurtarılmasını doğrular. Cross-workspace
FK/API/servis reddi, forged evidence ref atomik reddi, policy revision fence, resource-owner
ilişkileri, prompt injection metninin atılması, summary byte cap, migration koruma/geri
alma ve storage hatasında cleanup bu testlerin içindedir.

Standart suite'te atlananlar mevcut üç gerçek Ollama testi ve bir API/BOLA model testidir;
bu Faz 4B koşusunda üç mevcut Gemma testi ayrıca opt-in açılarak çalıştırıldı. Tek uyarı
önceden var olan Starlette/TestClient httpx deprecation uyarısıdır. Tarihsel **24/24**
Qwen/Gemma karşılaştırması `QWEN_VS_GEMMA.md` ve eski raporlarında korunur; bu fazda 24 testin
tamamı yeniden koşulmuş gibi sunulmaz. Qwen için yeni inference yapılmadı, model silinmedi.

Yeni Gemma koşusu `gemma4:26b`, thinking=false, context=8192, output=4096, timeout=300,
concurrency=1 kullandı. Üretim ayarları/AI varsayılanı değiştirilmeden yalnız test sürecinin
ortamı ayarlandı. Üç senaryoda da JSON/ref validation ve exact reference eşleşmesi başarılı,
Türkçe sinyal kontrolü geçti, ayrı thinking çıktısı 0 karakterdi.

| Gerçek Gemma senaryosu | Provider yanıt süresi | Model yükleme (Ollama) |
|---|---:|---:|
| Bulgu | 58,373 s | 31,424 s |
| Tam tarama | 40,509 s | 0,038 s |
| WAF | 29,150 s | 0,041 s |

Ara geliştirme koşusunda iki yeni test başarısız oldu: offline API'nin `Conflict`
istisnası `ValueError` alt sınıfı olduğu için yanlış 422 dönmesi düzeltildi (409 korunur).
Windows process exit bildiriminden hemen sonra lock acquisition'ın geçici başarısızlığı
testte sınırlandırılmış tekrar acquisition ile ele alındı; worker hâlâ lock almadan fail
closed kalır, elapsed time lease serbest bırakma kanıtı olarak kullanılmaz. Tekrar koşusu
ve son 469 testte başarısız test yoktur. Bir Windows wildcard komut denemesinde test
toplanmadı; gerçek son test sonuçlarına bu deneme dahil edilmez.

Depo genelindeki 127 lint bulgusu eski CLI/engine/yardımcı/test dosyalarındadır; yeni
discovery/API/faz dosyaları hedefli kontrolde temizdir. Önceki raporda 125 tarihsel bulgu
vardı; bugünkü sayı 127 olarak kaydedilir, geçmiş sayı bugünkü lint sonucu yerine
kullanılmaz. Bu görevde eski CLI davranışlarını etkileyebilecek toplu lint rewrite yapılmadı.

Makine kayıtları: `reports/phase4b/validation.json`,
`reports/phase4b/gemma4_regression.json` (yalnız sentetik, doğrulanmış/maskeli çıktı ve
GPU/RAM/provider ölçümleri), `reports/phase4b/full_repo_ruff.json`.

Tekrar doğrulama:

```powershell
.venv\Scripts\python.exe -m pytest -q
.venv\Scripts\python.exe -m ruff check src/crimsonweb/api tests/test_phase*.py tests/*benchmark*.py tests/*comparison*.py tests/*helpers.py
.venv\Scripts\python.exe -m compileall -q src tests
.venv\Scripts\python.exe -m alembic heads
# Yalnız yeni testler için PowerShell wildcard'ını açıkça dosyalara genişlet:
$discoveryTests = @(rg --files tests -g "test_phase4b*.py")
& .venv\Scripts\python.exe -m pytest $discoveryTests -q
```

Eklenen üretim dosyaları:

- `src/crimsonweb/api/discovery/__init__.py`
- `src/crimsonweb/api/discovery/models.py`
- `src/crimsonweb/api/discovery/urls.py`
- `src/crimsonweb/api/discovery/html.py`
- `src/crimsonweb/api/discovery/openapi.py`
- `src/crimsonweb/api/discovery/inventory.py`
- `src/crimsonweb/api/discovery/store.py`
- `src/crimsonweb/api/discovery/worker.py`
- `src/crimsonweb/api/discovery/crawler.py`
- `src/crimsonweb/api/discovery/summary.py`
- `src/crimsonweb/api/discovery/service.py`
- `src/crimsonweb/api/discovery/routes.py`
- `src/crimsonweb/api/migrations/versions/0004_phase4b.py`

Yeni testler: `tests/discovery_helpers.py`, `test_phase4b_parsers.py`,
`test_phase4b_crawler.py`, `test_phase4b_jobs.py`, `test_phase4b_database.py`,
`test_phase4b_api.py`, `test_phase4b_lab.py`; belge: `docs/PHASE4B.md`.

Değişen mevcut dosyalar: `src/crimsonweb/api/database.py`, `api/app.py`,
`api/engine.py`, `api/workspaces/service.py`, `api/workspaces/store.py`,
`tests/test_phase2_database.py` (head beklentisi), `README.md`, `.gitignore`.
Git'te bunlara ek görünen dosyalar önceki çalışma ağacındandır.

Faz 4B bu kapsamla tamamlandı. Faz 4C/4D kodu veya otomatik faz geçişi yoktur.
