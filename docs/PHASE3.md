# CrimsonWeb — Faz 3: AI Security Intelligence Engine

Faz 3.5 güncellemesi: kimliğe bağlı sağlayıcı şeması, Türkçe sistem talimatı ve
gerçek gemma3:4b doğrulaması [PHASE3.5.md](PHASE3.5.md) içinde açıklanır.
Aşağıdaki Faz 3 test sonuçları ilk teslimin tarihsel kaydıdır.

## Mimari ve kapsam

README, Faz 1/2 dokümanları, API/veritabanı ve JSON rapor yapısı incelendi.
Geliştirme öncesinde önceki 137 test geçti. CLI, tarama motoru, TLS/WAF akışları
korundu. Plan: sağlayıcı sınırı → maskelenmiş kanıt paketi → doğrulanmış AI
yorumları → ayrı migration/kalıcılık → API/JSON → regresyon testleri.

`src/crimsonweb/api/ai` altında:

- `models.py`: istek, yorum, kanıt referansı, kullanım ve analiz kayıt şemaları.
- `provider.py`: LLMProvider Protocol, OllamaProvider, yapılandırma ve ortak çağrı sınırı.
- `security.py`: veri minimizasyonu, prompt, referans/çıktı doğrulama ve bağımsız öncelik sırası.
- `service.py`: asenkron AI işleri, hata/iptal yönetimi ve rapor annotation'ı.
- `routes.py`: mevcut yetkilendirmeyi kullanan `/ai` API'si.

İlk sağlayıcı Ollama'dır. Yeni sağlayıcı yalnız `name`, `model`, `health()` ve
`generate(system, evidence, schema)` sözleşmesini uygulamalıdır. OpenAI veya
başka API entegrasyonu henüz yoktur; API anahtarı gerekmiyor. AI servisi tarama
motorunu, ağ araçlarını veya kapsam değiştirme fonksiyonlarını almaz.

## Kurulum ve migration

Faz 2'nin `[api,dev]` bağımlılıkları yeterlidir; yeni runtime bağımlılığı eklenmedi.
Tek Uvicorn worker kullanın. PowerShell, proje kökünde:

```powershell
.venv\Scripts\python.exe -m pip install -e ".[api,dev]"
.venv\Scripts\python.exe -m alembic -c alembic.ini upgrade head
.venv\Scripts\python.exe -m alembic -c alembic.ini current
.venv\Scripts\python.exe -m alembic -c alembic.ini check
```

Head `0002_phase3`, parent `0001_phase2`. Yeni `ai_analyses` tablosu taramaya
nullable foreign key, durum/tür/zaman indeksleri ve şema doğrulanmış JSON kayıt
taşır. Teknik tablolar değiştirilmez. Bulgu ve WAF kimlikleri kayıt içinde
referans olarak tutulur; model bu tabloları yazamaz.

API açılışı migration'ı uygular. Yarım kalmış AI işleri restart'ta
`stopped/process_interrupted` olur; tekrar LLM çağrısı yapılmaz. Oluşturulma,
başlangıç/bitiş zamanı, servis süresi, sağlayıcı/model, kanıt kimlikleri,
maskelenmiş girdi hash'i, güvenlik notları ve destekleniyorsa token kullanım
bilgileri saklanır. Ham prompt, ham sağlayıcı yanıtı ve API anahtarı saklanmaz.

## Yerel Ollama yapılandırması

AI varsayılan olarak kapalıdır. Hazır yerel Ollama kurulumunda `ollama list`
ile yüklü modelin **tam etiketini** seçin; CrimsonWeb model indirmez veya cloud'a
geçmez. Structured output destekli bir yerel model gerekir. Ollama sunucusunda
cloud özelliklerini kapatın:

```powershell
# Ollama'yı bu ortamdan başlatın; çalışan eski süreç bu değeri sonradan almaz.
$env:OLLAMA_NO_CLOUD = '1'
ollama serve
```

Bu davranış [Ollama'nın yerel kullanım ayarı](https://docs.ollama.com/faq#how-do-i-disable-ollama-cloud-features)
ile belgelenmiştir. Windows masaüstü Ollama kullanıyorsanız ayarı o sürecin
ortamına uygulayıp Ollama'yı yeniden başlatın. CrimsonWeb başka bir sürecin cloud
ayarını doğrulayamaz; yerel daemon'ın yönetimi operatöre aittir.

CrimsonWeb API için başka terminalde (model değerini kendi yüklü etiketinizle değiştirin):

```powershell
$env:CRIMSON_AI_ENABLED = 'true'
$env:CRIMSON_OLLAMA_URL = 'http://127.0.0.1:11434'
$env:CRIMSON_OLLAMA_MODEL = 'your-local-model:tag'
$env:CRIMSON_AI_TIMEOUT = '90'
.venv\Scripts\python.exe -m uvicorn crimsonweb.api.app:app --app-dir src --host 127.0.0.1 --port 8000 --no-proxy-headers
```

Yalnız localhost/127.0.0.1/::1 origin'leri kabul edilir. Her çağrıda DNS kapsamı
doğrulanır, bağlantı loopback IP'ye sabitlenir; Host/SNI korunur. URL credentials,
query, fragment ve path kabul edilmez. Redirect/proxy ortamı kullanılmaz.
Cloud adlı modeller reddedilir. Sağlayıcıya yalnız `/api/tags` ve `/api/chat`
çağrıları yapılır; araç, key header'ı, web araması, model pull veya retry yoktur.
HTTPX TLS doğrulaması açıktır. API'den model/provider URL override edilemez.

Ollama bağlantısı/model hatalıysa yalnız AI işi başarısız olur; tarama devam eder.
Geçersiz AI env ayarı da API başlangıcını bozmaz; AI status invalid_configuration
döndürür. `.env` otomatik okunmaz.

## Limitler ve sağlayıcı yanıtı

| Ayar | Varsayılan |
|---|---|
| CRIMSON_AI_MAX_CONCURRENCY | 2 aktif AI işi/sağlayıcı çağrısı |
| CRIMSON_AI_CALLS_PER_MINUTE | 20 çağrı, kayan 60 saniye; health dahil |
| CRIMSON_AI_TIMEOUT | 90 saniye, tek çağrının toplam süresi |
| CRIMSON_AI_MAX_INPUT_BYTES | 32768 UTF-8 byte |
| CRIMSON_AI_MAX_OUTPUT_TOKENS | 4096 (`num_predict`) |
| CRIMSON_AI_CONTEXT_TOKENS | 16384 (`num_ctx`) |

HTTP yanıtı en fazla 262144 byte, seçilen bulgu/olay türü başına en fazla 100 kayıt.
4000 karakteri aşan tek dış metin alanı açık bir güvenlik notuyla çıkarılır;
toplam input sınırı aşılırsa analiz reddedilir. Daha küçük kimlik seçimi kullanın.
Byte sınırı token sayısı garantisi değildir; model bağlam kapasitesi ve donanım
uyumunu ayarlayın. Kesilmiş/tamamlanmamış yanıt başarı olarak kaydedilmez.

Tek POST `/api/chat`, `stream=false`, JSON schema ve temperature=0 kullanılır.
[Ollama chat](https://docs.ollama.com/api/chat) ve
[structured outputs](https://docs.ollama.com/capabilities/structured-outputs)
sözleşmelerine göre yanıt doğrulanır. Prompt/eval token sayıları ve model süresi
yalnız sağlayıcı verirse kaydedilir; verilmeyen değerler null kalır. Otomatik
yeniden deneme/repair yoktur. Tek worker sınırı Faz 2 ile devam eder; çağrı sayacı
süreç içidir ve restart'ta sıfırlanır.

## Analiz ve API kullanımı

OpenAPI: http://127.0.0.1:8000/docs. Bütün AI uçları mevcut loopback/Bearer
token yetkilendirmesini kullanır. İstek yalnız veritabanındaki kimlikleri alır;
URL, serbest prompt, önem derecesi ve model adı istekte kabul edilmez.

| Uç | İşlev |
|---|---|
| GET /ai/providers | Yapılandırılmış sağlayıcı, bağlantı çağrısı yapmaz |
| GET /ai/status | Bağlantı, yüklü model listesi ve seçilen modelin bulunması |
| POST /ai/analyses | scan/findings/waf analizi; 202 ve analiz kimliği |
| GET /ai/analyses/{id} | İş durumu ve doğrulanmış JSON AI yorumu |
| GET /ai/analyses | scan_id/status/kind/limit/offset ile kalıcı geçmiş |
| GET /scans/{id}/report?include_ai=true | En son tamamlanan scan AI annotation'ı |

Kullanım örneği, mevcut bir tarama kimliği ile:

```powershell
Invoke-RestMethod 'http://127.0.0.1:8000/ai/status'
$request = @{kind='scan'; scan_id=$scan.id; language='tr'} | ConvertTo-Json
$analysis = Invoke-RestMethod 'http://127.0.0.1:8000/ai/analyses' -Method Post -ContentType 'application/json' -Body $request
Invoke-RestMethod "http://127.0.0.1:8000/ai/analyses/$($analysis.id)"
# AI status completed olduktan sonra:
Invoke-WebRequest "http://127.0.0.1:8000/scans/$($scan.id)/report?include_ai=true" -OutFile 'reports/with-ai.json'
```

Bulgu seçimi: `{kind:'findings', finding_ids:[bulgu-UUID], language:'en'}`.
Bir analizin bulguları aynı taramaya ait olmalıdır. WAF seçimi:
`{kind:'waf', waf_event_ids:[olay-UUID], language:'tr'}`. İsteğe bağlı scan_id
verilirse tüm seçilen kimlikler ona ait olmalıdır. WAF analizi ilişkisiz veya
farklı taramalara ait kalıcı olayları da yorumlayabilir; bu durumda tek scan
ilişkisi/scan rapor overlay'i olmayabilir. Scan analizi tüm mevcut bulgu ve
olayları alır; aktif taramalar için 409 döner. Limit aşımında seçili kimlikleri azaltın.

TR ve EN ayrı isteklerdir; language etiketi ve çıktı alanı doğrulanır, istemci
iki dil için iki analiz başlatabilir. Modelin dil/yorum kalitesi insan incelemesi
gerektirir. Bilinmeyen kanıt 404, geçersiz şema/limit 422, aktif iş kapasitesi
429, AI kapalı/yapılandırma hatalıysa 503. Sağlayıcı hataları asenkron işte
failed/error_code olarak görünür. Health hatası status içinde güvenli kod taşır.
Kayan çağrı bütçesi worker'da dolmuşsa iş provider_capacity ile başarısız olur.

## Teknik bulgu ve AI yorumu ayrımı

Model yalnız maskelenmiş, izinli kimliklerden oluşturulan kanıt paketini alır.
Ham hedef URL'si, IP, cookie, request_id, issuer ve tüm HTTP response header'ları
gönderilmez. Bulgu metni, tür, teknik severity; WAF olay türü/kural/zaman ve
Retry-After; status ve doğrulanmış TLS metadata gönderilir. Teknik kayıtlardaki
metinler **untrusted** olarak işlenir. Teknik doğrulama derecesi yükseltilmez.

AI JSON: yönetici özeti, teknik bulgu yorumları, risk açıklaması, TLS bölümü,
WAF yorumları, düzeltme önerileri, ilişkiler, kanıt referansları ve sınırlamalar.
Yorumlarda confidence (nitel), uncertainty, impact, false-positive görüşü,
OWASP mapping önerisi ve remediation bulunur. Bunlar model görüşüdür;
OWASP mapping doğrulanmış standart kontrol eşleşmesi değildir.

Her bulgu/WAF yorumu seçilen gerçek kimlikle eşleşmeli ve kendi kimliğini
evidence_refs içinde taşımalıdır. Eksik/tekrar/uydurma referans reddedilir.
TLS referansları yalnız gönderilen TLS gözlemlerinden seçilir. Model yeni bulgu,
test veya önem derecesi kaydedemez. Öncelik listesi sunucuda teknik severity
(critical → high → medium → low → info) ve eşitlikte kimlik sırasıyla hesaplanır;
sayısal CVSS üretilmez. Model priority_improvements sırası yalnız öneridir.
`interpretation_only=true`, `model_claims_verified=false` zorunludur.

Normal JSON raporu ve GET scan sonucu eskisi gibi `ai_analysis:null` kalır.
include_ai=true, tamamlanmış scan analizi varsa yalnız bu alanı ekler; teknik
bulguları değiştirmez. Modele verilen maskelenmiş kanıt paketi sonradan değişmişse
`stale=true` olur; yeniden AI çağrısı yapılmaz. Analiz geçmişi kendi snapshot
hash'ini taşır; ham teknik tablonun her alanı bu hash'e dahil değildir.

## Prompt injection ve veri güvenliği

Sistem prompt'u sabittir, dış metinler yalnız ayrı JSON user mesajında yer alır.
Instruction-like örüntüler, rol belirteçleri ve görünmez Unicode kontrolleri
işlenir; şüpheli alan çıkarılarak safety_notes'a yazılır. Credential alanları,
Bearer/JWT/key örüntüleri, private key blokları, URL/email/IPv4 bilgileri maskelenir.
Mevcut privacy helper yeniden kullanılır. Maskelenmiş girdi bile ham prompt olarak
DB/loglara yazılmaz. Model çıktısı da maskelemeden geçer; yalnız şeması/referansları
geçerli sonuç kaydedilir. Hatalı ham cevap ve sağlayıcı hata metni kaydedilmez.

Şema extra alanları reddeder; CVE kimliği, CVSS, belirli doğrulanmış açık/test
iddiaları ve instruction-like model çıktıları engellenir. Bu kontroller semantik
doğruluk veya tüm injection/secret biçimleri için matematiksel garanti değildir.
Serbest açıklama hâlâ doğrulanmamış AI görüşüdür; bilinmeyen hassas veri biçimleri
ve dolaylı iddialar için insan incelemesi gerekir. Modelin araç/ağ/tarama yazma
yetkisi bulunmaması, yorumun hedef kapsamına etkisini mimari olarak sınırlar.

## Dosyalar ve testler

Eklenenler:

- `src/crimsonweb/api/ai/__init__.py`, `models.py`, `provider.py`, `security.py`, `service.py`, `routes.py`
- `src/crimsonweb/api/migrations/versions/0002_phase3.py`
- `tests/ai_helpers.py`
- `tests/test_phase3_provider.py`, `test_phase3_security.py`, `test_phase3_service.py`, `test_phase3_api.py`
- `tests/test_phase3_ollama_integration.py`
- `docs/PHASE3.md`

API app/models/database, README, .env.example ve pytest marker ayarı güncellendi.
Faz 2 migration testinin yalnız head beklentisi 0001_phase2 → 0002_phase3 olarak
güncellendi; testin downgrade/upgrade ve metadata kontrolleri korundu.

```powershell
.venv\Scripts\python.exe -m pytest -q
.venv\Scripts\python.exe -m ruff check src/crimsonweb/api tests/test_phase1_api.py tests/test_phase1_integration.py tests/test_phase2_*.py tests/test_phase3_*.py tests/ai_helpers.py tests/conftest.py
.venv\Scripts\python.exe -m compileall -q src tests
```

Varsayılan testler mock LLM/HTTPX kullanır; ücretli anahtar ve gerçek Ollama
gerekmez. Gerçek sunucu ile **isteğe bağlı** test:

```powershell
$env:CRIMSON_TEST_OLLAMA = '1'
$env:CRIMSON_AI_ENABLED = 'true'
$env:CRIMSON_OLLAMA_MODEL = 'your-local-model:tag'
.venv\Scripts\python.exe -m pytest -m ollama -q
```

Bu test gerçek model bağlantısı, schema üretimi ve kanıt eşleşmesini doğrular;
başarısı seçilen modelin bu çıktı sözleşmesini karşılamasına bağlıdır. Gerçek
Ollama testi bu geliştirmede çalıştırılmadı; varsayılan testte skip olarak raporlanır.

8 Ekim 2026 son doğrulama: **200 test geçti** (önceki 137 + 63 yeni),
**1 opt-in Ollama testi atlandı**. API ve ilgili Faz 1/2/3 testlerinde Ruff,
src/tests Python derleme kontrolü, Alembic upgrade/current/check başarılı.
Head 0002_phase3, ORM/schema farkı yok. Wheel oluşturuldu; AI modülleri ve yeni
migration pakette doğrulandı. CLI `--version` çalıştı. Önceki tek Starlette
TestClient/HTTPX deprecation uyarısı devam ediyor.

Bu bilgisayarda Ollama uygulaması bulundu; ancak 127.0.0.1:11434 model listesi
kontrolü bağlantı reddi aldı. Sunucu çalışmadığı için gerçek model üretimi
test edilmedi. Gerçek çıktı kalitesi için yukarıdaki opt-in testi sunucu/model
hazır olduktan sonra çalıştırın. Mock LLM sonuçları gerçek tarama sonucu olarak
ürüne eklenmedi; yalnız sentetik test kayıtlarında kullanıldı.

## Sonraki aşama

Faz 4 başlamadı. İleride dashboard mevcut ayrı teknik/AI API'lerini tüketebilir.
Yeni provider implementasyonu, insan değerlendirme veri seti ve dil/model kalite
ölçümleri bu sözleşme üzerinde eklenebilir. Teknik severity ve izin kapsamı AI
tarafından değiştirilemez.
