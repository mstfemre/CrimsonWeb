# CrimsonWeb — Faz 2

## Kapsam ve mimari

Faz 1'in 87 testi geliştirme öncesinde çalıştırıldı ve tamamı geçti.
CLI ve kullanıcıya ait mevcut değişiklikler korundu. API aynı `src/crimsonweb/api`
paketinde genişletildi; bağımsız bir backend klasörüne taşınmadı.

Katmanlar: `engine.py` ağ/kapsam analizi, `headers.py` Faz 1 gözlemleri,
`web_analysis.py` mevcut CLI HSTS/cookie/CORS yardımcılarının API adaptörü,
`tls.py` doğrulanmış bağlantı verileri, `waf.py` savunma log adaptörleri,
`database.py` SQLAlchemy repository, `routes.py` sorgu/içe aktarma uçları.
Pydantic modelleri `models.py` içindedir. LLM ve dashboard bu fazda eklenmedi.

## Kurulum ve migration

Python 3.12+ ve tek Uvicorn worker kullanın. Windows PowerShell, proje kökü:

```powershell
.venv\Scripts\python.exe -m pip install -e ".[api,dev]"
$env:CRIMSON_DATABASE_URL = 'sqlite:///data/crimsonweb.sqlite'
.venv\Scripts\python.exe -m alembic -c alembic.ini upgrade head
.venv\Scripts\python.exe -m alembic -c alembic.ini current
.venv\Scripts\python.exe -m uvicorn crimsonweb.api.app:app --app-dir src --host 127.0.0.1 --port 8000 --no-proxy-headers
```

Linux/macOS aynı işlemler:

```bash
.venv/bin/python -m pip install -e '.[api,dev]'
export CRIMSON_DATABASE_URL=sqlite:///data/crimsonweb.sqlite
.venv/bin/python -m alembic -c alembic.ini upgrade head
.venv/bin/python -m alembic -c alembic.ini current
.venv/bin/python -m uvicorn crimsonweb.api.app:app --app-dir src --host 127.0.0.1 --port 8000 --no-proxy-headers
```

Varsayılan URL `sqlite:///data/crimsonweb.sqlite`; dizin otomatik oluşturulur.
Göreli yollar çalışma dizinine göredir; servis kurulumunda mutlak SQLite yolu
kullanın. `.env` otomatik yüklenmez. API açılışında da `upgrade head` çalışır;
elle migration komutu değişikliği servis açılmadan inceleme olanağı sağlar.
İlk revision `0001_phase2` olup migration kaynakları paketle birlikte dağıtılır.

Yeni revision oluşturma:

```powershell
.venv\Scripts\python.exe -m alembic -c alembic.ini revision --autogenerate -m "describe_schema_change"
```

Oluşan migration'ı inceleyin. SQLite ve indeksler için `foreign_keys=ON` ve
`busy_timeout=5000` ayarlanır. Çoklu worker/dış görev kuyruğu henüz yoktur:
yeniden başlatma kurtarma mekanizması tek servis süreci varsayar.

## Kalıcı veri ve görev durumları

`targets` hedef URL'lerini, `scans` hedef ilişkisini, zamanları, durumu ve JSON
teknik raporunu; `findings` taramaya bağlı bulguları; `waf_events` HTTP/log olaylarını
tutar. Foreign key ve arama indeksleri migration ile oluşturulur. Tarama ve
çocuk bulgular aynı transaction'da kaydedilir. SQLAlchemy işlemleri worker
thread'lerinde ayrı Session'larla yürütülür; asyncio döngüsü DB beklemez.

Queued, running, completed, failed, blocked ve stopped ayrı durumlardır.
403/429 ve kapsam politikası durdurmaları `blocked`; operatör iptali `stopped`;
ağ/sertifika hatası `failed` olur. Başlangıç, her yanıt ve bitişte kayıt yapılır.
Servis yeniden açıldığında queued/running işler `stopped/process_interrupted`
olur; otomatik tekrar veya devam yapılmaz. Geçmiş silinmez.
Faz 1'deki 100 bellek içi kayıt sınırı kalktı; sorgu sayfa sınırı 100'dür.
Aktif iş sınırı dört, motor genelinde istek aralığı bir saniyedir.

## API

OpenAPI: http://127.0.0.1:8000/docs. Token/loopback erişim politikası ve kapsam
kuralları Faz 1 ile aynıdır; yeni uçlar da aynı yetkilendirmeyi kullanır.

| Uç | İşlev |
|---|---|
| `POST /scans` | Aynı izinli tarama sözleşmesi, 202 |
| `GET /scans` | Eski liste biçimini korur; en yeni 100 rapor |
| `GET /scans/{id}` | Kalıcı rapor ve güncel bulgular |
| `GET /scans/{id}/report` | JSON indirme; aktif işte 409 |
| `POST /scans/{id}/stop` | Aktif görevi iptal eder ve sonucu kalıcı kaydeder |
| `GET /history` | `status`, `target_id`, `engagement_id`, `limit`, `offset` |
| `GET /targets` | Kalıcı hedef listesi, `limit`, `offset` |
| `GET /findings` | `severity`, `scan_id`, `limit`, `offset` |
| `GET /waf/events` | `scan_id`, `event_type`, `rule_id`, `limit`, `offset` |
| `POST /waf/import` | Savunma loglarını doğrular, içe aktarır ve tekrarları ayıklar |

Sayfalı yanıtlar `{items, total, limit, offset}` içerir; limit 1–100,
offset 0–1.000.000. Risk seviyeleri info/low/medium/high/critical'dır.
Geçersiz şema/filtre 422, bilinmeyen tarama 404, job sınırı 429,
veritabanı erişim hatası ayrıntıları ifşa etmeyen 503 döndürür.

Örnek:

```powershell
Invoke-RestMethod 'http://127.0.0.1:8000/history?status=blocked&limit=10&offset=0'
Invoke-RestMethod 'http://127.0.0.1:8000/findings?severity=medium&limit=10'
Invoke-RestMethod 'http://127.0.0.1:8000/waf/events?event_type=rate_limited'
```

## TLS, HTTPS ve web gözlemleri

TLS incelemesi HTTPX'in mevcut doğrulanmış TLS bağlantısındaki SSLObject'ten
sertifika başlangıç/bitişi, kalan gün ve **negotiated** protokolü kaydeder.
Hostname, güven zinciri ve zaman doğrulaması standart SSL doğrulamasıyla yapılır;
IP hedeflerde de kapatılmaz. Hata halinde doğrulama nedeni kaydedilir ve iş biter;
doğrulamayı kapatarak sertifika toplamaya devam edilmez. Başarısız handshake'te
sertifika tarihleri alınamamış olabilir. 30 gün veya daha az kalan doğrulanmış
sertifika için düşük seviyeli yenileme gözlemi üretilir.

Gözlenen TLS 1.2/1.3, sunucunun eski protokolleri desteklemediğinin kanıtı değildir.
`supported_versions_tested=false`: aktif protokol matrisi bu fazda yapılmaz;
eski negotiated protokoller için gözlem üretilir. TLS metadata bulunmayan mock
yanıtında doğrulama iddiası yapılmaz. Engellemeden sonra ek TLS probe yoktur.

HTTP→HTTPS yönlendirmesi `https_redirect` alanında observed/not_observed/incomplete
olarak tutulur; başlangıç HTTPS ise not_applicable. Downgrade engellenir.
HTTPS'e yönlenen HTTP hop'u tek başına hassas veri ifşası olarak sunulmaz.
HSTS max-age, sıfır/tekrar/geçersiz değerler değerlendirilir. includeSubDomains
zorunlu sayılmaz; alt alan kapsamına göre karar verilmelidir.

Cookie kontrolleri çoklu Set-Cookie başlıklarında çalışır. HttpOnly, SameSite,
HTTPS'te Secure, SameSite=None/Secure tutarlılığı incelenir. Cookie adı ve
değeri saklanmaz; sıra numarası ve eksik/geçersiz nitelikler kanıttır.
Cookie amacı bilinmediği için eksik HttpOnly doğrulanmış açık sayılmaz.

Her GET'te kontrollü `Origin: https://crimsonweb.invalid` gönderilir; ek CORS
flood/probe yoktur. Mevcut CORS helper adayları sınıflandırır, API adaptörü riski
bağlama göre düşürür. Public wildcard düşük riskli bilgi gözlemidir; wildcard
ile credentials birleşimi tarayıcıların reddettiği yanlış yapılandırma olarak
sunulur. Kontrollü origin/null izinleri ve Vary: Origin gözlemleri bağlamla
raporlanır. Response body okunmadığından veri hassasiyeti/açıklık doğrulanmaz.
[MDN CORS davranışı](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Origin)
ve [OWASP Secure Headers](https://owasp.org/www-project-secure-headers/) referanstır.

## WAF / IDS olayları ve log içe aktarma

HTTP 403 = access_denied; HTTP 429 = rate_limited. Retry-After saniye veya
timezone içeren HTTP tarihi olarak yorumlanır; geçmiş tarihler sıfır, geçersiz
değerler `retry_after_valid=false` olur. Bu sadece kayıttır: yeniden deneme yapılmaz.
403/429 tek başına WAF ya da IP engeli kanıtı değildir.

`normalized_json` ve `modsecurity_json` adaptörleri JSON nesne, dizi veya NDJSON
kabul eder. Her içe aktarmada en fazla 1000 olay, content en fazla 1.048.576 karakterdir.
Kayıtların tümü doğrulanmadan DB'ye yazılmaz; tekrarlar deterministik kimlikle
ayıklanır. Aynı olayın assessment alanını değiştirmek için tekrar import yapılmaz.
Ham log, HTTP başlıkları, rule matched-data ve payload saklanmaz. Kural kimliği,
request kimliği, UTC zaman, olay türü ve HTTP durum ilişkisi saklanır.
`scan_id` ilişkilendirmesi operatör tarafından verilir; yakın zamanlara bakarak
otomatik eşleşme yapılmaz. `scan_id` yoksa olay ilişkisiz kayıt olarak saklanır.

Normalize edilmiş kayıt:

```json
{"timestamp":"2026-10-08T09:00:00+03:00","event_type":"waf_block","rule_id":"949110","request_id":"lab-001","status_code":403}
```

event_type access_denied/rate_limited/rule_match/waf_block/ip_block olabilir.
Normalize timestamp timezone içermelidir. ModSecurity JSON için
transaction.timestamp/time_stamp, unique_id, response.http_code ve
messages[].details.ruleId desteklenir. Yaygın zonesuz time_stamp biçiminde
`timezone_offset_minutes` **açıkça** verilmelidir (İstanbul için 180).
403 ile kural eşleşmesi yalnız `rule_match` olarak kaydedilir; açık
`transaction.intervention.disruptive=true` varsa `waf_block` olur.
Klasik düz metin/audit v2 formatları bu adaptörde desteklenmez; JSON dışa aktarın.

PowerShell import örneği:

```powershell
$payload = @{format='modsecurity_json'; content=(Get-Content tests/fixtures/modsecurity_lab.json -Raw); expected_benign=$true} | ConvertTo-Json
Invoke-RestMethod 'http://127.0.0.1:8000/waf/import' -Method Post -ContentType 'application/json' -Body $payload
```

Fixture açıkça sentetik laboratuvar kaydıdır. Gerçek taramayla eşleştirmek için
payload'a o taramanın `scan_id` değerini ekleyin. Aktif taramaya bağlı açık
waf_block/ip_block log kaydı gelirse iş iptal edilir ve defense_log_block
nedeniyle blocked kaydedilir. İçe aktarma hiçbir görevi başlatmaz/yeniden başlatmaz.
`expected_benign=true` yalnız operatörün benign test beyanıdır; sonuç
candidate_false_positive olur, kesin yanlış pozitif hükmü verilmez.
Ground truth yoksa undetermined kalır; kural bağlamı ve analist incelemesi gerekir.

## Eklenen dosyalar

- `src/crimsonweb/api/database.py`, `routes.py`, `tls.py`, `web_analysis.py`, `waf.py`
- `alembic.ini`
- `src/crimsonweb/api/migrations/__init__.py`, `env.py`, `script.py.mako`
- `src/crimsonweb/api/migrations/versions/__init__.py`, `0001_phase2.py`
- `tests/conftest.py`
- `tests/test_phase2_database.py`, `test_phase2_web.py`, `test_phase2_waf.py`
- `tests/test_phase2_tls.py`, `test_phase2_api.py`
- `tests/fixtures/modsecurity_lab.json`
- `docs/PHASE2.md`

Güncellenenler: API app/models/engine, pyproject.toml, README.md, .env.example,
.gitignore. Önceki 87 testin dosyaları değiştirilmedi; conftest her teste ayrı SQLite
dosyası vererek kullanıcı veritabanına yazılmasını önler.

## Kalite kontrolleri

```powershell
.venv\Scripts\python.exe -m pytest -q
.venv\Scripts\python.exe -m ruff check src/crimsonweb/api tests/test_phase1_api.py tests/test_phase1_integration.py tests/test_phase2_*.py tests/conftest.py
.venv\Scripts\python.exe -m compileall -q src/crimsonweb/api
```

SQLite restart/ilişki/transaction, upgrade/downgrade ve metadata tutarlılığı,
yerel TLS güven/geçerlilik/hostname, cookie/HSTS/CORS, Retry-After, JSON/NDJSON
loglar, import tekrarları, API filtre/sayfalama/erişim/iptal testleri eklendi.
Dış hedefler taranmaz. Windows loopback testleri izinli sandbox dışı çalıştırılır.

8 Ekim 2026 doğrulaması: **137 test geçti** (önceki 87 + 50 yeni test),
API ve Faz 1/2 testlerinde **Ruff geçti**, `src` ve `tests` Python derleme
kontrolü geçti. Editable kurulum ve wheel oluşturma başarılı; migration
revision ve şablonu dağıtım paketinde bulunur. Gerçek proje veritabanında
`upgrade head`, `current` (0001_phase2) ve `check` (schema farkı yok) doğrulandı.
CLI `--help` çalıştı. Starlette TestClient/HTTPX adaptörüne ilişkin önceki
tek deprecation uyarısı devam ediyor; test başarısızlığı yok.

## Faz 3 hazırlıkları

Kalıcı tarama UUID'leri, bulgu kanıtları ve ayrı WAF olay kaynağı artık LLM
değerlendirmesine temel olabilir. `ai_analysis` hâlâ null'dır; teknik rapor
AI yorumuyla değiştirilmez. Faz 3'te sağlayıcı arayüzü ve ayrı AI analiz tablosu için
yeni Alembic revision, bulgu kimliğine dayalı referanslar ve güvenilmeyen
header/log metinleri için prompt injection sınırları eklenmelidir.
