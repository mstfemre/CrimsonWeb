# CrimsonWeb — Operatör kontrollü web test kataloğu ve Top 10 raporu

12 Ekim 2026. Bu teslim Faz 4C/4C.1 altyapısını genişletir: model mevcut test
araçlarını seçer, deterministik yürütücü yetki/bütçe denetimiyle çalıştırır ve
minimize edilmiş sonuçlardan takip planı önerilebilir. Varsayılan katalog hâlâ
yalnız BOLA'dır; diğer test aileleri açıkça seçilmelidir.

## Katalog

| Kimlik | Davranış | Kanıt sınırı |
|---|---|---|
| `bola_cross_owner_read` | İki test hesabıyla sahiplik kontrolü; üç GET | Önceden tanımlı alan ve doğru private-record beklentisi koşuluyla BOLA gözlemi. |
| `xss_reflection_probe` | Normal marker ve inert HTML elementi ile iki GET | HTMLParser bağlam sinyali; JavaScript çalıştırılmaz, XSS doğrulanmış sayılmaz. |
| `sql_error_probe` | Baseline, inert geçersiz değer ve quote ile üç GET | Quote'a özgü SQL hata sinyali; veri erişimi/injection doğrulanmış sayılmaz. |
| `web_security_observation` | Tek GET ile mevcut header/cookie/CORS/TLS analizini kullanır | Yapılandırma gözlemleri; uygulamanın bütün güvenliğini kanıtlamaz. |

Hiçbir araç shell, model-authored payload, veri çıkarma, zaman gecikmesi, yazma,
hesap değişikliği, WAF bypass veya proxy/IP değişimi uygulamaz. GET'in gerçek
uygulamada yan etkisiz olduğu varsayılmamalı; operatör yalnız read-only olduğunu
bildiği endpoint'leri onaylamalıdır. İzinli endpoint'e yapılan probe, sınırlı testtir;
otomatik exploit geliştirme veya genel otonom saldırı motoru değildir.

XSS probe'unun marker'ı her testte rastgele üretilir ve yalnız bellekte kullanılır.
Escaped HTML, yorum, script/style ve text-only bağlamları aday sinyali üretmez.
Yanıtın ana MIME türü `text/html` olmalıdır. DOM/stored XSS ve browser execution
bu teslimde ölçülmez. Gerçek DOM parser davranışı ile Python HTMLParser bütün
durumlarda eşdeğer değildir; sonuç **candidate / unverified** olarak tutulur.

SQL hata sinyali baseline ve inert kontrol yanıtında bulunmayıp quote yanıtında
bulunmalıdır. Aynı hatayı bütün cevaplarda veren uygulama aday bulgu üretmez.
Hata göstergeleri sınırlı imzalardır; aday sinyal bağımsız DB doğrulaması değildir.

Yanıtlar en çok 65,536 byte incelenir. Yeni probe'lar identity dışındaki content
encoding'i body/decompression öncesinde reddeder. Bu konservatif sınırlama bazı
gerçek sitelerde testi inconclusive/failed yapabilir. Ham body, header, cookie,
marker/payload değerleri ve SQL hata mesajları DB'ye veya model girdisine yazılmaz.
Yalnız fixed kodlar, statuslar, ilişki kimlikleri ve kısa sinyaller saklanır.

## Merkezi kapsam ve onay

`AuthorizationRequest.query_parameters`, URL'den ayrı bounded bir yapıdır:
en çok 8 isim/değer, her değer en çok 256 ASCII karakter; control karakterleri
ve bilinen secret alan adları reddedilir. Policy `TargetScope.allowed_query_parameters`
ile adları açıkça izinlemelidir; boş liste query testlerini reddeder. Query verisi
transportta encode edilir; URL/path/host/DNS/IP yetki kontrolü atlanmaz.

Scope URL'lerine keyfi query ekleme hâlâ reddedilir. Query taşıyan transport yolu
merkezi admission'dan geçen yapılandırılmış request içindir. Mevcut yöntem, yol,
category, CIDR, SSRF, süre, bütçe, concurrency ve DNS pinning kontrolleri korunur.
403/429/redirect bütün planı durdurur; durdurulmuş policy takip planı başlatamaz.

Yeni query probe'ları için mevcut geçerli politikanıza `allowed_query_parameters`
ve ilgili kategorileri ekleyin. Örneğin `/search` için `q`, kategoriler için
`xss` ve `sqli`; normal gözlem için `web_observation`. Bu yalnız örnek eklemedir:
domain/CIDR/path/port/method/izin kaynağı/expiry/bütçe gereklilikleri ayrıca geçerlidir.
Politikanın kapsamı model tarafından değiştirilemez.

Plan oluştururken `catalog_ids` açıkça seçilir; en çok 4 bilinen katalog kimliği.
`max_tests` 1–50 arasındadır. Model schema'sı katalog, endpoint, kanıt ve query adı
enumlarını bağlar; fabricated/yanlış endpoint'in parametresi/referansı, extra payload
alanları veya izin verilmemiş katalog reddedilir. Yalnız GET ve sensitive-operation
olarak işaretlenmemiş, çözümlenebilir route'lar seçilebilir.

Onay `read_only_operations=true` sözleşmesini kullanır. `private_records_only`
BOLA içeren planlarda zorunlu olarak true olmalıdır; salt query/configuration
probe'ları için private-record iddiası gerekli değildir. Kimliksiz execution
`identities=[]` ile mümkündür; BOLA çalıştırırken iki kimlik hâlâ zorunludur.
Kimlik bilgisi verildiğinde mevcut HTTPS ve dar private-lab istisnası korunur.

## LLM geri bildirim döngüsü

`POST /api/v1/workspaces/{workspace_id}/verification/plans/{plan_id}/next`,
tamamlanmış planın minimize edilmiş sonuçlarını ve kalan bilinen bağlamaları
planlayıcıya verir. Girdi catalog ID, endpoint ref, outcome ve confidence içerir;
raw response, credential, kişisel veri veya modelin keyfi teknik metni içermez.

Kalan testler parent/ancestor planlardan deterministik çıkarılır. Bir parent'ın
en çok bir child'ı olabilir; en çok **3 tur**. Workspace, katalog ve origin
provenance korunur. Her yeni plan `awaiting_approval` durumunda oluşur ve ayrıca
onaylanmalıdır. `max_tests=1` ile adım adım araştırma yapılabilir. Operator fallback
varsa `planner=operator` ve limitation görünür; bu, model başarısı diye raporlanmaz.
AI concurrency ve timeout, existing `AIService.gate` ile ortaktır.

`GET /api/v1/workspaces/{workspace_id}/verification/catalog`, mevcut katalog ve
Top 10 kategori adlarını gösterir. API bearer ve workspace kontrolleri uygulanır.
Yeni alanlar mevcut JSON row modellerinde saklanır; yeni migration eklenmedi.

## OWASP Top 10:2025 kapsamı

Kategori isimleri [resmî OWASP Top 10:2025](https://top10.owasp.org/2025/)
listesini kullanır. Bu bir awareness sınıflandırmasıdır, on bağımsız exploit değildir.
Her raporda on satır bulunur; `partially_assessed` yalnız yapılan dar gözlemi,
`not_tested` ise kanıt eksikliğini anlatır. Hiçbir satır tüm kategoriyi geçti sayılmaz.

| Kategori | Bu teslimdeki gözlem | Gereken ek kanıt |
|---|---|---|
| A01 Broken Access Control | BOLA | Diğer roller, paylaşım ve iş mantığı yetkileri. |
| A02 Security Misconfiguration | Header/cookie/CORS gözlemleri | Deployment ve uygulama yapılandırması. |
| A03 Software Supply Chain Failures | `not_tested` | SBOM, dependency/build/provenance kayıtları. |
| A04 Cryptographic Failures | Gerçek TLS metadata'sı varsa dar gözlem | Depolama kriptografisi ve tüm protokol/cipher kapsamı. |
| A05 Injection | Inert HTML ve SQL hata aday sinyalleri | Bağımsız doğrulama, DOM/stored ve diğer injection aileleri. |
| A06 Insecure Design | `not_tested` | Threat model ve iş akışı beklentileri. |
| A07 Authentication Failures | Cookie gözlenirse sınırlı attribute gözlemi | Login, reset, MFA ve session yaşam döngüsü. |
| A08 Software or Data Integrity Failures | `not_tested` | Trusted integrity/provenance ve işleme akışı kayıtları. |
| A09 Security Logging and Alerting Failures | `not_tested` | Kontrollü olaylarla uygulama log/alert karşılaştırması. |
| A10 Mishandling of Exceptional Conditions | SQL hata karşılaştırmasının dar kapsamı | Diğer exception/resource/fail-open davranışları. |

`no_signal_observed`, güvenli uygulama veya exhaustive negatif sonuç değildir.
Candidate findings `confidence=unverified`; yalnız mevcut BOLA ölçütü conditional
`confirmed` üretebilir. Model ifadeleri verified teknik sonuç yerine geçmez.

`web plan --require-model` / API `require_model=true`, model hatasında operator
fallback planı oluşturmayı reddeder; bu şart sonraki turlarda korunur. Gemma ana
analist ve Qwen alternatif profilleri ile yeni gerçek kontroller
[Gemma kurulum raporunda](GEMMA_WEB_SETUP.md) yer alır.

## CLI kullanımı

Workspace, geçerli scope policy ve authenticated local API önceden hazırlanmalıdır.
Yeni örnek spec yalnız synthetic metadata'dır; bir hedef sunucu oluşturmaz.

```powershell
.venv\Scripts\python.exe -m crimsonweb web plan --workspace <ws> --policy <policy> --openapi docs/examples/web_query_lab_openapi.json --top10 --max-tests 1
.venv\Scripts\python.exe -m crimsonweb web approve --workspace <ws> --plan <plan> --base-url https://your-authorized-host --binding-field owner_id --approved-by operator --scope-source "authorization reference"
.venv\Scripts\python.exe -m crimsonweb web execute --workspace <ws> --plan <plan> --base-url https://your-authorized-host --binding-field owner_id --anonymous
.venv\Scripts\python.exe -m crimsonweb web report --workspace <ws> --plan <plan>
.venv\Scripts\python.exe -m crimsonweb web next --workspace <ws> --plan <plan>
```

Yeni child planı ayrıca approve/execute edin. BOLA varsa `--anonymous` kullanılamaz;
onayda `--private-records-only` ve hidden promptlarla test kimlikleri gerekir.
Shared API sözleşmesindeki binding field, BOLA için kullanılır; diğer probe'lar
aynı approval origin/field bağlamına uyar fakat body alan karşılaştırması yapmaz.

Yalnız bir test ailesi için `--catalog sql_error_probe` veya
`--catalog xss_reflection_probe`; birden fazla `--catalog` kullanılabilir.
`--top10` yalnız uygulanmış araçları seçer, bütün on kategoriyi aktif test etmiş sayılmaz.

## Yerel model

Üretim varsayılanı veya `.env` değiştirilmedi. Ana analist için mevcut local benchmark
Gemma `gemma4:26b` lehine; RAM baş boşluğu/soğuk başlatma önceliğinde `qwen3.5:9b`
alternatif. [Geçmiş karşılaştırma](QWEN_VS_GEMMA.md) küçük sentetik veri kümesine
aittir. Yeni schema'nın gerçek model başarısı o rapordan çıkarılamaz. Qwen ile
yeni katalog ve üç onaylı tur daha sonra gerçekten doğrulandı;
[yerel LLM akış raporu](LOCAL_LLM_WEB_FLOW.md). Gemma bu yeni akışta denenmedi.

Test edilmiş optimize profil: thinking false, context 8192, output 4096,
timeout 300 ve concurrency 1. İki büyük model aynı anda yüklenmemelidir.

## Kalite ve teslim sınırları

Son kontrol, 12 Ekim 2026:

| Kontrol | Sonuç |
|---|---|
| Standart suite | **838 passed, 0 failed**, 8 Ollama testi deselected; son kontrol 76,09 saniye. |
| Önceki regresyonlar | Önceki 816 standart test dahil; profil/strict planlama için 22 yeni test başarılı. |
| Gerçek Ollama kontrolleri | Gemma ile son kodda **4 planlama + 3 analiz testi başarılı**; Qwen ile strict planlamada 4 test başarılı. İlk Qwen çalışmasında da 7 test geçti. Ayrıntılar `GEMMA_WEB_SETUP.md` ve `LOCAL_LLM_WEB_FLOW.md`. |
| Değiştirilen/yeni katalog, API, CLI ve test dosyalarında Ruff | Başarılı. |
| Bütün repoda Ruff | Başarısız: 123 mevcut finding; `reports/web_top10/ruff_summary.json`. |
| Python compileall | `src` ve `tests` başarılı. |
| Git diff whitespace kontrolü | Başarılı; Windows LF/CRLF uyarıları var. |

Pytest ayrıca Starlette/httpx TestClient için bir deprecation uyarısı verdi.
Standart suite JUnit kanıtı `reports/web_top10/standard_tests.xml` içindedir.
AI generation ve kanıt doğrulama algoritmaları değişmedi; profil seçimi opt-in,
profilsiz varsayılanlar korunmuştur. AISettings profilleri ve strict planlama
sonraki teslimde eklenmiştir; ayrıntılı dosya listesi `GEMMA_WEB_SETUP.md` içindedir.

Yeni dosyalar: `api/verification/probes.py`, `api/verification/coverage.py`,
`tests/test_web_top10.py`, `tests/test_web_top10_ollama.py`, bu belge ve
`docs/examples/web_query_lab_openapi.json`. Mevcut verification katalog/model/
planner/executor/service/store/routes, merkezi workspace model/policy/service,
pinned HTTP transport, CLI ve README genişletildi. Dosya yolları `src/crimsonweb`
altındaki modüller içindir; önceki uncommitted Faz 4C/4C.1 çalışmaları korunmuştur.

Önceki 785 standard test korunur. Yeni kontroller `tests/test_web_top10.py`
üzerindedir: zafiyetli/güvenli synthetic yanıtlar, MIME/HTML bağlamları, budget,
scope/query/category reddi, bounded body/encoding, SQLite non-retention,
candidate evidence, API/workspace izolasyonu, CLI anonymous execution ve LLM
feedback/yeniden onay/tur/child uniqueness.

`tests/test_web_top10_ollama.py` iki opt-in gerçek local schema kontrolü ve bir
gerçek model / sentetik transport ile üç turlu execution testi içerir. Qwen ile
bu üç test, mevcut BOLA planlama ve üç analiz testi birlikte başarılıdır.
Testler yeni saldırı tespiti precision/recall'ını veya gerçek Gemma uyumluluğunu ölçmez.

```powershell
.venv\Scripts\python.exe -m pytest -m "not ollama" -q --junitxml=reports/web_top10/standard_tests.xml
.venv\Scripts\python.exe -m pytest tests/test_web_top10.py -q
.venv\Scripts\python.exe -m pytest -m ollama -q
.venv\Scripts\python.exe -m compileall -q src tests
```

Gerçek database migration, model download ve üçüncü taraf test yapılmadı.
Gerçek testler için kurulu yerel Ollama daemon'u başlatıldı.
RBAC, retention enforcement, encrypted storage, HAR import, browser
instrumentation, gerçek-model planlama ve Top10'un manuel kanıt gerektiren alanları
hâlâ açık işlerdir. Retention/gizlilik kapsamı önceki belgelerdeki sınırları korur.
