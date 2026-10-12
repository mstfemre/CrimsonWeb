# CrimsonWeb proje durum ve analiz raporu

Tarih: 12 Ekim 2026, Europe/Istanbul.

İnceleme: kaynak ağacı, paket bağımlılıkları, temel çalışma akışları, Git geçmişi/değişiklikleri, faz belgeleri, test artefaktları ve gerçek SQLite şemasının salt okunur kontrolü. Üretim kodu veya gerçek DB değiştirilmedi; hedef taraması/model çağrısı yapılmadı. Bu rapor ve yeni kontrol artefaktları eklendi. Bu çalışma bütün satırlar için bağımsız bir güvenlik denetimi değildir.

CrimsonWeb, izinli hedeflerde ağ/servis keşfi ile web/API güvenlik değerlendirmesini birleştiren Python uygulaması. Bugünkü ürünün en belirgin değeri, bilinen endpoint'lerden operatör onaylı test planı üretmesi, kapsam kontrollü isteklerle kanıt toplaması ve gözlenen sonucu LLM yorumundan ayırması. CLI ve FastAPI backend var; tarayıcı üzerinden kullanılan bir ürün arayüzü yok. Rich tabanlı terminal arayüzü mevcut.

## 1. Mevcut mimari — Ne var?

| Katman | Kod | Mevcut işlev |
|---|---|---|
| CLI ve tarama çekirdeği | `src/crimsonweb/cli.py`, `cli_commands.py`, `core_engine.py` | Komutlar, tarama orkestrasyonu, çalışma profilleri; eski launcher kökteki `core_engine.py`. |
| Ağ keşfi | `src/crimsonweb/discovery/`, `ports.py` | Asenkron TCP connect, SYN ve UDP keşfi, hedef/port çözümleme. |
| Servis tanıma | `probes/`, `service_detection.py`, `probes.json` | Yerel probe'lar, banner/sürüm tanıma, TLS ve web devam kontrolleri. Harici nmap/masscan çalıştırmaz. |
| Web ve CVE gözlemleri | `web_checks.py`, `cve.py`, `api/headers.py`, `web_analysis.py`, `tls.py`, `waf.py` | Header, cookie, HSTS, CORS, TLS; CPE/NVD eşleştirme ve savunma olayı değerlendirmesi. CVE eşleşmesi tek başına exploit kanıtı değildir. |
| API ve kalıcılık | `api/app.py`, `routes.py`, `database.py`, `migrations/` | FastAPI, token/Host denetimi, SQLite geçmişi, Alembic şema geçişleri. |
| Workspace ve kapsam | `api/workspaces/`, `api/scope.py`, `api/engine.py` | Domain/path/method/category/CIDR, DNS/IP, süre, istek bütçesi ve concurrency kontrolü; doğrulanan IP'ye bağlantı. |
| Web/API keşfi | `api/discovery/` | Aynı origin içinde kontrollü crawler, HTML bağlantı/form metadata'sı, offline OpenAPI importu, endpoint ve kaynak kanıt ilişkileri, kalıcı işler. Formların bulunması otomatik doldurulması anlamına gelmez. |
| Yerel AI | `api/ai/` | Ollama ile kayıtlı kanıt analizi; JSON Schema, referans doğrulama, redaksiyon, Türkçe çıktı kontrolleri ve çağrı sınırları. AI devre dışıyken teknik tarama çalışabilir. |
| Verification | `api/verification/` | Katalog, hedef çıkarma, planlayıcı, onay, sabit yürütücü, sonuç karşılaştırması, kanıt/bulgu kaydı, iptal ve takip planı. |
| Web iş akışı | `web_cli.py` | `web plan / approve / execute / report / cancel / next`; port taraması yapmadan yerel API üzerinden doğrulama. |
| Gizlilik ve operasyon | `privacy.py`, `api/privacy/`, `audit.py`, `state.py`, `reporting.py`, `egress.py` | Maskeleme, egress/DNS/IPv6 gözlemleri, audit, checkpoint/resume, raporlar; eski CLI'da proxy/Tor seçenekleri. Yeni verification akışı direct çalışır. |

Verification akışı: keşif/OpenAPI → bilinen hedefler → model veya deterministik operatör planı → operatör onayı → her istekte scope/DNS/bütçe kontrolü → sabit test → minimize edilmiş kanıt/rapor → isteğe bağlı takip planı. En çok üç tur; her yeni plan yeniden onaylanır. Model keyfi Python, shell veya HTTP payload yürütmez.

### Gerçekte uygulanmış katalog

| Test kimliği | Ne yapar? | Ne kadarını kanıtlar? |
|---|---|---|
| `bola_cross_owner_read` | İki test kimliğiyle A→A, B→B, A→B olmak üzere üç GET. | Doğru private-record/izin beklentisi ve açık binding eşleşmesi koşuluyla BOLA doğrulaması. |
| `xss_reflection_probe` | Baseline ve inert HTML marker ile iki GET. | HTML injection aday sinyali; JavaScript/browser execution, DOM/stored XSS doğrulaması yok. |
| `sql_error_probe` | Baseline, inert kontrol ve quote ile üç GET. | Quote'a özgü SQL hata aday sinyali; DB erişimi/veri çıkarma doğrulaması yok. |
| `web_security_observation` | Bir GET üzerinden header/cookie/CORS ve mevcut TLS gözlemleri. | Yapılandırma gözlemi; bütün uygulama güvenliği sonucu değil. |

Varsayılan katalog BOLA; diğer aileler açıkça seçiliyor. `--top10` uygulanmış araçları seçip on kategori için kapsam raporu üretir. Bütün OWASP kategorilerini test eden bir motor değildir; eksik alanlar `not_tested`, sınırlı gözlemler `partially_assessed` kalır.

403/429/redirect verification planını durdurur. Credential taşıyan hedef isteklerinde HTTPS gerekir; açıkça izinli dar private-lab istisnası var. Execute admission credential body okunmadan yoğunluğu reddeder; bir process içinde tek aktif execution ve bekleyen credential kuyruğu yok.

## 2. Teknoloji yığını — Stack

- Python **3.11+**; paket sürümü **2.1.0**, setuptools/wheel, `src` düzeni.
- Async I/O: `asyncio`, `aiohttp`; API/transport: FastAPI, Uvicorn, HTTPX ve Pydantic modelleri.
- Veri: SQLite, SQLAlchemy 2.x, Alembic; DNS: dnspython.
- Terminal: Rich, argparse/getpass; profil helper'ı: PowerShell.
- İsteğe bağlı: Scapy (SYN), aiohttp-socks/PyYAML (egress), curl-cffi (fingerprint), asyncio-throttle (CVE).
- HTML ayrıştırma: Python `HTMLParser`; OpenAPI importu projedeki yerel parser ile.
- AI: yerel Ollama; `gemma-web` → `gemma4:26b`, `qwen-web` → `qwen3.5:9b`. Profiller: thinking=false, context=8192, output=4096, timeout=300 s, concurrency=1. Profil AI'ı tek başına açmaz; ayrıca enabled gerekir.
- Kalite: pytest, Ruff, compileall; GitHub Actions Python 3.11/3.12 test matrisi.

Playwright, LangChain, BeautifulSoup ve OpenAI API mevcut bağımlılık/akışın parçası değil. Yerel LLM entegrasyonu Ollama HTTP üzerinden.

### En son ne yaptık?

Son commit **9 Ekim 2026 23:32 +03:00**, `f820229`: “CrimsonWeb Phase 1-5A.1 snapshot”. Bundan sonraki çalışmalar dosyalarda mevcut fakat commit edilmemiş. Dosya/belge ve test artefaktlarına göre son teslim sırası:

1. **Faz 4C:** operatör onaylı BOLA/IDOR doğrulaması, verification paketi ve `0006_phase4c` migration; standart test kaydı 759.
2. **Faz 4C.1:** web CLI, ortak secret redaksiyonu, blok sonrası retry'ı durdurma, credential HTTPS, audit minimization ve yoğunluk kabul sınırı; test kaydı 785.
3. **Web katalog/Top10:** HTML yansıması, SQL hata farkı, yapılandırma gözlemleri, query allowlist ve üç turlu takip planı; test kaydı 816.
4. **Son teslim:** Gemma/Qwen profilleri, `Set-LocalAIProfile.ps1` ve `--require-model`. Model planlayamazsa operatör fallback yerine sabit hata; strict şart takip planlarına taşınıyor. Standart test kaydı 838.

Son model artefaktlarında Gemma strict planlama **4/4**, Gemma bulgu/tarama/WAF analizi **3/3**, Qwen strict planlama **4/4** başarılı. Model gerçek Ollama; hedef yanıtları MockTransport ve DNS FakeResolver. Bu, gerçek sitelerde doğrulama veya gerçek socket/TLS uçtan uca testi değildir. Bu incelemede model suite'i yeniden çalıştırılmadı.

## 3. Hedeflenen sonraki adım — Ne yapmak istiyoruz?

Belgelerdeki açık işleri ve mevcut kodu birlikte değerlendirdiğim öneri: **mevcut plan → onay → çalıştır → rapor akışını gerçek yerel HTTP/HTTPS laboratuvarında tekrar üretilebilir hale getirmek.** Bu yeni bir kapsam önerisidir; kullanıcının belirlediği kesin yeni özellik olarak sunulmamalı.

Önerilen sıra:

1. Commit edilmemiş teslimleri gözden geçirip Git snapshot oluşturmak; test/model artefaktlarını ilgili kaynak sürümüne bağlamak.
2. Gerçek DB için ayrı ve kontrollü backup/restore doğrulaması ve `0006_phase4c` geçişi. Bu incelemede migration uygulanmadı.
3. Güvenli ve zafiyetli yerel HTTP/HTTPS fixture'larında aynı katalogla gerçek socket/TLS, scope, stop ve rapor davranışını ölçmek.
4. Endpoint bazlı test kimliği/nesne çifti ve beklenen izin tanımları; approval'ı policy revision'a bağlamak, process çökmesi sonrası verification durumunu uzlaştırmak.
5. Veri retention/purge, runtime verisinin konumu, yedek bütünlüğü; takım kullanımından önce principal/üyelik/RBAC.

Browser tabanlı XSS kanıtı, geniş rol matrisi ve redaksiyonlu HAR/Burp/ZAP importu sonraki ayrı teslimler. Mevcut katalog sonuçlarını gerçek exploit doğrulaması olarak sunmak doğru olmaz.

## 4. Engel — Nerede takıldık?

Bu depoda “LLM saldırı aracı geliştiremem dedi” şeklinde doğrulanabilir konuşma kaydı yok. Kullanıcının örnek ret cümlesi proje gerçeği olarak alınmadı. Doğrulanan engeller teknik ve operasyonel:

| Engel | Kanıt / etkisi |
|---|---|
| Gerçek DB eski | Salt okunur kontrolde `data/crimsonweb.sqlite`: **0002_phase3**, **6 tablo**. Kod head'i **0006_phase4c**. Test DB migration başarısı gerçek DB'nin güncellendiğini göstermiyor. |
| Son çalışmalar commit edilmemiş | 16 tracked dosya değişmiş; verification, migration, yeni test/docs/script/report dosyaları untracked. Git tek başına son teslimi geri üretemiyor. |
| Lint borcu | Bu incelemede tüm `src/tests` Ruff: **123 bulgu**, çıkış kodu 1. Başlıca import/logging/geniş exception ve eski kod kalitesi konuları; bu sayı 123 güvenlik açığı anlamına gelmez. |
| Gerçek hedef transport kanıtı sınırlı | Son gerçek-model suite'leri sentetik HTTP/DNS kullanıyor. LLM planlama başarısı gerçek web güvenliği doğruluğunu kanıtlamıyor. |
| Bir model testi ortam ayarı nedeniyle başarısız olmuş | `gemma_strict_profile.xml`: 4 failure; belgelenen neden boş thinking environment değeri, `Invalid thinking configuration`. Düzeltilmiş komutla ayrı artefaktlarda 4/4 geçti. Bir LLM güvenlik reddi değil. |
| Gemma bellek payı dar | Önceki kaynak örneklerinde minimum boş sistem RAM **0,393 GiB**; örneklenmiş GPU kullanımında **7782/8188 MiB**. Tarihsel tüm sistem ölçümü; bu incelemede yeni benchmark yapılmadı. |
| Veri yaşam döngüsü tamamlanmamış | `retention_enforced=False`; otomatik purge yok. SQLite/yedekler uygulama düzeyinde şifrelenmiyor. Repo OneDrive yolunda; sync'in açık olduğu doğrulanmadı. |
| Tek operatör yetki modeli | Ortak API token'ı; kullanıcı üyeliği/RBAC ve doğrulanmış approver kimliği yok. Workspace kayıt ilişkilerinin izolasyonu kullanıcı yetkilendirmesinin yerini tutmuyor. |
| Çalıştırma ölçeklenmesi/lifecycle | Verification execution inline ve process-içi seri lock ile; bounded background worker, endpoint bazlı identity/object binding ve crash recovery açık. |
| Sürüm/belge tutarsızlığı | Paket 2.1.0; API title hâlâ “CrimsonWeb Phase 3”, version 0.3.0. Eski faz belgelerinin bazı ifadeleri yeni katalog öncesini anlatıyor. |

CI pytest çalıştırıyor; lint/compile/migration/restore ayrı kalite kapıları mevcut workflow'da yok. Bu yerel çalışma için uzaktaki CI sonucu doğrulanmadı.

## 5. İstenen çıktı türü — Prompt ne üretmeli?

Bu isteğin çıktısı: **kaynak ve test kanıtlarına bağlı Türkçe proje durum/analiz raporu**. Şu aşamada bir exploit scripti ya da yeni agent geliştirme isteği yok.

Sonraki uygulama görevi için önerilen çıktı: yerel laboratuvar fixture'ları + Python integration testleri + JSON verification raporu + kısa tekrar çalıştırma kılavuzu. Mevcut sonuç sözleşmesinde plan/test kimlikleri, katalog, outcome/confidence, kanıt referansları, kapsam/stop sebepleri ve Top10 coverage tutulmalı; ham credential/yanıt gövdesi eklenmemeli.

Kopyalanabilir sonraki görev taslağı:

> CrimsonWeb'in mevcut scope guard, sabit test kataloğu ve operatör onayını kullanarak yalnız yerel HTTP/HTTPS laboratuvarında plan→approve→execute→report akışını gerçek socket/TLS üzerinden doğrula. Güvenli ve zafiyetli fixture'ları birlikte test et. 403/429/redirect durdurma, credential HTTPS, DNS/IP sınırı ve kanıt minimizasyonunu koru. XSS/SQL adaylarını doğrulanmış exploit olarak etiketleme. Gerçek kullanıcı veritabanını değiştirmeden Python integration testleri, JSON sonuç raporu ve tekrar çalıştırma kılavuzu üret.

## Bu incelemenin doğrulaması

- Standart pytest bu incelemede yeniden çalıştırıldı: **838 passed, 0 failed, 8 deselected**, **78,17 saniye**. Sekiz opt-in Ollama testi bu koşuya dahil değil. Bir mevcut Starlette/TestClient deprecation uyarısı var. Yeni JUnit: `reports/project_review_2026-10-12_standard.xml`.
- Ruff `src tests`: **123 bulgu**, kontrol başarısız; ayrıntı `reports/project_review_2026-10-12_ruff.json`.
- `compileall -q src tests`: başarılı.
- `git diff --check`: başarılı; Git bazı dosyalar için LF→CRLF çalışma kopyası uyarısı veriyor.
- Gerçek DB yalnız şema sürümü/tablo sayısı için read-only açıldı; kayıt içerikleri dışarı aktarılmadı.

Güncel teslimin ana referansları: `docs/GEMMA_WEB_SETUP.md`, `docs/WEB_TOP10_ENGINE.md`, `docs/PHASE4C1.md`. `docs/CURRENT_STATE_REVIEW_2026-10-12.md` daha eski bir snapshot; oradaki safe-stop/redaksiyon/HTTPS/admission eksiklerinin bir kısmı 4C.1 ile giderilmiş. Eski rapordaki 759/785 değerleri son 838 kayıtlarının yerine kullanılmamalı.
