# CrimsonWeb — Faz 1–5A Denetimi (salt okunur)

Tarih: 2026-10-09. Yöntem: her iddia kodda okunarak ve projenin **kendi** testleri
çalıştırılarak doğrulandı; önceki oturum raporları doğru kabul edilmedi. Hiçbir kod,
test, migration veya git durumu değiştirilmedi. Üçüncü taraf hedefe istek gönderilmedi.
Ortam: Windows, `.venv` Python 3.12.14, ruff 0.16.10, Ollama `gemma4:26b`.

## 1. Yönetici özeti

En kritik 5 bulgu:
1. **[Yüksek]** Faz 1–5A'nın tamamı commit edilmemiş (13 değişmiş + 152 untracked) ve bir
   OneDrive klasöründe. Senkron/çakışma veya kaza tek kopyayı kaybettirebilir.
2. **[Yüksek/operasyonel]** Gerçek `data/crimsonweb.sqlite` hâlâ `0002_phase3`. Açılışta
   `Repository.initialize()` otomatik `upgrade head` çalıştırıyor → API ilk kez başlatılınca
   prod DB, yedek adımı olmadan 0005'e taşınır (`database.py:450-454`).
3. **[Orta/Yüksek]** `origin/main` ile yerel, `cve.py`/`test_cve.py` üzerinde **ters tasarım**
   taşıyor (origin servis-whitelist'ini kaldırıyor, yerel whitelist ekliyor). Birleştirmede
   çakışma kesin; bir tasarım kazanmalı.
4. **[Orta]** Origin CI yalnız `.[full]` kuruyor; `api`/`dev` ekstraları yok. `api/` testleri
   (FastAPI/SQLAlchemy/Alembic) CI'da import aşamasında çalışmaz → kalite kapısı kör.
5. **[Düşük]** `PHASE5A.md`'de iki hata (benim yazdığım): "151 yeni test" → gerçek **144**;
   `privacy.py`/`scheduling.py`/`test_privacy.py`/`test_scheduling.py` Faz 5A'ya değil
   2026-10-08 refactor'una ait.

Güvenlik sözleşmeleri (deny-by-default, tek guard, SSRF/rebinding, izolasyon, sabitler,
ham-IP tutmama): **tümü kodda doğrulandı ve geçen testlerle destekleniyor** (§3).

## 2. Doğrulanan / doğrulanamayan iddialar

| İddia | Kaynak | Sonuç | Kanıt |
|---|---|---|---|
| Standart testler 0 başarısız | kendi koşum | Doğrulandı | `613 passed, 4 deselected` (56 s) |
| "151 yeni Faz 5A testi" | PHASE5A.md | **Yanlış** | Gerçek 144 (6× `test_phase5a_*`); 473→617 farkı |
| privacy.py/scheduling.py 5A dosyası | PHASE5A.md | **Yanlış** | CreationTime 2026-10-08; 5A kodu 2026-10-09 10:2x |
| Faz 5A yeni ruff ihlali eklemedi | ruff JSON karşılaştırma | Doğrulandı | 4b=127, 5a=127, now=126 (yalnız `re.I` fix) |
| 125→127 artış hangi faz | reports | **Doğrulanamadı** | 4A için ruff JSON kaydı yok; 4B snapshot'ı 127 |
| Migration upgrade/downgrade temiz | temiz SQLite koşum | Doğrulandı | 0001↔0005 tam zincir, `alembic check` temiz |
| Gerçek DB zaten head'de | — | **Yanlış** | Gerçek DB `0002_phase3`, 6 tablo |
| Gemma 4 regresyon 3/3 | kendi koşum | Doğrulandı | 147.88 s; profil korunmuş (§3.8) |
| Model profili değişmedi | kaynak + env | Doğrulandı | `provider.py:51-59` + from_env |

## 3. Güvenlik sözleşmeleri (kod + test)

**3.1 Preflight ağ yapmıyor.** `PrivacyService.preflight` yalnız DB snapshot + saf
`evaluate()` + `preflight_audit` çağırır; `decide`/`resolver.resolve`/`stream` **yok**
(`privacy/service.py:72-110`). `PrivacyPreflight.network_performed` sözleşme gereği
`Literal[False]` (`privacy/models.py:147-148`). Test: `test_phase5a_jobs.py:223`
(`...passive_preflight_require_no_network`). Not: ağ yapan tek yol gözlem (`decide`→
`resolver.resolve`, `service.py:79-81`) olup bu preflight değildir.

**3.2 Deny-by-default; PrivacyPolicy scope'u yalnız daraltır.** `privacy_reason` ek kısıt
listesi (`privacy/evaluation.py:32-54`); `verification_url` için `program_policy_id`
zorunlu (`privacy/models.py:128-138`). `managed_egress` ve zorunlu interface ağdan önce
reddedilir (`evaluation.py:44-47`). Test: `test_phase5a_contracts.py`, `..._lab.py`.

**3.3 Tek guard; atlayan çağrı yok.** `grep` ile `api/` içindeki tüm ağ çağrı noktaları:
tek transport primitifi `pinned_response` (`engine.py:36-65`, `trust_env=False`,
`follow_redirects=False`), DNS `Scope.resolve`/`SystemResolver` (getaddrinfo/dnspython),
IPv6 **yetenek** probu (aşağıda), ve yerel AI `ai/provider.py`. Privacy servisi yalnız
`self.guard.decide`/`self.guard.stream` kullanır (`privacy/service.py:153,223`). Guard'ı
atlayan serbest `httpx/socket/urllib/requests` çağrısı bulunamadı.

**3.4 SSRF / loopback / link-local / private / IPv4-mapped.** `ip_allowed`
(`workspaces/policy.py:74-99`) reddeder: bulut metadata IP'leri (PROTECTED_PLATFORM_IPS),
`%` scope, unspecified, multicast, link-local, reserved(non-loopback) ve IPv6
`ipv4_mapped/sixtofour/teredo`; private ağ yalnız `owned/lab` + `allow_private_networks`.
IPv6 yetenek probu yalnız `bind(("::1",0))`, dışarı bağlanmaz (`evaluation.py:113-122`).

**3.5 DNS rebinding / redirect / CNAME re-doğrulama.** `evaluate()` çözülen her adresi ve
CNAME zincirini yeniden denetler (`policy.py:146-162`); `SystemResolver` DNAME'i reddeder,
A/AAAA tutarsızlığını (`chains[0]!=chains[1]`) ve eksik zinciri yakalar (`dns.py:27-88`).
Admission, taze çözümle DB işlemi içinde tekrar değerlendirir (`service.py:85-110`).
Redirect takip edilmez (privacy tek gözlem; `service.py:245-246`). Testler:
`test_phase5a_observations.py:423`, `test_phase4a_runtime.py:59,72`, `test_phase1_api.py:104`.

**3.6 403/429/WAF güvenli durma; rotasyon/engel aşma yok.** `stream` 403/429'da `halt`
eder (`service.py:174-187`); egress gözlemi `PrivacyStop` ile durur (`privacy/service.py:232-237`).
`notify_defense` yalnız `waf_block/ip_block/authorization_violation` (`service.py:201-208`).
IP rotasyonu / proxy / fallback kodu yok.

**3.7 Workspace izolasyonu (IDOR/BOLA).** Tüm store sorguları `workspace_id` ile
nitelikli (`privacy/store.py:45-101,246-249`); evidence yazımında çapraz-workspace fence
(`store.py:469`); yabancı kayıt 404 döner. Testler: `test_phase5a_api.py:221`
(`foreign_workspace_objects_are_unreachable`), `test_phase5a_database.py:90,160`,
`test_phase4a_api.py:112`, `test_phase4b_api.py:136`.

**3.8 Kimlik doğrulama.** Ortak Bearer token; `secrets.compare_digest` ile **zaman-sabit**
karşılaştırma (`app.py:121-125`). Token tanımsızsa yalnız loopback kabul (`app.py:110-129`).
Tüm rotalar app seviyesindeki `Depends(authorize)` ile korunur (`app.py:135`); test
`test_phase4a_api.py:187`. **Eksik:** uygulama katmanında `Host` başlığı allowlist'i yok;
TrustedHostMiddleware yok. Pratik rebinding riski IP-pinning + `ip_allowed` + CNAME
denetimiyle sınırlanıyor (§3.4-3.5), ancak derinlemesine savunma için Host doğrulaması
önerilir. **[Düşük]**

**3.9 Sabitler değiştirilemez.** `interface_verified`, `route_verified`,
`anonymity_guaranteed`, `retention_enforced` ve `echo_trust` Pydantic `Literal[False]`/
`Literal["untrusted"]` (`privacy/models.py:147,169,171-172,246-247`); başka değer
validasyonda reddedilir. Test: `test_phase5a_contracts.py`.

**3.10 Ham IP/resolver/token persist ve log.** Gözlenen IP/resolver yalnız profile'a özel
`secrets.token_hex(32)` HMAC parmak izi olarak saklanır (`privacy/evaluation.py:10-13`,
`store.py:145`); ham IP/body/header persist edilmez. Audit `safe_summary=
"metadata_only_no_raw_ip_or_payload"` (`store.py:129`). Loglarda `audit._PrivacyFilter`
+ `sanitize` (`audit.py` diff). `parse_echo` yalnız sınırlı `{"ip": ...}` JSON kabul eder
(`evaluation.py:70-93`). **Sınır (tehdit modelinde belirtilmiş):** HMAC pseudonymization'dır,
DB'yi okuyan aday IP deneyebilir; harici web-server/httpcore debug logları maskelenmez.

**3.11 Worker / iptal / recovery.** Tek işbirlikçi worker + `WorkerLock` OS-lifetime kilidi;
`claim/check/complete` sahiplik+revizyon+iptal fence'i (`privacy/service.py:273-401`,
`store.py:367-480`). İptalde slot serbest bırakılmadan güvenli kapanış (§prod'da bütçe iade
yok). Namespace'ler çapraz-engine recovery'yi engeller: `test_phase5a_jobs.py:285`. Publication
fence: `test_phase5a_jobs.py:166`. `gate=Semaphore(1)` ile seri yürütme (`service.py:52,278`).
Yarış riski: canlı worker kilidi tutulurken recovery atlanır — tasarım gereği; dağıtık/çok
host desteklenmez (tehdit modeli ile tutarlı).

**3.8b Gemma 4 opt-in koşumu.** `test_phase3_ollama_integration.py` 3/3 passed, **147.88 s**
(findings 72.5 s [model yükleme dahil], scan 46.5 s, waf 27.8 s). Profil: `gemma4:26b`,
thinking=false, context 8192, output 4096, timeout 300, concurrency 1 — `from_env` ile set,
kaynak varsayılanlarıyla (`provider.py:51-59`) doğrulandı. AI'a scope değiştirme veya ağ
isteği yetkisi verilmiyor (deterministik `evaluate`/`privacy_reason` dışında karar yok).

## 4. Yeni vizyona (Privacy-First) hizalama

- **Doğrudan kullanılır:** `api/privacy/*` (Privacy & Leak Protection çekirdeği),
  `workspaces/*` (Scope/Authorization çekirdeği), `engine.pinned_response`+`scope.py`
  (pinned transport), `audit.py`/`privacy.py` (minimizasyon), TLS/WAF/header analizleri.
- **Hunter ürününe ait:** `api/discovery/*` (crawler, OpenAPI import, inventory/surface
  graph) — keşif/zafiyet avı; privacy platformunda yalnız opsiyonel bağımlılık olmalı.
  Not: `PrivacyService` şu an `discovery.crawler.AuthorizedCrawler`/`durable`/`WorkerLock`'a
  bağımlı (`privacy/service.py:11-13`) → çekirdek ayrımında bu yardımcılar ortak bir
  `core`/`worker` paketine taşınmalı, yoksa dairesel/istenmeyen bağımlılık kalır. **[Orta]**
- **Çekirdek ayırma maliyeti:** `workspaces`+`scope`+`engine`+`database` tek SQLAlchemy
  `Base`/migration zincirini paylaşıyor; ayrı pakete çıkarmak migration sahipliğini ve
  `Repository` bağımlılığını bölmeyi gerektirir — orta maliyet, tek `Base` nedeniyle önce
  metadata ayrımı planlanmalı.
- **Doküman çelişkisi:** `PHASE5_ARCHITECTURE.md`/`PRIVACY_THREAT_MODEL.md` 5B–5F'yi
  Secure Egress/Fingerprint/AI Analyst olarak zaten privacy-first sırada tanımlıyor; yeni
  vizyonla büyük çelişki yok. Eksik tehditler: **OS seviyeli kill switch yok** (uygulama
  fail-closed ≠ kill switch — belgede kabul edilmiş), **WebRTC/tarayıcı sızıntısı** hiç
  ele alınmamış, **TLS/HTTP fingerprint** 5C'ye ertelenmiş. Bunlar tehdit modeline açık
  kapsam-dışı maddeler olarak eklenmeli.

## 5. Teknik borç ve risk

| Risk | Önem | Öneri |
|---|---|---|
| Tüm iş commit dışı, OneDrive'da | Yüksek | Faz bazlı commit (aşağıda), uzak yedek |
| Prod DB 0002 + açılışta oto-upgrade, yedek kapısı yok | Yüksek | Başlatma öncesi zorunlu backup; `initialize` öncesi revizyon kontrolü/uyarı |
| origin cve.py ters tasarım çatışması | Orta/Yüksek | Birleştirmeden önce whitelist tasarımına karar ver |
| CI `api`/`dev` ekstralarını kurmuyor | Orta | CI'ya `.[api]`/`.[dev]` ekle, aksi halde api testleri koşmaz |
| Kullanıcı bazlı RBAC yok (ortak token) | Orta | Çok kullanıcılı kullanım öncesi RBAC |
| Eski analizler workspace'e atanmıyor | Düşük | Geri doldurma migration'ı veya "legacy" workspace |
| Çökme sonrası açık rezervasyon bütçe iadesi yok | Düşük | Sınırlı, önizlemeli temizleme işi (belgede planlı) |
| Host başlığı doğrulaması yok | Düşük | TrustedHost allowlist (derinlemesine savunma) |
| `privacy`→`discovery` bağımlılığı | Orta | Ortak worker/crawler yardımcılarını `core`'a taşı |
| Windows/Linux: SYN/scapy, dosya kilidi farkları | Düşük | CI matrisi 3.11/3.12 var; Windows job ekle |

## 6. Commit stratejisi (yalnızca öneri — uygulanmadı)

> **Uyarı:** API'yi başlatan her komut (`uvicorn`, bazı testler değil ama elle çalıştırma)
> `Repository.initialize()` üzerinden gerçek DB'yi 0005'e yükseltir. Commit/push öncesi ve
> API'yi ilk başlatmadan önce `data/crimsonweb.sqlite` **yedeklenmeli**.

1. Önce `origin/main`'i al; `cve.py`/`test_cve.py` tasarım çatışmasını bilinçli çöz (iki
   whitelist yaklaşımından birini seç), ayrı bir commit olarak.
2. Faz bazlı commit sırası: Faz1→2→3→3.5→4A→4B→5A; her commit ilgili `src`+`tests`+`docs`
   +`migration` dosyalarını içersin. `data/`, `*.sqlite`, `.lock` zaten `.gitignore`'da.
3. Her fazda `pytest -m "not ollama"` + hedefli `ruff` geçtiğini doğrula; depo-geneli ruff
   127 eski ihlalle `exit 1` verir (ayrı teknik borç olarak izlenebilir, faz commit'lerini
   bloklamasın).
4. Tag: `v2.1.0-phase5a`. 5A tamamlanınca dur; 5B'yi ayrı başlat.
5. CI düzeltmesini (`.[api]`/`.[dev]`) ilk push'tan önce yap ki api testleri koşsun.

## Ek A — origin `cve.py` / `test_cve.py` çatışma notu (Faz 5A.1'de değiştirilmedi)

- `origin/main` (429af3a) yalnız `tests/test_cve.py`'yi değiştirir: `test_service_product_mismatch_is_rejected`
  kaldırılıp `test_extraction_is_service_independent` eklenir; beklenti `_query_from_version("ssh",
  "nginx/1.25.4")` → nginx CPE (servis etiketinden bağımsız çıkarım). Origin `cve.py`'ye dokunmaz.
- Yerel çalışma ağacı ters yönde: `cve.py`'ye `PRODUCT_SERVICES` whitelist'i eklenmiş (satır ~52-64,
  ~115-117) ve yerel test uyumsuz ürün/servis eşleşmesini **reddeder**.
- Origin'in testi yerel `cve.py` ile çalıştırıldığında 1 başarısız (`None != 'cpe:2.3:a:nginx:...'`).
  `git pull` sırasında `tests/test_cve.py` metin çatışması da beklenir.
- Karar gereken soru: CPE çıkarımı servis etiketine bağlı mı olmalı (yanlış pozitif CVE eşleşmesini
  azaltır) yoksa bağımsız mı (banner yanlış portta çıksa da ürün tanınır)? Karar verilene kadar
  iki dosya da olduğu gibi bırakıldı.
- Ayrıca Faz 5A.1 `.github/workflows/ci.yml`'yi yerelde **untracked** olarak oluşturdu (origin'deki
  dosyanın `.[full,api,dev]` sürümü). `git pull` bu untracked dosya nedeniyle "would be overwritten"
  hatası verir; çözüm: dosyayı geçici olarak kenara al → pull → tek satırlık değişikliği yeniden uygula.

Faz 5A.1 kapanış durumu için bkz. `docs/PHASE5A1.md` (Host allowlist, zorunlu token,
yedekli migration, PHASE5A.md sayı/dosya düzeltmeleri, CI ekstraları).

## Özet (≤15 satır)

- Faz 5A kodu sağlam: tüm güvenlik sözleşmeleri (deny-by-default, tek guard, SSRF/rebinding/
  CNAME, IPv6 yetenek-probu bind-only, workspace izolasyonu, zaman-sabit token, `Literal[False]`
  sabitler, ham-IP yerine HMAC, worker fence) kodda ve geçen testlerle **doğrulandı**.
- Standart testler `613 passed, 4 deselected`, 0 başarısız. Gemma 4 opt-in **3/3**, 147.88 s,
  profil korunmuş. Migration zinciri temiz SQLite'ta tam ileri/geri çalışıyor.
- Önceki raporların iki iddiası yanlış: Faz 5A testi **144** (151 değil); `privacy.py`/
  `scheduling.py` ve `test_privacy`/`test_scheduling` 5A'ya ait değil — `PHASE5A.md` düzeltilmeli.
- En yüksek riskler **operasyonel**: tüm iş commit dışı (OneDrive); prod DB 0002'de ve açılışta
  yedeksiz oto-upgrade; origin'de `cve.py` ters tasarım çatışması; CI `api`/`dev` kurmuyor.
- Privacy-first vizyona çekirdek (`privacy`+`workspaces`+`engine`) uygun; `discovery` Hunter
  ürününe ait ve `privacy`'nin ona bağımlılığı ayırmadan önce çözülmeli. Eksik tehditler:
  OS kill switch, WebRTC/tarayıcı sızıntısı, TLS/HTTP fingerprint.
- Hiçbir düzeltme uygulanmadı. Faz 5B başlatılmadı.
