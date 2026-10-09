# CrimsonWeb Faz 5A — Privacy Engine (gözlem, deterministik değerlendirme, minimal kanıt)

Bu belge yalnız **Faz 5A** teslimini anlatır. 5B–5F kodlanmadı; teknik planları
`docs/PHASE5_ARCHITECTURE.md` ve `docs/PRIVACY_THREAT_MODEL.md` içindedir.
Faz 5A, mevcut Faz 1–4B altyapısını ve Gemma 4 entegrasyonunu **değiştirmeden**
privacy profilini kapsam iznine *ek bir kısıt* olarak ekler.

> Privacy değerlendirmesi bir anonimlik sertifikası değildir. `secure_observed`
> yalnız belirli bir kontrollü gözlemin beklenen koşulu karşıladığını söyler.
> `anonymity_guaranteed` ve `retention_enforced` alanları sözleşme gereği her zaman `false`.

## 1. Gerçekten çalışan bileşenler

- **PrivacyProfile / PrivacyPolicy**: workspace'e bağlı, revizyonlu profil ve bu profile
  özel politika. Profil beklenen kimliktir (egress identity, resolver, aile/interface,
  retention beklentisi); hedef izni değildir. Politika, ProgramPolicy iznine yalnız
  kısıt ekler (verifier allowlist, test türü, explicit approval/expiry, diagnostic
  bütçe/rate, IPv6 probe onayı). `maximum_concurrency` sözleşme gereği `Literal[1]`.
- **Diagnostic preflight**: pasif/advisory. `network_performed=false`, `advisory_only=true`;
  hiçbir DNS/HTTP göndermez, yalnız profil + privacy politikası + (varsa) ProgramPolicy
  revizyonlarını ve deterministik admission kararını döndürür.
- **Observation (assessment)**: `egress`, `dns`, `ipv6`. Aktif gönderim, mevcut
  `WorkspaceService` karar/lease/HTTPX pinning yolundan geçer; her assessment **en fazla
  bir logical network observation** yapar, redirect takip etmez.
- **Deterministik değerlendirme**: tüm status/aile/resolver kararları Python kodu ile
  verilir (`evaluation.py`). AI çağrısı yoktur.
- **Minimal kanıt + audit**: gözlenen ham IP/resolver persist edilmez; profile'a özel
  salted HMAC parmak izi saklanır. Audit `safe_summary` + maskeli `evidence_ref` tutar.
- **Kalıcı, iptal edilebilir işler**: assessment kuyruğa alınır (`queued`), tek aktif iş
  (`maximum_active_jobs=1`), `expires_at` ve `cancel_requested` fence'i; crash sonrası
  sahiplik ancak eski worker'ın sona erdiği kanıtlanınca açılır (PID/timeout tek başına
  yeterli değil).

## 2. Kapsam ve gönderim güvenliği

- **Deny-by-default korunur.** PrivacyPolicy scope'u **genişletemez**; yalnız daraltır.
  `verification_url` için `program_policy_id` zorunludur (bkz. `DiagnosticRequest.network_contract`).
- `managed_egress` modu ve zorunlu `allowed_network_interfaces`, mevcut pinned direct
  transport bunları sağlayamadığı için **ağ gönderiminden önce** `blocked_by_policy` ile
  reddedilir. Alternatif yola sessiz retry/fallback yoktur.
- HTTPX `trust_env=False` ve `engine.pinned_response` değişmedi; OS proxy/VPN/WinHTTP
  durumu doğrulanmış sayılmaz.
- 403/429/WAF kararları `access_denied`/`rate_limited`/`blocked_by_policy` olarak kalır;
  IP rotasyonu, gizli tarama veya engel aşma eklenmedi.
- Fragment (`#`) içeren verifier/verification URL'leri reddedilir; URL'ler `active_url`
  ile normalize edilir.

## 3. Kanıt statüleri

| Status | Anlamı |
|---|---|
| `secure_observed` | Kontrollü gözlem beklenen koşulu karşıladı; genel koruma iddiası yok |
| `leak_suspected` | Echo mismatch / capability-config göstergesi; bağımsız kanıtlı egress leak değil |
| `leak_validated` | Yalnız doğrudan transport metadata ile doğrulanabilen dar iddia veya trusted lab instrumentation ile gözlenen resolver yolu |
| `inconclusive` | Timeout, çelişkili/eksik echo, bilinmeyen resolver yolu veya ölçülmeyen route |
| `not_tested` | Test yapılmadı; olumlu/olumsuz leak sonucu üretilemez |
| `blocked_by_policy` | Scope/privacy/unsupported mode/revision/defense kararı gönderimi engelledi |

Echo sunucusu yanlış IP bildirebilir (`echo_trust="untrusted"`). DNS A/AAAA kaydı public
egress IP veya DNS leak kanıtı değildir; bağlantının peer ailesi, sunucunun bildirdiği
client IP ailesinden ayrı tutulur. `interface_verified`/`route_verified` sözleşme gereği
`false`.

## 4. Veritabanı ve kanıt sözleşmesi

- Yeni migration: `0005_phase5a` (down_revision `0004_phase4b`). Mevcut veriyi korur;
  geri alınabilir (`downgrade` tanımlı).
- Yeni tablolar: privacy profile, privacy policy (revizyon + `used_observations`),
  assessment, evidence, network-leak finding, privacy audit log. Hepsi workspace'e ve
  profile/assessment'a bileşik FK ile bağlıdır → **workspace izolasyonu** servis ve API
  seviyesinde zorlanır.
- Pydantic modelleri (`api/privacy/models.py`): `PrivacyProfile(Input)`, `PrivacyPolicy(Record)`,
  `DiagnosticRequest`, `PrivacyPreflight`, discriminated `PrivacyEvidence`
  (`EgressObservation`/`DNSObservation`/`IPv6Observation`/`PolicyObservation`),
  `NetworkLeakFinding`, `PrivacyAssessment`, `PrivacyAuditLog`.
- `LoggingSettings`: `mask_ip_literals=True`, `store_raw_payloads=False`,
  `retention_enforced=False` (sözleşme sabitleri). Beklenen IP/resolver kimlikleri
  profile'a özel salted HMAC ile karşılaştırılır; raw IP persist edilmez.

## 5. Worker, iptal ve recovery

- Tek cooperating local worker + OS lifetime lock. İptalde yanıt, rezervasyon serbest
  bırakılmadan güvenli kapanır; bütçe geri yüklenmez (fail-safe).
- Privacy rezervasyonları, discovery rezervasyonlarından ayrıdır; yaşayan worker'ın kilidi
  recovery'yi engeller.
- Diagnostic preflight bütçesi admission'ı ayrı sayılır; ProgramPolicy bütçesi yalnız
  gerçek guarded admission'ı sayar. A/AAAA paket sayısı logical observation sayısı değildir.

## 6. API

Tümü `GET/POST/PUT/DELETE /api/v1/workspaces/{workspace_id}/privacy/...` altında,
ortak operatör Bearer token'ı ve Host allowlist'i ile (Faz 5A.1, `docs/PHASE5A1.md`):

| Yöntem | Yol | İşlev |
|---|---|---|
| POST | `/profiles` | Profil oluştur (201) |
| GET | `/profiles` | Profil listesi (sayfalı) |
| GET/PUT/DELETE | `/profiles/{id}` | Profil oku / revizyonla güncelle / sil |
| GET/PUT | `/profiles/{id}/policy` | Privacy politikasını oku / revizyonla güncelle |
| POST | `/profiles/{id}/preflight` | Pasif advisory admission kontrolü (ağ yok) |
| POST | `/profiles/{id}/observations` | Gözlem başlat (202, kuyruğa alır) |
| GET | `/assessments` / `/assessments/{id}` | Assessment listesi / tek kayıt |
| POST | `/assessments/{id}/cancel` | Güvenli iptal |
| GET | `/assessments/{id}/findings` | Network-leak bulguları |
| GET | `/evidence/{id}` | Tek kanıt (discriminated) |
| GET | `/audit` | Maskeli privacy audit log (sayfalı) |

`PUT` işlemleri `expected_revision` ister (optimistic concurrency). Scope kontrol
servisi 4B/4C modüllerinin çağıracağı ortak arayüz olarak korunur.

### Kurulum ve migration

```bash
# Gerçek veritabanını yedekledikten ve uygulamayı durdurduktan sonra:
python -m alembic -c alembic.ini upgrade head     # 0005_phase5a'ya kadar
```

API açılışı (Faz 5A.1 sonrası):
- `CRIMSON_API_TOKEN` **zorunlu**; tanımsızsa API başlamayı reddeder. Token'sız çalışma
  yalnız `CRIMSON_API_DEV_ALLOW_NO_TOKEN=1` ile ve yalnız loopback istemcilerle mümkündür.
- `Host` başlığı allowlist'e karşı doğrulanır; varsayılan `127.0.0.1`, `localhost`, `[::1]`
  (her port). Port kısıtlamak için örnek: `CRIMSON_API_ALLOWED_HOSTS=127.0.0.1:8000,localhost:8000`.
  Eşleşmeyen Host 403 alır (`/docs` ve `/openapi.json` dahil).
- `Repository.initialize()` head'in gerisindeki mevcut DB'yi upgrade etmeden önce
  zaman damgalı yedek alır (`<db>.<UTC>.bak` + varsa `-wal`/`-shm`); yedek başarısızsa
  upgrade yapılmaz. Elle `alembic upgrade` bu yedeği almaz.

Geri alma (gerekirse): `python -m alembic -c alembic.ini downgrade 0004_phase4b`.

### API kullanımı — yalnız kendi izinli laboratuvarınız / sahipli hedef

```bash
API=http://127.0.0.1:8000/api/v1/workspaces/$WS/privacy   # Host allowlist'te olmalı
AUTH="Authorization: Bearer $CRIMSON_API_TOKEN"            # her istekte zorunlu
JSON="Content-Type: application/json"

# 1) Profil (beklenen egress IPv4, uygulama resolver yolu, IPv4-only beklentisi)
curl -XPOST "$API/profiles" -H "$AUTH" -H "$JSON" -d '{
  "name": "lab-egress", "mode": "direct_observation",
  "ipv4_expectation": "expected", "ipv6_expectation": "forbidden",
  "approved_egress_identity": ["203.0.113.10"],
  "dns_expectations": {"approved_resolvers": ["203.0.113.53"], "path": "application"}}'

# 2) Privacy politikası (verifier allowlist + explicit approval + bütçe)
curl -XPUT "$API/profiles/$PID/policy?expected_revision=1" -H "$AUTH" -H "$JSON" -d '{
  "verification_urls": ["https://echo.lab.internal/ip"],
  "allowed_tests": ["egress","dns"], "operator_approved": true,
  "maximum_observations": 50, "rate_limit_per_minute": 6}'

# 3) Pasif preflight (ağ YOK) → sonra gözlem
curl -XPOST "$API/profiles/$PID/preflight" -H "$AUTH" -H "$JSON" -d '{"kind":"egress",
  "program_policy_id":"'$PROG'","verification_url":"https://echo.lab.internal/ip"}'
curl -XPOST "$API/profiles/$PID/observations" -H "$AUTH" -H "$JSON" -d '{"kind":"egress",
  "program_policy_id":"'$PROG'","verification_url":"https://echo.lab.internal/ip"}'
```

## 7. Gemma 4 korunması

AI sözleşmesi, JSON Schema, kanıt referansı doğrulaması ve üretim modeli **değişmedi**.
Gerçek Ollama regresyonu (opt-in) `reports/phase5a/gemma4_regression.json`:

| Senaryo | Sonuç | Referans doğrulaması |
|---|---|---|
| findings | passed | 1/1 bulgu, exact match |
| scan | passed | 2/2 bulgu + 1/1 WAF, exact match |
| waf | passed | doğrulandı |

Korunan profil: `gemma4:26b`, `thinking=false`, context `8192`, output `4096`,
timeout `300`, concurrency `1`. Privacy katmanı AI'a kapsam değiştirme veya ağ isteği
gönderme yetkisi vermez; tüm izin kararları deterministiktir.

## 8. Doğrulama ve dosyalar

**Standart testler (ollama hariç):** `613 passed, 4 deselected` (56 s). Başarısız: **0**.
Bunların **144'ü Faz 5A** testidir (altı `test_phase5a_*` dosyası: api 36, contracts 39,
database 19, jobs 13, lab 7, observations 30). Bu, 4B sonundaki 473 toplanan testten
617'ye olan farkla birebir örtüşür. Faz 1–4B testleri regresyonsuz geçer. Opt-in Ollama
testleri (4) gerçek yerel model ister. (Düzeltme: bu belgenin ilk sürümü yanlışlıkla 151
yazıyordu; `test_privacy`/`test_scheduling` 2026-10-08 refactor'una aittir.)

**Ruff:** Faz 5A'nın tüm yeni kaynak/test dosyaları temiz (`All checks passed!`).
5A teslimi sırasında 10-08 refactor dosyası `privacy.py` içindeki tek ihlal (`re.I` →
`re.IGNORECASE`, `FURB167`) de düzeltildi. Depo genelindeki 126 **eski** ihlal (I001/LOG015/BLE001/UP0xx; legacy
`core_engine.py`, `audit.py`, `discovery/*`, `service_detection.py` vb.) Faz 5A kapsamı
dışıdır ve değiştirilmedi — tam döküm `reports/phase5a/full_repo_ruff.json`.

**Derleme:** `compileall` temiz (exit 0).

**Privacy performans ölçümü** (`reports/phase5a/privacy_performance.json`; mock transport,
gerçek ağ gecikmesi/OS koruması değil):
- Başlangıç: ~22.45 ms; 7 seri sentetik iş, 0 AI çağrısı.
- Egress gözlem medyanı: **57.13 ms**; DNS 49.28 ms ve IPv6 24.91 ms (`inconclusive`).
- Ek Python bellek tepe değeri (tracemalloc): **~0.72 MiB**; process working set farkı: **~2.37 MiB**.
- `maximum_active_jobs=1`, response body limiti 4096 B.

**Faz 5A dosyaları** (satır):

| Dosya | LOC |
|---|---|
| `src/crimsonweb/api/privacy/store.py` | 656 |
| `src/crimsonweb/api/privacy/service.py` | 426 |
| `src/crimsonweb/api/privacy/models.py` | 215 |
| `src/crimsonweb/api/privacy/routes.py` | 157 |
| `src/crimsonweb/api/privacy/evaluation.py` | 106 |
| `src/crimsonweb/api/privacy/dns.py` | 67 |
| `src/crimsonweb/api/privacy/admission.py` | 32 |
| `src/crimsonweb/api/privacy/__init__.py` | 1 |
| `src/crimsonweb/api/migrations/versions/0005_phase5a.py` | 153 |
| `tests/test_phase5a_database.py` | 453 |
| `tests/test_phase5a_observations.py` | 408 |
| `tests/test_phase5a_jobs.py` | 397 |
| `tests/test_phase5a_api.py` | 308 |
| `tests/test_phase5a_lab.py` | 169 |
| `tests/test_phase5a_contracts.py` | 127 |
| `tests/privacy_lab_helpers.py` | 109 |
| `tests/privacy_helpers.py` | 75 |
| `tests/benchmark_privacy.py` | 161 |

Güncellenen mevcut dosyalar: `api/app.py` (privacy servis yaşam döngüsü + rota kaydı),
`api/database.py` (privacy tabloları). Eşlik eden belgeler:
`docs/PHASE5_ARCHITECTURE.md`, `docs/PRIVACY_THREAT_MODEL.md`.

Faz 5A'ya **ait olmayan** (2026-10-08 refactor'u, önceki listede yanlışlıkla vardı):
`src/crimsonweb/privacy.py`, `src/crimsonweb/scheduling.py`, `tests/test_privacy.py`,
`tests/test_scheduling.py` ve `audit.py`'deki `privacy.sanitize` entegrasyonu.

## 9. Bilinen eksikler ve sınırlar

- Ortak operatör token'ı kullanılır; **kullanıcı bazlı RBAC yok**.
- **Retention otomatik uygulanmaz** (`retention_enforced=false`): `expires_at`/retention
  yalnız metadata; otomatik silme/secure erasure bu fazda yok. Eski scan/discovery/audit
  geçmişi otomatik temizlenmez.
- HMAC pseudonymization disk şifreleme değildir; DB'yi okuyabilen IP adaylarını deneyebilir.
  OS/root compromise, ISP/AS izleme, küresel korelasyon ve header/TLS fingerprint bu fazın
  kapsamı dışıdır (5C lab tasarımına bırakıldı).
- `managed_egress` ve zorunlu interface henüz desteklenmez (gönderimden önce reddedilir).
- Performans sayıları mock transport ölçümüdür; gerçek ağ gecikmesini veya OS düzeyi
  korumayı temsil etmez.
- Çökme sonrası açık rezervasyonlar güvenli biçimde kapalı kalır; bütçe otomatik iade yok.

## 10. Faz 5B teknik planı (kod yok)

Secure Egress Engine, scope kararından **ayrı** bir route verifier gerektirir:
`EgressProfileManager`, `TrustedProxyConfiguration`, `EgressRouteVerifier`,
`ProxyCredentialVaultAdapter`, `ConnectionFailClosedGuard`, `EgressAuditService`.
Release ön koşulları: client→proxy peer, proxy→target DNS/peer, orijinal hostname/SNI,
certificate validation ve CNAME/IP scope doğrulamasının **her biri için ayrı kanıt**;
sabit onaylı trusted egress; ephemeral credential erişimi; fail-closed hata matrisi.
Açık proxy toplama/rotasyon/engel aşma yoktur; proxy failure direct fallback oluşturmaz —
gerekirse request reddedilir. Mevcut pinned direct transport sessizce proxy'ye dönüştürülmez.
Uygulama fail-closed kararı OS kill switch değildir; Windows WFP/OS filtreleme ayrı bir
fizibilite (admin elevation, imzalı kurulum, process/interface/DNS/v4/v6 filtre matrisi,
boot/crash recovery, emergency rollback) ister ve o geliştirilmeden genel IP koruması
ilan edilmez.

## 11. Durdurma kriteri

Faz 5A tamamlandı ve doğrulandı. **Faz 5B başlatılmadı** ve otomatik geçilmeyecek.
