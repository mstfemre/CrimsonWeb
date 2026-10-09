# CrimsonWeb Faz 5A.1 — Denetim düzeltmeleri

`docs/AUDIT_PHASE5A.md` bulgularını kapatır. Yeni özellik yok, Faz 5B başlatılmadı.
Git commit/push/branch yapılmadı; tüm değişiklikler çalışma ağacında. Gemma 4 profili,
JSON Schema ve kanıt doğrulaması değişmedi. Üçüncü taraf hedefe istek gönderilmedi.

## 1. Yapılanlar

**Host allowlist** (`src/crimsonweb/api/hosts.py`, yeni). Saf ASGI middleware olduğu için
app seviyesindeki `authorize` bağımlılığının dışında kalan `/docs` ve `/openapi.json`
dahil her rotayı kapsar. Eşleşme kesindir: wildcard yok, suffix eşleşmesi yok, kanonik
olmayan yazımlar reddedilir (userinfo, path, zone-id, köşeli parantezsiz IPv6, geçersiz
port, eksik/çift/ASCII olmayan Host). Eşleşmeyen istek uygulamaya ulaşmadan `403
{"detail":"Host not allowed"}` alır; reddedilen değer yanıtta yankılanmaz.
- `CRIMSON_API_ALLOWED_HOSTS`, varsayılan `127.0.0.1,localhost,[::1]` (her port).
- `host:port` yazılırsa yalnız o port kabul edilir; portsuz Host http için 80, https için 443 sayılır.
- Geçersiz yapılandırma (`*`, boş liste, URL, köşeli parantezsiz `::1`) `create_app` sırasında
  `ValueError` ile durur (fail-closed).
- Token'sız geliştirme modunda da uygulanır.

**Token politikası** (`api/app.py`).
- `CRIMSON_API_TOKEN` tanımsız ya da yalnız boşluksa API lifespan başında `RuntimeError` ile
  açılmayı reddeder. İstisna yalnız tam olarak `CRIMSON_API_DEV_ALLOW_NO_TOKEN=1` ile tanınır;
  `true` veya `0` kabul edilmez.
- Dev modunda da yalnız loopback istemci kabul edilir. Token tanımlıysa bayrak etkisizdir.
- Derinlemesine savunma: lifespan atlanmış olsa bile (`authorize`) token ve bayrak yoksa 403 döner.
- Karşılaştırma artık byte'lar üzerinden `secrets.compare_digest` ile yapılıyor (zaman-sabit).
  Önceden ASCII dışı bir Bearer değeri `TypeError`'a, dolayısıyla 500'e yol açabiliyordu;
  şimdi 401 döner.
- Kontrol `create_app` yerine lifespan'da çünkü `app = create_app()` modül import'unda çalışıyor;
  oraya konsaydı token'sız ortamlarda import kırılırdı.

**Yedekli migration** (`api/database.py`).
- `Repository.initialize()`, mevcut ve **boş olmayan** bir dosya DB'si head'in gerisindeyse
  (`pending_upgrade()`) önce havuzdaki bağlantıları kapatır, sonra `backup_sqlite()` ile
  `<db>.<UTC-zaman-damgası>.bak` dosyasını ve varsa `-wal`/`-shm` eşlerini SQLite adlandırmasıyla
  kopyalar, ardından upgrade eder.
- Kopyalama hatası veya boyut uyuşmazlığı olursa kısmi yedek silinir ve `MigrationBackupError`
  fırlatılır; upgrade **yapılmaz**. Mevcut bir yedeğin üzerine asla yazılmaz.
- Yeni/boş/in-memory DB ve zaten head'deki DB'nin davranışı değişmedi (yedek alınmaz).
- Alınan yedek yolları `repository.backup_paths` içinde tutulur.
- Elle çalıştırılan `alembic upgrade` bu yedeği **almaz** (env.py değiştirilmedi).

**Doküman / yapılandırma.**
- `PHASE5A.md`: Faz 5A test sayısı 144 olarak düzeltildi; `privacy.py`, `scheduling.py`,
  `test_privacy.py`, `test_scheduling.py` ve `audit.py` entegrasyonu 5A listesinden çıkarıldı;
  kullanım örnekleri token/Host/Content-Type ile güncellendi.
- README ve `.env.example` yeni token/Host davranışını anlatıyor.
- `.gitignore` yedek dosyalarını (`*.sqlite.*.bak*`) dışarıda tutuyor.
- `AUDIT_PHASE5A.md`'ye origin `cve.py`/`test_cve.py` çatışma notu eklendi (Ek A); iki dosya
  **değiştirilmedi**.

**CI** (`.github/workflows/ci.yml`). Origin'deki dosyanın birebir kopyası; tek fark kurulumun
`.[full,api,dev]` olması ve buna dair yorum. Dosya yerelde **untracked**; bkz. §4.

## 2. Değişen / eklenen dosyalar

| Dosya | Değişiklik |
|---|---|
| `src/crimsonweb/api/hosts.py` | **Yeni.** Host allowlist + ASGI middleware |
| `src/crimsonweb/api/app.py` | Token politikası, byte compare_digest, middleware kaydı |
| `src/crimsonweb/api/database.py` | `MigrationBackupError`, `backup_sqlite`, `pending_upgrade`, yedekli `initialize` |
| `tests/test_phase5a1_hardening.py` | **Yeni.** 64 test |
| `tests/conftest.py` | Test Host'u `testserver` eklendi, dev bayrağı her testte temizleniyor, `dev_tokenless` fixture'ı |
| `tests/test_phase1_api.py`, `test_phase1_integration.py`, `test_phase4a_api.py` | Token'sız testler `dev_tokenless` ile açıkça opt-in |
| `tests/test_phase2_api.py`, `test_phase3_api.py` | Modül fixture'ı: token ayarlamayan testler açık dev modunda |
| `docs/PHASE5A.md`, `docs/AUDIT_PHASE5A.md`, `docs/PHASE5A1.md` | Düzeltme, çatışma notu, bu rapor |
| `README.md`, `.env.example`, `.gitignore` | Token/Host/yedek belgeleri ve ignore kuralları |
| `.github/workflows/ci.yml` | **Yeni (yerel).** `.[full,api,dev]` |

Mevcut testlerin hiçbir assertion'ı gevşetilmedi. Yapılan tek uyarlama, token'sız çalışan
testlerin artık zorunlu olan dev bayrağını açıkça istemesi; beklenen durum kodları aynı kaldı
(örn. loopback dışı istemciye 403, yanlış token'a 401). `testserver`, Starlette TestClient'ın
sentetik host'u olduğu için yalnız test ortamında allowlist'e ekleniyor. Üretim varsayılanının
onu reddettiği ayrıca test ediliyor.

## 3. Eklenen testler (64)

| Grup | Sayı | Kapsam |
|---|---|---|
| Host: varsayılan allowlist kabul | 5 | `127.0.0.1`, `:8000`, `localhost`, `LOCALHOST`, `[::1]:8000` |
| Host: ret × rota | 16 | 4 yabancı Host × `/health`, `/openapi.json`, `/docs`, `/api/v1/workspaces` |
| Host: token'sız modda da geçerli | 1 | loopback istemci + yabancı Host → 403 |
| Host: port kısıtı | 1 | 7 alt durum (http/https, 80 varsayılanı, yanlış port, IPv6) |
| Host: bozuk değerler | 15 | parser reddi + `allows()` false |
| Host: geçersiz yapılandırma | 6 | `create_app` fail-closed |
| Host: ham ASGI | 4 | eksik / çift / ASCII olmayan Host uygulamaya ulaşmaz |
| Token: başlamayı reddetme | 6 | {tanımsız, boşluk} × {bayrak yok, `true`, `0`} |
| Token: lifespan atlanırsa | 1 | 403 `API token required` |
| Token: dev bayrağı sınırları | 1 | yalnız loopback; token varsa bayrak etkisiz |
| Token: ASCII dışı Bearer | 1 | 500 yerine 401 |
| Migration: yeni ve boş DB | 1 | yedek yok, head |
| Migration: head'deki DB | 1 | yedek yok |
| Migration: eski DB | 1 | yedek 0002'de kalır, DB head'e çıkar |
| Migration: kopyalama hatası | 1 | upgrade yok, kısmi yedek yok |
| Migration: kesik kopya | 1 | boyut uyuşmazlığı → silinir, upgrade yok |
| Migration: WAL/SHM eşleri | 1 | SQLite adlandırmasıyla kopyalanır |
| Migration: üzerine yazmama | 1 | mevcut yedek korunur |

## 4. Doğrulama — öncesi / sonrası

| Ölçüm | Öncesi (5A) | Sonrası (5A.1) |
|---|---|---|
| Standart testler | 613 passed, 4 deselected, 0 failed | **677 passed, 4 deselected, 0 failed** (58.7 s) |
| Toplanan test | 617 | 681 (+64) |
| Ruff, değişen ve yeni dosyalar | — | `All checks passed!` |
| Ruff, depo geneli | 126 | **126** (yeni ihlal yok) |
| compileall | exit 0 | exit 0 |
| Alembic, temiz SQLite | 0001↔0005 temiz | 0001↔0005 temiz, `alembic check` drift yok |
| Gerçek DB kopyasında `initialize()` | — | 0002 → yedek (`.bak`, rev 0002) → 0005; **orijinal DB hash'i değişmedi** |
| Gemma 4 opt-in | 3/3, 147.88 s (aynı gün, denetim koşumu) | **Doğrulanamadı**: Ollama sunucusu kapalı (süreç yok, 11434 dinlemiyor) → 3 test "All connection attempts failed" ile başarısız |

Gemma notu: Bu testler `create_app`, Host middleware'i veya token yolunu kullanmıyor; yalnızca
in-memory `Repository` kuruluyor (yedek yolu tetiklenmez). Hata `provider.health()` bağlantı
aşamasında. Ollama başlatıldıktan sonra tek komutla yeniden doğrulanmalı (§5). Model
profili kodda değişmedi (`provider.py:51-59`, `from_env`).

Ek kontrol: Python 3.11 kurulu olmadığından CI matrisindeki 3.11, yalnız
`ast.parse(feature_version=(3, 11))` ile statik olarak kontrol edildi. Gerçek sözdizimi hatası
bulunmadı (tek uyarı `tests/test_discovery.py`'deki UTF-8 BOM, import'ta sorun değil). Bu
kontrol çalışma zamanı API farklarını yakalamaz; gerçek 3.11 koşumu CI'da görülecek.

## 5. Bilinen sınırlar

- **Gemma 4 bu fazda yeniden doğrulanmadı.** Ollama'yı başlattıktan sonra:
  `CRIMSON_TEST_OLLAMA=1 CRIMSON_AI_ENABLED=true CRIMSON_OLLAMA_MODEL=gemma4:26b
  CRIMSON_OLLAMA_THINK=false CRIMSON_AI_CONTEXT_TOKENS=8192 CRIMSON_AI_MAX_OUTPUT_TOKENS=4096
  CRIMSON_AI_TIMEOUT=300 CRIMSON_AI_MAX_CONCURRENCY=1 pytest -m ollama tests/test_phase3_ollama_integration.py`
- **CI dosyası untracked.** `git pull` origin'deki `ci.yml` ile çakışır ("untracked working tree
  file would be overwritten"). Çözüm: dosyayı kenara al → pull → tek satırı (`.[full,api,dev]`)
  yeniden uygula ya da commit'le.
- **CI hâlâ kırmızı olacak.** Origin'in `test_cve.py`'si yerel `cve.py` whitelist'iyle çelişiyor
  (AUDIT Ek A). Bu karar bilinçli olarak açık bırakıldı.
- **Gerçek DB hâlâ `0002_phase3`'te.** API'nin ilk açılışında artık otomatik yedek alınacak,
  ama bağımsız bir yedeği önceden elle almak yine önerilir. Yedek DB ile aynı klasöre yazılır
  (aynı disk). Disk arızasına karşı koruma sağlamaz.
- Yedek dosya düzeyinde kopyadır. Başka bir süreç aynı anda yazıyorsa boyut kontrolü bunu
  yakalayıp upgrade'i durdurur, ama tutarlı bir anlık görüntü garanti etmez. Kopyadan önce
  havuzdaki bağlantılar kapatılır.
- `/docs` ve `/openapi.json` izinli Host'tan token'sız erişilebilir (FastAPI bu rotalara
  app bağımlılığını uygulamıyor). Şema bilgisi yerel çağırana açık; bu fazda değiştirilmedi.
- Host allowlist DNS rebinding'e karşı derinlemesine savunmadır. Kimlik doğrulamanın yerine
  geçmez. Token hâlâ ortak operatör token'ı; kullanıcı bazlı RBAC yok.
- Ters proxy arkasında çalışıyorsa proxy'nin ilettiği `Host` allowlist'e eklenmeli.
  `--no-proxy-headers` önerisi geçerli.

## Özet

- Host allowlist: kesin eşleşme, `/docs` ve `/openapi.json` dahil tüm rotalarda, token'sız modda
  da geçerli, geçersiz yapılandırmada fail-closed.
- Token zorunlu: token yoksa API açılmıyor; istisna yalnız `CRIMSON_API_DEV_ALLOW_NO_TOKEN=1` ve
  yalnız loopback. ASCII dışı Bearer artık 500 değil 401.
- Migration: head'in gerisindeki mevcut DB önce zaman damgalı olarak (WAL/SHM dahil)
  yedekleniyor; yedek başarısızsa upgrade yapılmıyor. Yeni ve boş DB davranışı aynı.
- Testler: 613 → **677 passed** (+64 yeni), 0 failed. Ruff depo geneli 126 → 126. compileall temiz.
  Migration zinciri temiz; gerçek DB kopyasında yedek ve upgrade uçtan uca doğrulandı.
- Gemma 4: Ollama kapalı olduğu için **doğrulanamadı**. Değişen kod bu testin yolunda değil;
  yeniden koşum komutu §5'te.
- `PHASE5A.md` düzeltildi (144 test, dosya listesi, kullanım örnekleri). CI `.[full,api,dev]`.
  `cve.py` çatışması dokunulmadan AUDIT Ek A'da belgelendi.
