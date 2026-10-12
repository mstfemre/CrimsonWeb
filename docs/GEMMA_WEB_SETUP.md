# Gemma ana analist ve kontrollü web yürütücüsü

12 Ekim 2026, Europe/Istanbul. Ana tercih `gemma4:26b`; kaynak açısından daha hafif
alternatif `qwen3.5:9b`. Model test kataloğundan seçim ve takip planı yapar;
kapsam, onay, istek bütçesi ve teknik kanıt kararlarını Python verir.
Modelin native tool-call çıktısı çalıştırılmaz; JSON önerisi doğrulanıp sabit araçlara bağlanır.

## Uygulanan kod

`AISettings.for_web_profile()` ve `CRIMSON_AI_PROFILE` iki yerel profil sunar:

| Profil | Model | Thinking | Context | Output | Timeout | Concurrency |
|---|---|---|---:|---:|---:|---:|
| `gemma-web` | `gemma4:26b` | false | 8192 | 4096 | 300 s | 1 |
| `qwen-web` | `qwen3.5:9b` | false | 8192 | 4096 | 300 s | 1 |

Profil tek başına AI'ı açmaz veya model yüklemez. `CRIMSON_AI_ENABLED=true`
ayrıca gerekir. Profilsiz eski varsayılanlar korunur. Bilinmeyen profil veya
geçersiz/boş explicit thinking ayarı servisi `invalid_configuration` ile kapatır.
Explicit ortam değişkenleri profil varsayılanlarının önüne geçer; bu bilinçli
uyumluluk davranışıdır. Yerel origin/model denetimleri değişmedi.

`scripts/Set-LocalAIProfile.ps1`, Python profil tanımından değerleri alır ve
yalnız mevcut PowerShell prosesinin AI değişkenlerini tam profile ayarlar.
API tokenını okumaz/göstermeyi amaçlamaz; hiçbir token değerini çıktıya yazmaz.
`.env` yazmaz, API başlatmaz, model yüklemez/indirmez. Manuel Qwen seçiminde de aynı
profil uygulanır; otomatik model geçişi yoktur. İki modeli aynı anda yüklemekten
kaçınmak için model değişiminde Ollama'daki önceki modelin bellekten çıktığı doğrulanmalıdır.
CrimsonWeb gate'i kendi çağrılarını sınırlar; başka uygulamaların Ollama çağrılarını kilitlemez.

`VerificationPlanCreate.require_model=true` ve CLI `web plan --require-model`
model seçimini zorunlu yapar. Eksik/hatalı model, uydurulmuş seçim veya boş model
planı fixed bir 409 Conflict üretir; operator planı oluşturulmaz. Hata mesajına
model yanıtı/exception içeriği konmaz. Takip planları flag'i devralır; store katmanı
flag'i düşüren veya strict planı `planner=operator` olarak yazan kayıtları reddeder.
Bu durum JSON row'larda saklanır; eski kayıtlar false varsayılanıyla okunur,
yeni migration gerekmez. Varsayılan false mevcut operator workflow'u korur.

## Kullanım

Proje kökünde, hazırlanmış virtualenv ve kurulu yerel Ollama ile:

```powershell
. ./scripts/Set-LocalAIProfile.ps1 -Profile gemma-web
# API yalnız bu ortamı devralarak yeniden başlatılırsa profili kullanır.
# Mevcut CRIMSON_API_TOKEN ve DB migration hazırlığı ayrıca gereklidir.
.venv\Scripts\python.exe -m uvicorn crimsonweb.api.app:app --app-dir src --host 127.0.0.1 --port 8000 --no-proxy-headers
```

Önceden tanımlanmış workspace, geçerli policy ve izinli query adlarıyla:

```powershell
.venv\Scripts\python.exe -m crimsonweb web plan --workspace <ws> --policy <policy> --openapi docs/examples/web_query_lab_openapi.json --catalog xss_reflection_probe --catalog sql_error_probe --catalog web_security_observation --max-tests 1 --require-model
```

Sonrasında [onay/execute/report/next iş akışı](WEB_TOP10_ENGINE.md) uygulanır.
Her child plan için yeni onay gerekir; en çok üç tur. Üretim model değişikliği
veya canlı hedef testi otomatik başlatılmaz. Gerçek proje DB'si bu teslimde
migrate edilmedi; API başlangıcındaki migration davranışı ayrıca dikkate alınmalıdır.

Qwen'i manuel seçmek için, önce yüklü Gemma'nın bellekte olmadığı doğrulanıp:

```powershell
. ./scripts/Set-LocalAIProfile.ps1 -Profile qwen-web
```

Çalışmakta olan API ortamı sonradan değişmez; yeni profil API yeniden başlatılırken
devralınır. PowerShell oturumunu kapatmak process ayarlarını kaldırır.

## Gerçek model doğrulaması ve kaynaklar

Ollama 0.40.2; mevcut kurulu modeller ve sentetik test yanıtları kullanıldı.
Yerel LLM gerçek, target transport MockTransport ve DNS FakeResolver'dır.
Üçüncü taraf hedef trafiği, model indirme/silme ve WAF bypass yoktur.

| Kontrol | Sonuç | Kanıt |
|---|---|---|
| Gemma ilk yedi senaryo: SQL/XSS seçim, üç tur, BOLA planı, bulgu/tarama/WAF | 7 geçti; 165,97 s | `reports/web_top10/gemma_local_flow.xml` |
| Son kodda `gemma-web` + strict üç tur dahil planlama | 4 geçti; 56,19 s | `reports/web_top10/gemma_strict_profile_verified.xml` |
| Son kodda native helper ile `gemma-web` bulgu/tarama/WAF analizi | 3 geçti; 117,92 s | `reports/web_top10/gemma_profile_analysis.xml` |
| Son kodda native helper ile `qwen-web` + strict planlama | 4 geçti; 24,17 s | `reports/web_top10/qwen_strict_profile_verified.xml` |
| Standart suite | 838 geçti, 0 başarısız, 8 opt-in deselected; 76,09 s | `reports/web_top10/standard_profiles_tests.xml` |
| Yeni profil/strict kontrolleri | 22 geçti; önceki 816 test korundu | `tests/test_local_web_ai_profiles.py` |
| İlgili değişen Python/test dosyalarında Ruff | Başarılı | Kontrol komutu aşağıda |
| Bütün repoda Ruff | 123 mevcut finding; başarısız | `reports/web_top10/profile_ruff_summary.json` |
| `compileall -q src tests` | Başarılı | Python derleme kontrolü |

Bir profil denemesinde **4 test başarısızdı**: model çağrısına ulaşılmadan
`Invalid thinking configuration`. Test komutundaki .NET environment setter,
silinmesi istenen değerleri boş string olarak bıraktı. Explicit boş ayarı reddeden
doğrulama korundu; komut gerçek `Remove-Item Env:...` ile düzeltildi ve tekrar
çalıştırma ayrı dosyada kaydedildi. Başarısız sonuç
`reports/web_top10/gemma_strict_profile.xml` içinde korunur. Native helper bu boş
değerleri geçerli profil değerleriyle değiştirir; davranış otomatik testte doğrulandı.

Gemma strict üç turunda generation süreleri **8,206 / 6,135 / 3,496 s**;
Qwen strict üç turunda **2,861 / 5,114 / 2,790 s**. Her testte üç farklı araç,
altı kontrollü GET, her tur yeni onay, bilinen kanıt ilişkileri ve dördüncü turun
reddi doğrulandı. Bu tekil süreler, eşleştirilmiş/sabit UUID'li yeni bir benchmark
değildir; genel hız veya zafiyet bulma üstünlüğü sonucu çıkarılmaz.

İlk Gemma çalışmasının son bölümünde 32 kaynak örneği alındı:

- Minimum sistem boş RAM: **0,393 GiB**.
- En yüksek örneklenen GPU belleği: **7782 MiB / 8188 MiB** (tüm GPU kullanımı).
- En yüksek örneklenen Ollama process working set toplamı: **11,933 GiB**.
- Örneklerde başka modelin aynı anda yüklü olduğu görülmedi.

Kaynak dosyası `reports/web_top10/gemma_flow_resources.json`.
Örnekleme suite başladıktan sonra başlatıldı; soğuk model yüklemesini kapsamaz.
Örneklenmiş maksimumlar gerçek peak garantisi değildir; diğer uygulamaların belleği
ve OS cache etkisi vardır. OOM/timeout görülmedi fakat **Gemma bu cihazda RAM'i
çok dar bırakır**. Yoğun günlük kullanımda Qwen alternatifi daha fazla pay bırakır.
8192 context'i dolduran stres testi yapılmadı. Gizlilik/kanıt kontrolleri modelin
her serbest teknik iddiasının doğru olduğunu kanıtlamaz; injection adayları hâlâ
candidate/unverified, JavaScript/DB erişimi doğrulanmış değildir.

## Kontrol komutları

```powershell
. ./scripts/Set-LocalAIProfile.ps1 -Profile gemma-web
$env:CRIMSON_TEST_OLLAMA = '1'
.venv\Scripts\python.exe -m pytest tests/test_web_top10_ollama.py tests/test_phase4c_ollama_integration.py tests/test_phase3_ollama_integration.py -q -o junit_family=xunit1
```

Standart kontrolleri profil helper'ı uygulanmamış, AI devre dışı olan ayrı bir
PowerShell oturumunda çalıştırın; gerçek testlerin ortamını unit suite'e taşımayın:

```powershell
.venv\Scripts\python.exe -m pytest -m "not ollama" -q
.venv\Scripts\python.exe -m ruff check src/crimsonweb/api/ai/provider.py src/crimsonweb/api/verification src/crimsonweb/web_cli.py tests/test_local_web_ai_profiles.py tests/test_web_top10_ollama.py
.venv\Scripts\python.exe -m compileall -q src tests
```

Eklenen dosyalar: bu belge, `scripts/Set-LocalAIProfile.ps1`,
`tests/test_local_web_ai_profiles.py`. Değiştirilenler: AI settings/provider modülü,
verification model/service/store, web CLI, gerçek üç turlu integration testi,
`.env.example`, README ve ilgili kullanım belgeleri. Ollama generation, kanıt
sözleşmesi, WAF durdurma ve DNS/pinned transport algoritmaları değişmedi.
