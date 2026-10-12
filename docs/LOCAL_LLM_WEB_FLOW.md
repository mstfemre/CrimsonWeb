# Gerçek yerel LLM ile kontrollü web test akışı

12 Ekim 2026, Europe/Istanbul. Bu tur mevcut test kataloğunun gerçek Qwen modeliyle
uçtan uca çalışmasını doğrular. Yeni saldırı ailesi veya genel exploit yürütücüsü eklenmedi.
Üretim modeli, kanıt doğrulaması, scope kontrolleri ve operatör onayı korunmuştur.

Bu ilk Qwen doğrulamasından sonra Gemma, seçilebilir profiller ve strict model
planlama da doğrulandı. Güncel teslim ve 838 test sonucu
[GEMMA_WEB_SETUP.md](GEMMA_WEB_SETUP.md) içindedir; aşağıdaki sayılar ilk çalışmanın kaydıdır.

## Gerçekte çalıştırılan akış

Yerel Ollama 0.40.2, `qwen3.5:9b`, Q4_K_M kullanıldı. `/api/show` çıktısı
thinking için `false` ve `true` desteği, varsayılan olarak `true` bildirdi.
Testler açıkça `thinking=false`, context 8192, output 4096, timeout 300 ve
concurrency 1 gönderdi. `.env` veya üretim varsayılanları değiştirilmedi.

Ollama yalnız loopback adresinde başlatıldı; yalnız kurulu Qwen yüklendi.
Model indirilmedi veya silinmedi; Gemma aynı anda çalıştırılmadı.
Model gerçek, hedef yanıtları `httpx.MockTransport`, DNS ise kontrollü FakeResolver'dır.
`lab.test` adresi internette çözülmedi; üçüncü taraf hedefe trafik gönderilmedi.

Yeni `test_real_model_drives_three_approved_rounds_against_synthetic_transport`
testi şu sözleşmeyi doğrular:

1. Gerçek model üç araçlık katalogdan bilinen endpoint ve kanıt referanslarıyla test seçer.
2. Her plan `awaiting_approval` olur; onaysız execution reddedilir ve hedef isteği oluşmaz.
3. Operatör onayından sonra deterministik yürütücü kapsam denetimiyle testi çalıştırır.
4. Model yalnız fixed outcome/confidence kodlarını alır ve kalan bir aracı seçer.
5. Üç tur sonunda farklı üç araç çalışır; toplam altı sentetik GET görülür.
6. Dördüncü tur reddedilir. Operator fallback, gerçek model başarısı sayılmaz.

Sentetik sonuçlar: `html_injection_suspected`, `sql_injection_suspected`,
`configuration_observed`. Injection bulguları `candidate / unverified` kalır.
Her bulgunun gözlem referansı kayıtlı kanıta bağlanır. Script execution ve DB veri
erişimi doğrulanmaz. Ham body, SQL hata metni veya inert HTML payload modele
verilmedi; bunlar raporda da yer almadı. Test raporu yalnız model adı, tur süreleri
ve hedef istek sayısını ek metadata olarak saklar.

## Sonuçlar

| Gerçek Qwen testi | Sonuç | Test duvar süresi |
|---|---|---:|
| SQL testinin endpoint/query/kanıt seçimi | Başarılı | 1,649 s |
| XSS testinin endpoint/query/kanıt seçimi | Başarılı | 1,477 s |
| Üç onaylı tur: seçim → execution → gözlem → takip | Başarılı | 12,639 s |
| Mevcut BOLA planlama | Başarılı | 1,612 s |
| Mevcut bulgu analizi, Türkçe ve kanıt doğrulaması | Başarılı | 44,412 s |
| Mevcut tam tarama analizi, Türkçe ve kanıt doğrulaması | Başarılı | 63,891 s |
| Mevcut WAF analizi, Türkçe ve kanıt doğrulaması | Başarılı | 44,162 s |

**7 passed, 0 failed**, toplam 170,67 saniye. JUnit kanıtı:
`reports/web_top10/qwen_local_flow.xml`. Üç turda yalnız model generation süreleri
3,254 / 5,918 / 3,186 saniyedir; toplam test süresi DB, guard ve fixture işlemlerini
de içerir. Sıcak model ölçümleridir. Önceki ayrı soğuk başlangıç çalışmasında SQL
planlama testi 10,351 saniye sürdü; bu süre salt model yükleme süresi değildir.

Bu küçük sentetik küme başarı oranını genel web güvenliği doğruluğuna dönüştürmez.
Dil kontrollerinin geçmesi kapsamlı Türkçe editoryal kalite değerlendirmesi değildir.
Yeni döngü Gemma ile bu turda denenmedi; geçmiş karşılaştırma
[QWEN_VS_GEMMA.md](QWEN_VS_GEMMA.md) geçerliliğini kendi veri kümesiyle sınırlar.
Sekizinci opt-in model karşılaştırma testi bu çalıştırmada seçilmedi.

`/api/ps` anlık gözleminde Qwen için model belleği 5,939 GiB, VRAM 5,213 GiB;
Windows boş fiziksel RAM örnekleri yaklaşık 10,5–11,5 GiB idi.
Bunlar anlık örneklerdir: peak ölçümü veya yalnız CPU RAM tahsisi değildir.
GPU kullanımı ve yükleme süresi için yeni ayrıntılı benchmark yapılmadı.

Standart suite **816 passed, 0 failed, 8 deselected**, 87,67 saniye.
JUnit: `reports/web_top10/standard_tests.xml`. Yeni test dosyasında Ruff ve
`src/tests` compileall başarılı. Repo genelindeki önceki 123 Ruff bulgusu giderilmedi.
İki mevcut uyarı görüldü: standart suite Starlette/httpx deprecation;
gerçek suite `record_property` ile xunit2 metadata uyumluluk uyarısı. Süre
metadata'sı XML'de mevcut, test sonuçları başarılıdır.

## Tekrar çalıştırma

Yerel Ollama daemon'u açık ve model kurulu olmalıdır. Aşağıdaki değişkenler yalnız
bu PowerShell oturumuna uygulanır; üretim `.env` dosyasını değiştirmez.

```powershell
$env:CRIMSON_TEST_OLLAMA = '1'
$env:CRIMSON_AI_ENABLED = 'true'
$env:CRIMSON_OLLAMA_MODEL = 'qwen3.5:9b'
$env:CRIMSON_OLLAMA_THINK = 'false'
$env:CRIMSON_AI_CONTEXT_TOKENS = '8192'
$env:CRIMSON_AI_MAX_OUTPUT_TOKENS = '4096'
$env:CRIMSON_AI_TIMEOUT = '300'
$env:CRIMSON_AI_MAX_CONCURRENCY = '1'
.venv\Scripts\python.exe -m pytest tests/test_web_top10_ollama.py tests/test_phase4c_ollama_integration.py tests/test_phase3_ollama_integration.py -q -o junit_family=xunit1 --junitxml=reports/web_top10/qwen_local_flow.xml
```

`-o junit_family=xunit1` tekrar çalıştırmada ek metadata uyarısını önler; yukarıdaki
ölçülen çalışma varsayılan xunit2 ile yapıldı. Mevcut API'yi bu oturumda AI açık
başlatmak bu değişkenleri kullanır; gerçek proje DB'si için önce migration durumu
incelenmelidir. Bu test teslimi gerçek proje DB'sine migration uygulamadı.
Operatör CLI iş akışı ve desteklenen araçlar [WEB_TOP10_ENGINE.md](WEB_TOP10_ENGINE.md)
içindedir.

## Sonraki geliştirme

Bir sonraki adım, aynı guard ve taze onay şartıyla kontrollü bir yerel HTTP laboratuvarında
socket/TLS transport doğrulamasıdır. Sonrasında bağımsız browser kanıtı gerektiren
XSS değerlendirmesi ve iki test hesabıyla daha geniş BOLA rol matrisi ayrı modüller
olarak ele alınabilir. Bu teslim bunların tamamlandığını iddia etmez.
