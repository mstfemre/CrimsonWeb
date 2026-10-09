# CrimsonWeb — Gemma model karşılaştırması

Tarih: 9 Ekim 2026 (Europe/Istanbul). **Gemma 4 26B, thinking kapalı / 8K bağlam
profilinde mevcut Faz 3.5 sözleşmesiyle üç senaryonun tamamını geçti.** Varsayılan
thinking açık profilde bulgu ve WAF denemeleri çıktı sınırına ulaştı. Mevcut
güvenlik doğrulaması gevşetilmedi. Faz 4 başlatılmadı.

## Ortam ve ölçüm kapsamı

- Windows, Intel Core i7-13650HX (14 çekirdek / 20 mantıksal işlemci).
- RTX 4060 Laptop GPU; nvidia-smi 8188 MiB toplam VRAM bildiriyor.
  140W TGP kullanıcı tarafından belirtilmiştir; çalışma sırasındaki güç ayrıca ölçülür.
- Kullanıcının 32 GB RAM yapılandırması; Windows fiziksel bellek sayacı
  33.955.192.832 byte bildiriyor.
- Yerel Ollama 0.40.1, `http://127.0.0.1:11434`; hiçbir model indirilmedi.
- `gemma4:26b`: GGUF, Q4_K_M, yerel metadata 25.2B,
  dosya boyutu 18.731.025.629 byte; digest
  `001e5dafc3c77684c2307ebc6ab8e336e10c9b18eca52acf547d72fc83c3ca8c`.
- Gemma 4 `/api/show` thinking değerleri `[false, true]`, varsayılan `true`.
  Gemma 3'te thinking metadata'sı yok, completion/vision yetenekleri bildiriliyor.
- Gerçek Gemma 3 karşılaştırmasında çalışan model digest'i
  `c30276f7dffec93a536d283e15088990454b8d21cf180a3d6eea4959e4147291`;
  GGUF/Q4_K_M, 4.3B, llamacpp. `/api/tags` aynı `gemma3:4b` adı için bir başka
  digest/runner da listeliyor; karşılaştırma gerçekten çalışan digest'e dayanır.

Mevcut `test_real_local_ollama_structured_analysis` üç senaryosuyla kullanıldı:
tek Referrer-Policy bulgusu; iki bulgu + TLS + WAF içeren tam tarama; tek WAF
olayı. Kayıtlar SQLite içinde sentetik laboratuvar verisidir. TLSv1.3,
10 gün sonra biten doğrulanmış sertifika ve HTTP 429 / Retry-After 60 saniye
kanıtları bulunur. Tarama hedeflerine ağ isteği veya engel aşma yapılmaz.

Faz 3.5'in JSON Schema, tam kimlik anahtarları, sunucuda referans oluşturma,
maskelenmiş çıktı, iddia/injection/referans/dil kontrolleri aynen korunur.
Model yorumları teknik kanıt veya doğrulanmış zafiyet olarak kabul edilmez.

## Ölçüm yöntemi

`tests/ollama_benchmark.py`, isteğe bağlı pytest gözlemcisidir. Gerçek üretim
sağlayıcısına gönderilen şemayı veya isteği değiştirmez. Aynı gerçek testin
sonucu ile ölçüm sonucu birlikte kaydedilir.

- Duvar saati: `provider.generate()` başlangıç/bitişi; HTTP çağrısı ve
  sağlayıcı yanıtı işlemesi dahil. Ön/son donanım örneklemesi hariç.
- Ollama: load/prompt-eval/eval/total süreleri (API nanosecond), token sayıları,
  düşünme/cevap karakter sayıları ve tamamlanma/token sınırı bayrakları.
- Yaklaşık iki saniyede bir Windows GlobalMemoryStatusEx ile sistem RAM'i;
  Ollama/llama süreçlerinin working set ve private commit sayaçları.
- nvidia-smi ile toplam GPU VRAM, GPU kullanım yüzdesi, güç ve sıcaklık.
- `/api/ps` ile model size/size_vram/context/digest metadata'sı.

Working set yerleşik süreç belleğidir; private commit RAM ile aynı şey değildir.
Süreç working set toplamı paylaşılan sayfaları iki kez sayabilir. Sistem/GPU
ölçümleri diğer açık uygulamaları da kapsar; tek modele atfedilen bellek olarak
sunulmaz. Ayrık örnekler gerçek tepeyi kaçırabilir. Sistem izole edilmediği ve
her profil/senaryo bir kez çalıştırıldığı için değerler istatistiksel hız/kalite
garantisi değildir. `stream=false` nedeniyle ilk token gecikmesi ölçülmez.
Bellek tablosu, istenen modelin `/api/ps` içinde yüklü göründüğü örnekleri
kullanır. Başka modelden geçişte eski modelin başlangıç örneği yeni modele
atfedilmez. Ham sayaçların tümü ölçüm dosyalarında bulunur. GiB=1024³ byte,
MiB=1024² byte; GPU ortalaması örnek ortalamasıdır.

Ham prompt, ham model yanıtı veya thinking metni dosyaya/loga yazılmaz.
Dil incelemesinde yalnız testin doğruladığı ve maskelediği sentetik görüş
alanları kullanılır. Hata kaydında güvenli kod/kimlik/sayılar bulunur.

Önemli metadata farkı: ilk Gemma 4 denemesinde [`/api/ps`](https://docs.ollama.com/api/ps) size yaklaşık
1,23 GiB ve size_vram yaklaşık 0,93 GiB iken sistem sayaçları model sürecinde
yaklaşık 15–16 GiB working set, GPU genelinde 7,3–7,5 GiB gösterdi.
Bu API alanları ölçülen toplam bellekle uyuşmuyor; backend raporlama farkının
nedenini kesinleştirmeden CPU/GPU offload oranı bunlardan hesaplanmaz.
WAF'ın varsayılan denemesinde yeniden yüklemeden sonra size yaklaşık 14,11
GiB'ye değişti; size_vram yine yaklaşık 0,93 GiB kaldı. Bu rapor için tutarlı
karşılaştırma verisi Windows/nvidia-smi sayaçlarıdır; `/api/ps` metadata'sı ayrı tutulur.

## Thinking ve başarısızlığın kök nedeni

Mevcut varsayılan 16384 bağlam / 4096 çıktı sınırlarıyla, benchmark için
300 saniye çağrı sınırı seçildi (ürünün varsayılan 90 saniyesi korunuyor):

- Bulgu denemesi 189,23 saniyede başarısız oldu.
- Model eşleşti ve yanıt tamamlandı; `done_reason=length`, `eval_count=4096`.
- Thinking alanı 12018 karakter, JSON content alanı **0** karakterdi.
- `incomplete_provider_response` doğru biçimde üretildi. Kimlik doğrulaması
  aşamasına geçilemedi; bu, Faz 3.5 kanıt bağlama hatasının tekrarı değildir.
- Sistem kullanılabilir RAM'i bir örnekte 215.896.064 byte'a (yaklaşık 206 MiB)
  düştü; bu profilde ciddi bellek baskısı ölçüldü.
- Tam tarama aynı varsayılan profilde 162,07 saniyede başarılı oldu;
  6732 düşünme karakteri ve 3102 JSON karakteriyle toplam 3556 token üretildi.
  Dolayısıyla şema uyumluluğu var; thinking bütçesi sonucu girdiye göre değiştiriyor.
- WAF 238,29 saniyede aynı nedenle başarısız oldu: 12315 thinking karakteri,
  sıfır JSON karakteri, 4096 eval token ve length sonlandırması. Ollama ayrıca
  134,56 saniye load_duration bildirdi. Yeniden yüklemenin kesin nedeni bu
  sayaçlardan belirlenemiyor; JSON başarısızlığının kanıtlanan nedeni çıktı
  bütçesinin thinking tarafından tüketilmesidir.
- Yalnız thinking'i kapatan 16K bulgu kontrolü 26,37 saniyede geçti:
  sıfır thinking karakteri, 2297 JSON karakteri, 775 çıktı tokenı.
  Bağlam değiştirilmeden tamamlanmış JSON elde edilmesi kök neden teşhisini destekler.

[Ollama thinking sözleşmesinde](https://docs.ollama.com/capabilities/thinking)
`message.thinking` ile `message.content` ayrı kanallardır; `think=false`
destekleyen modellerde düşünme kapatılabilir. CrimsonWeb yalnız content
alanını doğrular. Thinking metni analize eklenmez.

Bu ölçüm nedeniyle `CRIMSON_OLLAMA_THINK=default|true|false` desteği eklendi.
Varsayılan `default`, HTTP isteğine think eklemez ve önceki davranışı korur.
Geçersiz değer sessizce açılmaz; yapılandırma hatasıdır. JSON Schema ve bütün
güvenlik kontrolleri değişmez. Optimize profilde thinking kapatılır ve bağlam
8192 olarak ayrıca ölçülür; çıktı sınırı artırılmaz.

## Türkçe kalite incelemesi

Varsayılan tam tarama çıktısı Türkçe ve kısa: Referrer-Policy eksikliği,
sertifikanın 10 gün içinde bitmesi ve HTTP 429 gözlemi doğru ayrılmıştır.
429'un nedenini kesin WAF/IP engeli diye nitelememiş, günlük incelemesini
önermiştir. Örnek: “HTTP 429 yanıtı gözlemlendi ancak neden belirsizdir.”

İki bulguda belirsizliğin yalnız “düşük” olarak ifade edilmesi açıklayıcı
değildir. Şema bunu kabul eder; semantik kalite kusuru olarak kaydedilir.

| Ölçüt | Gemma 3 4B, 8K | Gemma 4 26B, thinking kapalı / 8K |
|---|---|---|
| Türkçe ifade | Türkçe, daha uzun; “Sertifayı” gibi yazım ve cümle kusurları var | Daha kısa, akıcı; başlık/protokol adlarını koruyor |
| Kanıta bağlılık | `incomplete` yönlendirme sonucunu eksik yapılandırma gibi yorumluyor; TLS 1.3'ten eski protokol riski çıkarıyor | Sertifika 10 gün bilgisini ve HTTP 429'u doğru ayırıyor; WAF/uygulama kaynağını belirsiz bırakıyor |
| WAF iddiası | Özette yalnız HTTP kaydı olmasına rağmen WAF kaynağını kesinleştiriyor | Kural kimliğinin bulunmadığını ve kaynağın net olmadığını söylüyor |
| Gereksiz sonuç çıkarımı | Sertifika süresi dolmasını kötü amaçlı yazılım bulaşmasıyla bağlayan desteklenmeyen iddia var | “TLS yapılandırması günceldir” ifadesi tek TLS gözleminden daha geniş bir sonuç; Referrer-Policy etkisini “tarayıcı geçmişi” ile aşırı genelleştiriyor |
| Belirsizlik | Risklerin bazıları kanıtı aşan biçimde açıklanıyor | Bulgu yorumunda “Belirsizlik yok” fazla genel; gözlenen başlık yokluğu kesin olsa da uygulama etkisi belirsiz |
| Detay kapsamı | İncelenen WAF yorumunda Retry-After 60 saniye ayrıntısı yok | İncelenen WAF yorumunda aynı ayrıntı yok |

Başarılı optimize Gemma 4 tam tarama yorumundan örnek:
“Hatanın WAF kaynaklı mı yoksa uygulama kaynaklı mı olduğu belirsizdir.”
Gemma 3'ün “eski TLS protokollerine karşı savunmasızlık” yorumu verilen
TLSv1.3 gözleminden çıkarılamaz. HTTPS sonucu `incomplete`, yönlendirmenin
yokluğunu kanıtlamaz. Bu örnekler için Gemma 4'ün teknik dili daha ölçülüydü;
bu küçük veri setinden genel üstünlük sonucu çıkarılmaz.

Her iki modelde Türkçe karakter/işaret kontrolü geçti. Optimize Gemma 4'te
İngilizce dil işareti sayısı üç senaryoda sıfırdı; İngilizce teknik terim/enum
kullanımı doğal dilin İngilizce olması sayılmaz. Bu denetim akıcılık veya
teknik doğruluk garantisi değildir. Kimlik/şema doğrulaması, açıklamaların tüm
semantik iddialarını doğrulamaz; insan incelemesi ve `model_claims_verified=false`
korunmalıdır. Bu görevde kalite kusurlarını gizlemek için kontrol/prompt değiştirilmedi.

## Karşılaştırma ve nihai sonuçlar

Önceki Faz 3.5 kaydı: 228 standart test ve Gemma 3 4B üzerinde üç gerçek test
başarılı; gerçek paketin toplamı 58,32 saniye. Bu tarihsel koşuda senaryo başına
süre ve RAM/GPU örnekleri tutulmadığı için geçmiş belleği tahmin edilmeyecektir.
Bu çalışma başlangıcında 228 standart test tekrar başarılı, üç opt-in test atlandı.

### Senaryo sonuçları ve süreler

Tüm profillerde temperature=0, çıktı sınırı 4096, timeout 300 saniye;
çağrılar sırayla yapıldı. Süreler aşağıda provider duvar saati ölçümüdür.

| Model / profil | Bulgu | Tam tarama | WAF | Başarı |
|---|---:|---:|---:|---:|
| Gemma 4, varsayılan thinking açık, 16K | Başarısız / 189,23 sn | Başarılı / 162,07 sn | Başarısız / 238,29 sn | 1/3 |
| Gemma 4, thinking kapalı, 16K kontrol | Başarılı / 26,37 sn | Çalıştırılmadı | Çalıştırılmadı | 1/1 |
| Gemma 3, model varsayılanı, 8K karşılaştırma | Başarılı / 21,37 sn | Başarılı / 22,58 sn | Başarılı / 14,41 sn | 3/3 |
| Gemma 4, thinking kapalı, 8K optimize | Başarılı / 55,28 sn | Başarılı / 45,99 sn | Başarılı / 25,47 sn | 3/3 |

Gemma 3 paket süresi 60,14 sn; optimize Gemma 4 paket süresi 128,82 sn.
İlk çağrılar yükleme içeriyor: Gemma 3 6,74 sn, optimize Gemma 4 29,74 sn.
Takip eden çağrılarda load_duration yaklaşık 0,03–0,04 sn. Bu nedenle ilk
çağrıyı sıcak model hızının doğrudan karşılaştırması olarak kullanmayın.
Gemma 4 bu koşuda daha yavaştı; daha az token üretmesine rağmen CPU/GPU/RAM
yerleşimi ve model yüklemesi farklıdır. Kesin darboğaz için ayrı profiler gerekir.

| Model, 8K profil | Senaryo | Prompt token | Eval token | JSON karakter | Thinking karakter | Bulgu/WAF yorumu |
|---|---|---:|---:|---:|---:|---|
| Gemma 3 | Bulgu | 2376 | 951 | 3279 | 0 | 1 / 0 |
| Gemma 3 | Tam tarama | 3012 | 1460 | 4369 | 0 | 2 / 1 |
| Gemma 3 | WAF | 2443 | 947 | 2888 | 0 | 0 / 1 |
| Gemma 4 | Bulgu | 2344 | 783 | 2336 | 0 | 1 / 0 |
| Gemma 4 | Tam tarama | 2996 | 1358 | 3800 | 0 | 2 / 1 |
| Gemma 4 | WAF | 2467 | 677 | 2225 | 0 | 0 / 1 |

Her başarılı senaryoda beklenen ve dönen tam bulgu/WAF kimlik kümeleri eşleşti.
Birincil referanslar sunucuda aynı anahtardan oluşturuldu; eksik/fazla/değişmiş
kimlik kabul edilmedi. Diğer referans dizileri, tekrar, TLS kapsamı, dil,
tamamlanma ve mevcut içerik güvenliği kontrollerinden geçti. Başarısız varsayılan
iki senaryoda JSON olmadığı için referans doğruluğu **değerlendirilemedi**.

### Bellek, GPU ve güç

İstenen modelin yüklü göründüğü örneklerdeki tepe değerler; GPU kullanımında
ortalama/tepe yüzdesi. Bunlar sistem/süreç sayaçlarıdır, özel model tahsis ölçüsü değildir.

| Profil / senaryo | Sistem RAM tepe GiB | Ollama/llama WS tepe GiB | Private commit tepe GiB | GPU VRAM tepe MiB | GPU ort./tepe % | En az boş RAM GiB |
|---|---:|---:|---:|---:|---:|---:|
| Gemma 4 varsayılan / Bulgu | 31,42 | 16,11 | 23,55 | 7726 | 37,4 / 99 | 0,20 |
| Gemma 4 varsayılan / Tam tarama | 30,99 | 16,44 | 24,65 | 7725 | 38,1 / 99 | 0,63 |
| Gemma 4 varsayılan / WAF | 28,35 | 14,63 | 34,05 | 7768 | 38,1 / 99 | 3,28 |
| Gemma 4 kapalı 16K / Bulgu | 28,91 | 15,35 | 22,50 | 7743 | 41,1 / 99 | 2,72 |
| Gemma 3 8K / Bulgu | 13,98 | 1,29 | 5,66 | 5013 | 94,2 / 95 | 17,65 |
| Gemma 3 8K / Tam tarama | 14,42 | 1,69 | 6,03 | 5206 | 90,7 / 95 | 17,21 |
| Gemma 3 8K / WAF | 14,71 | 2,12 | 6,45 | 5083 | 94,6 / 95 | 16,91 |
| Gemma 4 kapalı 8K / Bulgu | 27,14 | 14,49 | 21,59 | 7786 | 42,9 / 99 | 4,49 |
| Gemma 4 kapalı 8K / Tam tarama | 28,67 | 15,15 | 22,25 | 7780 | 49,9 / 99 | 2,95 |
| Gemma 4 kapalı 8K / WAF | 29,04 | 15,78 | 22,92 | 7698 | 45,1 / 99 | 2,58 |

WAF varsayılan private commit'in fiziksel RAM'i aşması, 34 GiB'nin yerleşik
RAM tüketimi olduğu anlamına gelmez; commit ve working set farklı sayaçlardır.
Optimize Gemma 4 GPU güç tepeleri sırasıyla 47,69 / 50,10 / 52,95 W, sıcaklık
tepeleri 60 / 65 / 65 °C. Gemma 3 güç tepeleri 90,50 / 94,44 / 95,71 W,
sıcaklık tepeleri 58 / 65 / 69 °C. 140W TGP'nin bu testlerde kullanıldığı
iddia edilmez. Gemma 4'ün daha düşük ortalama GPU kullanımı ve yüksek host RAM
tüketimi hibrit çalışmayla uyumludur; doğrulanmış kesin offload oranı yoktur.

8K bağlam, bu paketlere yeterliydi ve çıktı sınırı 4096 olarak korundu.
Thinking kapalı 16K/8K bulgu örneklerinde WS 15,35/14,49 GiB, private commit
22,50/21,59 GiB ölçüldü; farklı yükleme/arka plan koşulları nedeniyle yalnız
bağlam değişikliğinin etkisi diye yorumlanmaz. GPU tepesinde düşüş görülmedi.
8192 küresel varsayılan yapılmadı; büyük kanıt paketleri ayrıca ölçülmelidir.

### Teslim ve kalite kontrolü

- Önceki 228 standart testin tamamı korundu; **235 standart test başarılı**
  (thinking ayarı için 7 yeni regresyon). Varsayılan pakette 3 gerçek test atlandı.
- Gerçek test çağrıları toplam 10: 8 başarılı, 2 varsayılan thinking/token-sınırı
  başarısızlığı. Gemma 3 karşılaştırması ve Gemma 4 optimize profilinin her biri 3/3.
- API/Faz 1/2/3/3.5, yeni benchmark gözlemcisi ve testleri için Ruff başarılı;
  src/tests compileall başarılı. Mevcut Starlette TestClient deprecation uyarısı sürüyor.
- Yeni dosyalar: `tests/ollama_benchmark.py`, `tests/test_model_benchmark.py`,
  `docs/MODEL_BENCHMARK.md`.
- Güncellenenler: `provider.py`, `test_phase3_provider.py`, `.env.example`, `README.md`.
  `security.py`, `contract.py`, teknik taramalar, API çıktı sözleşmesi ve migration'lar değişmedi.

Ölçüm kayıtları (ham prompt/yanıt/thinking içermez):

- [Gemma 4 varsayılan bulgu](../reports/model_benchmark/gemma4_default.json)
- [Gemma 4 varsayılan tam tarama/WAF](../reports/model_benchmark/gemma4_default_context_scenarios.json)
- [Gemma 4 thinking kapalı 16K kontrol](../reports/model_benchmark/gemma4_no_thinking_16k.json)
- [Gemma 3 karşılaştırması](../reports/model_benchmark/gemma3_comparison.json)
- [Gemma 4 optimize](../reports/model_benchmark/gemma4_optimized.json)

Bu donanımda doğrulanan Gemma 4 profili: thinking false, bağlam 8192, çıktı
4096, timeout 300, seri işler. API için eşzamanlı iş sınırı 1 önerilir;
bu benchmark iki paralel 26B işi test etmedi. Teknik güvenlik kontrolleri
aynen uygulanmaya devam eder; başarısız yanıt otomatik tamir edilmez veya yeniden denenmez.

## Yeniden çalıştırma

Yeni bağımlılık veya migration gerekmiyor. Windows gözlemcisi standart kütüphane
ve kurulu nvidia-smi kullanır; erişilemeyen sayaçlar sıfır kabul edilmez.

```powershell
$env:PYTHONPATH = 'tests;src'
$env:CRIMSON_TEST_OLLAMA = '1'
$env:CRIMSON_AI_ENABLED = 'true'
$env:CRIMSON_OLLAMA_MODEL = 'gemma4:26b'
$env:CRIMSON_OLLAMA_THINK = 'false'
$env:CRIMSON_AI_CONTEXT_TOKENS = '8192'
$env:CRIMSON_AI_MAX_OUTPUT_TOKENS = '4096'
$env:CRIMSON_AI_TIMEOUT = '300'
$env:CRIMSON_AI_MAX_CONCURRENCY = '1'
$env:CRIMSON_BENCHMARK_REPORT = 'reports/model_benchmark/gemma4_optimized.json'
.venv\Scripts\python.exe -m pytest -p ollama_benchmark tests/test_phase3_ollama_integration.py -q --tb=short
```

Gemma 3 karşılaştırması için model `gemma3:4b`, thinking `default` ve farklı
rapor dosyası seçilir. Varsayılan Gemma 4 profili için thinking `default`,
bağlam `16384` kullanılır. Profil değiştirmek otomatik retry değildir; her
deneme ayrı gerçek test sonucu olarak saklanır. Test gözlemcisi sabit loopback
11434 portunu ölçer; bu raporun kurulumuyla aynıdır.
