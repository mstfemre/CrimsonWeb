# CrimsonWeb — Qwen 3.5 9B / Gemma 4 26B

9 Ekim 2026, Europe/Istanbul. Yerel, sentetik kanıtlarla eşleştirilmiş benchmark.
Bu rapor Faz 4A sonrası model değerlendirmesidir; Faz 4B geliştirmesi içermez.

**24/24 gerçek test başarılı. Gemma sıcak analizlerde daha hızlı ve bu küçük veri
kümesinde teknik önerilerinde daha isabetli; Qwen daha hızlı yükleniyor ve çok daha
az sistem RAM'i gerektiriyor. Kalite odaklı ana analist tercihi Gemma'dır, ancak
32 GB sistemde ölçülen en düşük boş RAM yalnız 0,89 GiB olduğundan kullanım
kararı bu bellek sınırını dikkate almalıdır. İki modelde de anlam hataları vardır.**

## Ortam ve sözleşme

Windows 11 Pro 10.0.26300; Intel i7-13650HX, 14 çekirdek / 20 mantıksal işlemci;
RTX 4060 Laptop GPU, sürücü 617.14, NVIDIA sayacı 8188 MiB VRAM;
Windows fiziksel RAM sayacı 33.955.192.832 byte (kullanıcı yapılandırması 32 GB).
140W TGP kullanıcı beyanıdır; çalışma sırasındaki güç ayrı örneklenir.
Ollama 0.40.1, yalnız `http://127.0.0.1:11434`.

| Model | Yerel metadata | Quantization | Dosya boyutu |
|---|---|---|---:|
| `qwen3.5:9b` | 9.0B, GGUF, qwen35, llamacpp | Q4_K_M | 6.550.825.550 byte |
| `gemma4:26b` | 25.2B, GGUF, gemma4, llamacpp | Q4_K_M | 18.731.025.629 byte |

Digestler `reports/qwen_vs_gemma/environment.json` içinde kaydedildi.
İki model kurulu bulundu; indirme veya model dosyası silme yapılmadı.
Her iki `/api/show` yanıtı `thinking.values=[false,true]`, `default=true` bildiriyor.
Benchmark açıkça `think=false` gönderir. Bu keşif sözleşmesi
[Ollama thinking belgelerinde](https://docs.ollama.com/capabilities/thinking) açıklanır.

İki modelde aynı profil: context **8192**, maximum output **4096**, timeout **300 s**,
maximum AI concurrency **1**, `stream=false`, mevcut sağlayıcının `temperature=0`
ayarı. Testler sırayla çalışır. Üretimdeki model ve `.env` değiştirilmedi.
Model paketlerinin diğer sampling varsayılanları aynen korunur: Qwen top-k 20,
top-p 0.95, presence-penalty 1.5; Gemma top-k 64, top-p 0.95.
Bu, mevcut sağlayıcı altında model paketlerini karşılaştırır; yalnız model
mimarisinin etkisini izole eden bir deney değildir.

OllamaProvider, dinamik JSON Schema, izinli kanıt enumları/tam anahtarları,
sunucuda referans bağlama, maskeleme, iddia/dil/güvensiz çıktı denetimleri korunur.
Yeni UUID, konumsal/fuzzy eşleştirme, retry ile sonucu başarılıya dönüştürme yoktur.
AI yorumları `model_claims_verified=False` olarak kalır. Test başarısı, açıklamadaki
her teknik iddianın doğru olduğu anlamına gelmez.

## Veri ve deney tasarımı

Mevcut Faz 3.5 entegrasyon testinin bulgu, tam tarama ve WAF senaryoları kullanılır.
İsteğe bağlı gözlemci, yalnız benchmark bayrağı açıkken fixture UUID ve zamanlarını
`paired-models-v1` ile sabitler. Normal test fixture'ı değişmez. Her senaryoda
maskelenmiş giriş, şema ve sistem talimatı SHA-256 özeti karşılaştırılır; ham
prompt/yanıt/thinking veya gizli bilgiler saklanmaz.

Standart kanıtlar: eksik Referrer-Policy; 10 gün sonra bitecek, doğrulanmış sertifika;
gözlenen TLSv1.3 (`supported_versions_tested=False`); HTTP 429, geçerli
Retry-After **60 saniye**, kural kimliği yok. `https_redirect=incomplete`, bir
kontrolün tamamlanmadığını bildirir; yönlendirme yokluğunu kanıtlamaz.
`ScanReport.status=completed`, tüm alt kontrollerin tamamlandığı anlamına gelmez.

Ek `api_bola`, dört sentetik kaydı aynı tarama analizi sözleşmesinden geçirir:

| Kayıt | Beklenen yorum |
|---|---|
| 101: yok/geçersiz kimlik 401, geçerli kimlik 200 | Bu uç noktada gözlenen kimlik kontrolü çalışıyor; tüm API hakkında sonuç yok |
| 102: A kullanıcısı, B'ye ait nesne/veri, izin yok, 200 | Sağlanan laboratuvar kaydında yetkisiz kiracılar arası okuma var; yazma/yükseltme kanıtı yok |
| 103: A'nın B nesnesini okuması 403, veri yok; B 200 | Bu okuma engellenmiş; 403 tek başına WAF kanıtı değil |
| 104: HTTP 200, success=false, forbidden, data=null | Veri ifşası/IDOR/BOLA kanıtı yok; sahiplik ve izin kaydı eksik |

TLS/WAF kanıtı olmayan API fixture'ında TLS referansları ve WAF yorumları boş
olmalıdır. Bu ek senaryo API kimlik denetim kodunu çalıştırmaz, yalnız kayıt
yorumlamayı değerlendirir. Hiçbir uygulama/hedef/üçüncü tarafa istek gönderilmez.

Üç planlı tur: Qwen→Gemma, Gemma→Qwen, Qwen→Gemma. Her model grubu öncesinde
yüklü model `keep_alive=0` ile bellekten çıkarılır; `/api/ps` boşluğu doğrulanır.
İlk bulgu çağrısı soğuk model başlangıcı; tarama, WAF ve API/BOLA sıcak çağrılardır.
Soğuk başlangıç işletim sistemi disk önbelleğinin boşaltıldığı anlamına gelmez.
Başarısız vaka varsa korunur; başka planlı turda geçmesi ilk sonucu silmez.

## Ölçüm ve inceleme sınırları

Duvar süresi `provider.generate()` HTTP çağrısı ve sağlayıcı işlemesini kapsar;
ön/son donanım örneklemesi ve çıktı doğrulaması bu sürenin dışındadır. Ollama'nın
nanosecond load/prompt-eval/eval süreleri ve token sayıları ayrıca kaydedilir.
`stream=false` nedeniyle ilk token gecikmesi ölçülmez. Modeller farklı miktarda
metin ürettiğinden yanıt süresi ile token/s ayrı değerlendirilir.

Yaklaşık iki saniyede bir GlobalMemoryStatusEx, Ollama/llama süreçlerinin working
set/private commit, nvidia-smi GPU VRAM/kullanım/güç/sıcaklık ve `/api/ps` örneklenir.
GPU ve sistem RAM'i diğer uygulamaları da içerir. Working set yerleşik süreç
belleğidir; private commit fiziksel RAM değildir ve çalışma kümesi toplamı ortak
sayfaları iki kez sayabilir. Örneklenen tepe gerçek anlık tepeyi kaçırabilir.
Tabloda GiB=1024³ byte, GPU MiB=1024² byte kullanılır.

Teknik kalite, doğrulanıp maskelenmiş sentetik yorum alanlarının elle incelenmesine
dayanır. Şema/referans/dil testlerinden ayrı tutulur. Desteklenmeyen sonuçlar,
yanlış teknik öneriler ve atlanan kanıtlar ayrı belirtilir. Bu küçük veri kümesi
genel doğruluk/yanlış pozitif oranını, gerçek Bug Bounty başarısını veya
bağımsız kör değerlendirme sonucunu ölçmez.

## Sonuçlar

Gerçek ölçüm aralığı: **06:46:45–07:06:55 Europe/Istanbul**
(03:46:45–04:06:55 UTC). Üç turda her modelin her senaryosu üç kez çalıştı.
Tam ölçümler `reports/qwen_vs_gemma/*_round*.json`, hesaplanmış istatistikler
`summary.json`, yürütme sırası/çıkış kodları `run.json` içindedir.

| Senaryo | Qwen başarılı | Gemma başarılı | Qwen süre medyanı [min–max], s | Gemma süre medyanı [min–max], s |
|---|---:|---:|---:|---:|
| Bulgu, soğuk başlangıç dahil | 3/3 | 3/3 | 43,718 [43,057–45,767] | 55,632 [55,190–56,201] |
| Tam tarama, sıcak | 3/3 | 3/3 | 56,252 [54,458–59,711] | 41,949 [41,877–43,624] |
| WAF, sıcak | 3/3 | 3/3 | 39,968 [39,770–44,235] | 30,063 [29,797–32,860] |
| API/BOLA, sıcak, yalnız analiz | 3/3 | 3/3 | 69,537 [69,192–70,192] | 54,327 [53,908–55,050] |
| Toplam gerçek vaka | **12/12** | **12/12** | | |

Mevcut üç Faz 3.5 senaryosu her modelde **9/9**, yeni analiz senaryosu **3/3**.
**Başarısız gerçek test: 0.** Otomatik başarıya çevirme veya gizlenen başarısız
deneme yoktur. Teknik metin hataları aşağıda ayrıca gösterilir.

### Yükleme ve üretim süreleri

| Model / senaryo | Load medyanı, s | Prompt-eval medyanı, s | Eval medyanı, s | Eval token/s medyanı | Çıktı token sayısı |
|---|---:|---:|---:|---:|---:|
| Qwen bulgu | 5,415 | 1,396 | 36,291 | 35,16 | 1276 |
| Gemma bulgu | 28,338 | 5,404 | 21,838 | 38,97 | 851 |
| Qwen tarama | 0,034 | 1,770 | 54,342 | 34,01 | 1848 |
| Gemma tarama | 0,036 | 6,069 | 35,638 | 40,29 | 1436 |
| Qwen WAF | 0,035 | 1,347 | 38,461 | 35,18 | 1353 |
| Gemma WAF | 0,035 | 5,082 | 24,763 | 36,39 | 901 |
| Qwen API/BOLA | 0,036 | 1,867 | 67,530 | 34,89 | 2356 |
| Gemma API/BOLA | 0,034 | 7,114 | 46,950 | 39,60 | 1859 |

Soğuk yükleme aralığı Qwen **5,220–8,192 s**, Gemma **27,555–29,165 s**.
Sıcak load süreleri tam model yükleme maliyeti değildir. Tablo sütunları ayrı ayrı
medyan olduğu için toplamları duvar medyanına tam eşit olmak zorunda değildir.
Token sayısı her model/senaryonun üç tekrarında aynıdır; farklı tokenizer'lar
nedeniyle token/s doğrudan aynı Türkçe sözcük/saniye ölçüsü değildir.

Gemma sıcak taramada **%25,4**, WAF'ta **%24,8**, API/BOLA'da **%21,9** daha kısa
yanıt süresine sahipti. Hem daha kısa yanıtlar üretti hem bu ölçümlerde daha yüksek
eval token/s gösterdi; hız farkının tamamı tek bir nedene atfedilemez. Qwen soğuk
bulgu çağrısında daha hızlıdır. Bir soğuk ve üç sıcak çağrının gerçek süre toplamı
tur medyanı Qwen **209,277 s**, Gemma **181,552 s**: Gemma bu paket için yaklaşık
**%13,2** daha kısa süre kullandı. Bunlar n=3 yerel ölçümlerdir, evrensel hız garantisi değildir.

### Şema, referans ve thinking

| Kontrol | Qwen | Gemma |
|---|---:|---:|
| JSON Schema / Pydantic / mevcut güvenlik doğrulaması | 12/12 | 12/12 |
| Beklenen birincil kanıt kimlikleriyle tam eşleşme | 12/12 | 12/12 |
| Türkçe dil sinyali testi | 12/12 | 12/12 |
| Ayrı thinking alanındaki karakterler | Her çağrıda 0 | Her çağrıda 0 |
| Çıktı token sınırında kesilme | 0 | 0 |
| Zaman aşımı / provider hatası | 0 | 0 |

Referansların eksik/fazla/değiştirilmiş olması reddedilmeye devam eder. İkincil
referanslar ve TLS referansları mevcut sözleşmeyle doğrulanmıştır. Her senaryo
için giriş/şema/sistem SHA-256 özetleri altı model-tur grubunda aynıdır.
Örneklenen `/api/ps` context değeri iki modelde de **8192**; düşünme kapalı,
4096 çıktı sınırı, 300 s timeout, concurrency 1 bütün vaka kayıtlarında doğrulandı.
Ayrı thinking içeriği görülmemesi, modelin görünmeyen iç hesaplamaları hakkında
bir iddia değildir; thinking metni saklanmaz.

Her model/senaryoda üç doğrulanmış çıktı özeti aynıdır: **tek farklı çıktı**.
Tekrarlar zaman/bellek ölçümüne katkı sağlar; doğruluk açısından bağımsız yeni
örnek sayısını üçe katlamaz. Her model için dört farklı senaryo incelenmiştir.

### GPU ve RAM

İstenen modelin `/api/ps` içinde yüklü göründüğü örnekler kullanılır.
Her satır üç turun **örneklenen tepesidir**, ortalama model belleği değildir.

| Model / senaryo | GPU kullanılan MiB | Sistem kullanılan GiB | Ollama çalışma kümesi GiB | Ollama private commit GiB |
|---|---:|---:|---:|---:|
| Qwen bulgu | 7698 | 15,989 | 1,344 | 8,340 |
| Gemma bulgu | 7760 | 28,409 | 14,468 | 21,537 |
| Qwen tarama | 7752 | 16,462 | 1,617 | 8,581 |
| Gemma tarama | 7800 | 29,494 | 15,123 | 22,199 |
| Qwen WAF | 7801 | 16,662 | 1,917 | 8,881 |
| Gemma WAF | 7790 | 30,466 | 15,796 | 22,873 |
| Qwen API/BOLA | 7843 | 16,928 | 2,181 | 9,147 |
| Gemma API/BOLA | 7797 | 30,732 | 16,453 | 23,525 |

| Tüm yüklü örnekler | Qwen | Gemma |
|---|---:|---:|
| GPU kullanım medyanı / tepe | %81 / %100 | %37 / %99 |
| Güç medyanı / tepe, W | 88,57 / 112,05 | 34,92 / 54,06 |
| Sıcaklık medyanı / tepe, °C | 66 / 75 | 52 / 57 |
| Sistem boş RAM medyanı / minimum, GiB | 15,497 / 14,695 | 2,558 / **0,891** |

Soğuk başlangıç sistem RAM tabanları Qwen 14,084–14,627 GiB,
Gemma 13,711–14,795 GiB; GPU tabanları sırasıyla 1040–1424 ve 928–1361 MiB.
Başlangıçlar tam aynı değildir: masaüstü diğer uygulamalardan izole edilmedi.
Süreç sayaçlarında okunamayan süreç, `/api/ps` örnek hatası ve örneklenen başka
model yerleşimi yoktur. Model grupları arasındaki boş `/api/ps` kontrolü ayrıca
uygulandı. Sonunda yüklü modeller bellekten çıkarıldı; dosyaları duruyor.

Ollama `/api/ps`, Qwen size/size_vram için **5,939 / 5,213 GiB**, Gemma için
**1,216 / 0,922 GiB** bildirdi. Gemma metadata'sı 18,7 GB dosya ve NVIDIA/Windows
ölçümleriyle modelin toplam yerleşimini açıklamaz; buradan kesin GPU offload oranı
veya toplam model RAM'i türetilmedi. Ham metadata raporlarda korunur. İki model de
bu çalışmada yaklaşık 7,6 GiB toplam GPU kullanımı seviyesine ulaşmıştır;
Qwen'in avantajı burada düşük **RAM** yüküdür, çok düşük VRAM tüketimi değildir.

## Teknik doğruluk, Türkçe ve yanlış pozitif incelemesi

Ayrıntılı gözlem kaydı: `reports/qwen_vs_gemma/quality_review.json`. İnceleme,
doğrulamadan geçmiş özet/açıklama/belirsizlik/etki/öneri alanlarıyla sınırlıdır.

| İnceleme | Qwen 3.5 9B | Gemma 4 26B |
|---|---|---|
| API'nin dört ayrı kayıt durumunu ayırma | 4/4 doğru ayrım | 4/4 doğru ayrım |
| TLSv1.3 gözlemi / tam sürüm envanteri ayrımı | Envanterin bilinmediğini koruyor | Envanterin bilinmediğini koruyor |
| Gelecekteki sertifika bitişi | 10 gün ve yenileme ihtiyacını doğru aktarıyor | 10 gün ve yenileme ihtiyacını doğru aktarıyor |
| Referrer-Policy önerilerindeki literal değerler | İlgili iki senaryoda da geçersiz değer öneriyor | İlgili iki senaryoda geçerli değer öneriyor |
| Tam taramada HTTP 429 nedeni | Özette WAF'a atfediyor, belirsizlik alanında bunu kanıtlayamayacağını söylüyor | WAF mı uygulama limiti mi belirsizliğini daha tutarlı koruyor |
| HTTPS `incomplete` yorumu | Bulgu ve WAF senaryolarında yönlendirme eksikliği çıkarıyor | Bulgu/tarama metinlerinde eksiklik çıkarıyor; WAF sınırlamasında taramanın tamamlanmadığını ileri sürüyor |
| Retry-After 60 s | İncelenen açıklama/önerilerde atlanıyor | İncelenen açıklama/önerilerde atlanıyor |
| Türkçe anlatım | Türkçe, daha uzun/tekrarlı; yer yer bozuk ifade ve İngilizce sözcük | Türkçe, daha kısa ve genel olarak daha okunaklı; kusursuz değil |

Qwen'in bulgu önerisinde `strict` ve `origin-when-crossorigin`, tam taramada
`strict` bulunur. Bunlar geçerli Referrer-Policy değerleri değildir. Gemma,
`strict-origin-when-cross-origin` önerir. Bu ayrım
[W3C politika değerleriyle](https://www.w3.org/TR/referrer-policy/#referrer-policies)
kontrol edildi; JSON Schema serbest öneri metninin teknik doğruluğunu denetlemez.

Qwen'in sertifika etkisindeki “veri şifreleme garantisi sona erer” ifadesi
yanıltıcıdır. Sertifika bitişi güven/sertifika doğrulaması ve bağlantı reddi
konusudur; şifrelemeyi kendiliğinden ortadan kaldıran bir olay olarak
anlatılmamalıdır. Gemma “bağlantılar güvenilmez olarak işaretlenecektir” diyerek
daha doğru ayrım yapar. Karşılaştırma
[sertifika geçerlilik tanımı](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.5)
ve [TLS kayıt koruması](https://www.rfc-editor.org/rfc/rfc8446.html#section-5.2)
üzerinden değerlendirildi.

Ortak somut hata: `https_redirect=incomplete` değerinden yönlendirme kusuru
çıkarılması. Gemma'nın WAF sınırlamasındaki “Tarama sonuçları eksik yönlendirme
nedeniyle tamamlanmamıştır” ifadesi ayrıca `status=completed` ile uyuşmaz.
Alt kontrolün eksikliği ile tüm taramanın başarısızlığı ayrılmalıdır.
Bu hatalar mevcut deterministik doğrulamadan geçmiştir; şema/kanıt kimliği
kontrolleri başarılı kalırken serbest metin yanlış olabilir.

WAF `false_positive` etiketi Qwen'de `possible`, Gemma'da `undetermined`;
API'nin veri içermeyen 200 hata kaydında ikisinde de `possible` bulunur.
Bu etiketlerin farklılığı tek başına kalite sıralaması değildir. İki model de
korunan 401/403 senaryolarını açık olarak adlandırmaz; yetkisiz okuma kaydını
ayırır ve gözlenmeyen yazma/silme sonuçlarını uydurmaz. İki modelin de HTTPS
çıkarımları yanlış pozitif üretebilir. İstatistiksel yanlış pozitif oranı ölçülmedi.

Bu veri kümesinde **teknik öneri doğruluğu ve anlatım tutarlılığı bakımından Gemma
tercih edilir**. API/BOLA ayrımında üstünlük gösterilmedi. Genel doğruluk yüzdesi
veya her güvenlik alanında model üstünlüğü iddia edilemez.

## Model tercihi

**Ana AI analisti için kalite odaklı öneri: mevcut Gemma 4 26B profilini korumak.**
Bu örneklerde önerdiği politika değerleri daha doğru, WAF belirsizliği daha
tutarlı, Türkçe raporu daha kısa ve sıcak analizleri daha hızlıdır. Üretim
varsayılanı bu benchmark tarafından değiştirilmedi.

**Qwen 3.5 9B**, soğuk başlayan veya RAM bütçesi sınırlı analizlerde daha uygun
alternatiftir. Dört sentetik API/yetki durumunu Gemma kadar iyi ayırdı ve çok daha
fazla RAM payı bıraktı. Buna karşılık geçersiz güvenlik başlığı önerileri ve WAF
atıf tutarsızlığı, ana analist olarak otomatik tercih edilmesini bu veri kümesinde
desteklemiyor. Kaynak tasarrufu ve teknik kalite aynı sonuç olarak sunulamaz.

Gemma'nın bu masaüstünde boş RAM'i 0,89 GiB'ye kadar düşürdüğü gözlendi; OOM veya
timeout yaşanmadı. Bu ölçüm, aynı anda daha fazla uygulama/iş yüküyle çalışmasının
uygunluğunu kanıtlamaz. Concurrency 1 ve tek yüklü büyük model koşulu korunmalı;
RAM bütçesi uygun değilse Qwen'in kaynak avantajı operasyonel tercihi değiştirebilir.
İki modelin de metni insan incelemesi gerektirir; deterministik scope/authorization
kararları AI'a aktarılmaz. Model önerileri ağ isteğine dönüşmez.

## Regresyon ve teslim

| Kontrol | Sonuç |
|---|---|
| Değişiklik öncesi standart paket | 361 geçti, 3 opt-in atlandı; 19,55 s |
| Değişiklik sonrası standart paket | **365 geçti, 4 opt-in atlandı; 19,09 s** |
| Eski 361 standart test | Tamamı korundu ve geçti |
| Yeni deterministik fixture testleri | 4 geçti |
| Gerçek model testleri | 24 geçti; 0 başarısız; varsayılan paketten ayrı çalıştırıldı |
| API/faz/benchmark dosyalarında Ruff | Başarılı |
| `compileall -q src tests` | Başarılı |
| Depo genelinde Ruff | Exit 1; Faz 4A raporundaki aynı 125 eski ihlal sürüyor |

Standart paketteki dört atlama üç mevcut gerçek Ollama testi ve bir yeni gerçek
API/BOLA analiz testidir; gerçek benchmark'ta bunlar opt-in açılarak çalıştırıldı.
Bir mevcut Starlette/TestClient `httpx` deprecation uyarısı vardır. Depo genelindeki
eski Ruff sorunları giderilmiş veya tüm depo lint'i temizmiş gibi gösterilmedi.
Sayısal doğrulamalar `reports/qwen_vs_gemma/validation.json` içindedir.

Değiştirilen tek mevcut dosya: `tests/ollama_benchmark.py` (gözlemci).
Bu görevde eklenen dosyalar:

- `tests/model_comparison_data.py`: sabit sentetik kayıtlar/UUID/zamanlar.
- `tests/test_model_comparison_data.py`: maskelenmiş giriş ve şema tekrar üretimi.
- `tests/test_model_comparison_ollama.py`: opt-in, salt API/BOLA analizi.
- `tests/run_model_comparison.py`: üç tur, tek model yerleşimi, ayrı raporlar.
- `tests/summarize_model_comparison.py`: yerel ölçüm toplama; inference yapmaz.
- `docs/QWEN_VS_GEMMA.md`: bu rapor.
- `reports/qwen_vs_gemma/`: environment/hardware/run, altı tur dosyası,
  summary/quality_review/validation JSON kayıtları.

OllamaProvider, sözleşme, güvenlik doğrulaması, CLI/API ve Faz 4A üretim kodu
bu görevde değiştirilmedi. Önceden var olan Git değişiklikleri korunur.
Bağımlılık eklenmedi; model dosyaları silinmedi; Faz 4B başlatılmadı.

## Tekrar çalıştırma

Proje kökünden, mevcut virtualenv ve iki kurulu modelle:

```powershell
# Yeni ölçümü farklı bir dizinde tut; mevcut sonuçlar üzerine yazılmaz.
$env:CRIMSON_COMPARISON_DIRECTORY = "reports/qwen_vs_gemma_repeat_01"
.venv\Scripts\python.exe tests/run_model_comparison.py
.venv\Scripts\python.exe tests/summarize_model_comparison.py
Remove-Item Env:\CRIMSON_COMPARISON_DIRECTORY

.venv\Scripts\python.exe -m pytest -q
.venv\Scripts\python.exe -m compileall -q src tests
```

Runner AI ayarlarını yalnız pytest alt süreçlerine geçirir; üretim `.env` ayarlarını
değiştirmez. Çıktı dizini workspace `reports/` altında olmalıdır. Var olan `run.json`
bulunduğunda çalışmayı durdurur ve önceki dosyayı korur; bu koruma SHA-256 karşılaştırmasıyla
doğrulandı. Yeni tur sonunda raporun teknik kalite incelemesi ayrıca yapılmalıdır;
sayısal özetleyici semantik yorumları otomatik başarılı kabul etmez.

Kapsam sınırları: tek donanım, küçük sentetik veri, n=3 süre tekrarı, thinking yalnız
kapalı profil, kısa girişler (8192 bağlamın tamamını dolduran stres testi değil).
Gemma 3 veya başka quantization ile yeni deney yapılmadı. API analiz kayıtları gerçek
uygulama pentest'i değildir; gerçek Bug Bounty başarısı hakkında çıkarım yoktur.
