# CrimsonWeb — Faz 3.5: Ollama referans ve dil sözleşmesi

## Kök neden

8 Ekim 2026'da çalışan yerel Ollama ve `gemma3:4b` ile hata sentetik SQLite
kayıtları üzerinde yeniden üretildi. İncelenen akış: `models.py`, `security.py`,
`provider.py`, `service.py` ve gerçek Ollama entegrasyon testi.

Bulgu seçimi bir kayıt olsa bile `EvidenceBundle.refs`, bulgu yanında tarama,
HTTP ve TLS bağlamını içerir. Bunların tümü geçerli kanıttır; fakat yalnız
`finding:` kayıtları `technical_findings` yorumu, yalnız `waf:` kayıtları
`waf_assessment` yorumu olabilir.

Eski şemada yorum listelerinin sayısı ve `evidence_ref`/`evidence_refs`
değerleri seçime göre sınırlandırılmıyordu. Serbest `string` alanları vardı;
doğru kategori/kimlik kullanımı yalnız İngilizce prompt ve son doğrulamaya
bırakılmıştı. Yeniden üretimde model:

- Seçilen `finding:` kimliğini aynen korudu.
- Aynı listeye `scan:` ve `tls:0` yorumları ekledi.
- Eksik referans, UUID değişikliği veya tekrar üretmedi; iki fazla kategori yorumu üretti.

Bu nedenle eski `validate_output()` içindeki beklenen `finding:` kümesi ile
üretilen yorum kümesi karşılaştırması `invalid_evidence_reference` verdi.
Bu deney, bildirilen hatayı aynı modelle yeniden üretir; kullanıcının önceki
ham yanıtı alınmadığından onun tam kimlik listesi hakkında varsayım yapılmaz.

Dil kontrolü yalnız `language == "tr"` etiketini doğruluyordu. İlk deneyde
özette Türkçe karakter sinyali vardı; yeni dil denetimiyle genişletilen gerçek
WAF denemesinde İngilizce açıklama tespit edildi. Bu yüzden yalnız referans
sözleşmesi değil Türkçe sistem talimatı da güçlendirildi.

## Çözüm

`contract.py`, her işin güvenilir kanıt snapshot'ından Pydantic modelleri ve
JSON Schema oluşturur. Genel `AnalystOutput` artık doğrudan sağlayıcı formatı
olarak kullanılmaz.

- Modelin `technical_findings` ve `waf_assessment` yanıtları iç protokolde
  nesnedir. Gerekli anahtarlar, doğru türdeki mevcut tam referanslardır.
- Bütün anahtarlar zorunlu, fazladan alanlar yasaktır. Model yorum gövdesinde
  `evidence_ref` veya `evidence_refs` alanı üretmez.
- Sunucu, doğrulanmış nesne anahtarını `evidence_ref` ve tek elemanlı
  `evidence_refs` olarak aynı kimlikle API yorumuna ekler. Yorumun birincil
  kanıt kimliği tamamen sunucuya aittir; model ikinci kez kimlik seçmez.
  Anahtarların çıktıda farklı sırada bulunması eşleşmeyi etkilemez.
- Risk, TLS, öneri ve ilişki dizilerindeki kanıt referansları mevcut kimliklerden `Literal`/enum ile
  sınırlandırılır; TLS bölümünde yalnız TLS/TLS-failure kimlikleri bulunur.
- `language` istenen dilin sabitidir. Kanıtsız kategoriler boş nesne,
  TLS kanıtı yoksa TLS referansları boş dizi olur.
- Tekrarlı JSON anahtarları sessizce son değerle değiştirilmez. Kimlik
  kapsamı, yorumun kendi referansı, dizi tekrarları ve mevcut içerik güvenlik
  kontrolleri sunucuda da doğrulanır.

Konumsal eşleştirme, benzer metinden eşleştirme, UUID tamamlama, yeni UUID
üretme veya hatalı yorumları sessizce atma yoktur. Şemaya uymayan yanıt başarısız
olarak kalır. API/veritabanı çıktısındaki `technical_findings` ve
`waf_assessment` listeleri ve `evidence_ref` alanı korunur. Teknik bulgular,
önem derecesi, CLI, kapsam ve güvenli durdurma politikası değişmez.

Tam tarama denemesi, doğru yorum anahtarının altında modelin yalnız `tls:0`
referansını seçebildiğini de gösterdi. Bu nedenle birincil referansın sunucuda
oluşturulması sözleşmenin parçasıdır; eksik modeli yanıt sonrası tahminle
tamamlama değildir. Ek bağlam referansları ayrı risk/TLS/ilişki bölümlerindedir.
Çıktı uzunluğunu sınırlamak için en fazla üç öneri, iki ilişki, üç sınırlama
ve yorum başına üç düzeltme istenir. Zorunlu bulgu/WAF yorumları azaltılmaz;
her seçili kimlik hâlâ zorunludur. Kesilmiş yanıtlar başarı sayılmaz.

Şema hem `/api/chat` isteğinin `format` alanına hem güvenilir sistem mesajına
verilir. Bu yaklaşım [Ollama structured output belgesindeki öneriyle](https://docs.ollama.com/capabilities/structured-outputs)
uyumludur. Temperature=0 ve mevcut bağlam/çıktı/zaman sınırları korunur;
otomatik retry/repair veya başka modele geçiş eklenmez.

Türkçe isteklerde sistem prompt'u Türkçedir; İngilizce kanıt metinlerinin
açıklamalara kopyalanmaması açıkça belirtilir. Şema alan adları, kimlikler ve
enum değerleri çevrilmez. Açık İngilizce düzyazı için tutucu bir denetim
`model_language_mismatch` üretir. Denetim yalnız dil işaretlerini sayar;
tam bir dil tespit sistemi değildir, her karışık veya kısa metni yakalama
garantisi vermez. Türkçe ASCII metin ve teknik İngilizce terimler test edilmiştir.
Yorumların semantik doğruluğu hâlâ insan incelemesi gerektirir.

## Güvenli tanılama

`AIError.diagnostics` otomatik loglanmaz veya ham çıktı olarak DB'ye yazılmaz.
Referans hatalarında yalnız bölüm adı, kanonik referans kimlikleri,
eksik/fazla/tekrar kimlikleri ve sayılar bulunur. Referans alanına yerleştirilmiş
serbest metin, credential veya URL çıkarılır; yalnız geçersiz referans sayısı
verilir. Dil hatasında yalnız alan indeksi, dil etiketi ve işaret sayıları
bulunur. Hata mesajı güvenli hata kodudur.
Tamamlanmamış sağlayıcı yanıtında yalnız tamamlanma/model-eşleşme bayrakları,
çıktı token sayısı ve token sınırı bayrağı tanılamaya eklenebilir.

Pydantic doğrulama girdilerini gösterebilen hata zincirleri gizlenir.
`ProviderReply` repr'ı ham içeriği göstermez. Gerçek entegrasyon testi hatada
yalnız güvenli kod/tanılamayı gösterir; prompt, kanıt metni veya model cevabını
yazdırmaz. Testler sentetik, yerel laboratuvar kayıtları kullanır.

## Değişen dosyalar

Yeni:

- `src/crimsonweb/api/ai/contract.py`
- `tests/test_phase35_contract.py`
- `docs/PHASE3.5.md`

Güncellenen:

- `src/crimsonweb/api/ai/models.py`: ortak yorum gövdesi; dış API alanları korunur.
- `src/crimsonweb/api/ai/security.py`: yerelleştirilmiş talimat, anahtar doğrulama,
  güvenli tanılama, tekrar ve dil kontrolleri.
- `src/crimsonweb/api/ai/provider.py`: şemayı prompt'a ekleme, güvenli hata/repr.
- `src/crimsonweb/api/ai/service.py`: işe özel şema ve güvenilir kimlik bağlama.
- `tests/ai_helpers.py`, `tests/test_phase3_provider.py`,
  `tests/test_phase3_ollama_integration.py`: sağlayıcının iç protokolü ve gerçek testler.
- `README.md`, `docs/PHASE3.md`: güncel rehber bağlantısı.

## Çalıştırma ve migration

Yeni bağımlılık veya veritabanı migration'ı gerekmiyor. Alembic head
`0002_phase3` olarak kalır. Mevcut kurulum komutları:

```powershell
.venv\Scripts\python.exe -m pip install -e ".[api,dev]"
.venv\Scripts\python.exe -m alembic -c alembic.ini upgrade head
.venv\Scripts\python.exe -m pytest -q
.venv\Scripts\python.exe -m ruff check src/crimsonweb/api tests/test_phase1_api.py tests/test_phase1_integration.py tests/test_phase2_*.py tests/test_phase3_*.py tests/test_phase35_contract.py tests/ai_helpers.py tests/conftest.py
.venv\Scripts\python.exe -m compileall -q src tests
```

Çalışan yerel Ollama'da `gemma3:4b` yüklüyken:

```powershell
$env:CRIMSON_TEST_OLLAMA = '1'
$env:CRIMSON_AI_ENABLED = 'true'
$env:CRIMSON_OLLAMA_MODEL = 'gemma3:4b'
$env:CRIMSON_AI_TIMEOUT = '300'
.venv\Scripts\python.exe -m pytest tests/test_phase3_ollama_integration.py -q --tb=short
```

300 saniye bu doğrulamada kullanılan izinli çağrı sınırıdır; varsayılan 90
saniye değiştirilmedi. Sunucu/model hazır olmalı; test model indirmez.
Varsayılan pakete dönmek için `Remove-Item Env:CRIMSON_TEST_OLLAMA` kullanın.

## Doğrulama sonuçları

Başlangıç: 200 test başarılı, 1 gerçek Ollama testi atlandı.
Son varsayılan paket: 228 test başarılı, 3 gerçek Ollama senaryosu atlandı.
28 yeni regresyon; kategori karışması, eksik/fazla/değişmiş/kısaltılmış kimlik,
sıra bağımsızlığı, sunucuya ait kimliği değiştirme girişimi, tekrar, gizli veri içeren sahte referans,
şema hatası, yanlış dil ve boş kategori/TLS durumlarını kapsar.

Nihai gerçek Ollama doğrulaması: **gemma3:4b ile 3/3 test başarılı**, 58,32 saniye.
Seçili bulgu, tam tarama (iki bulgu + WAF olayı) ve seçili WAF olayı senaryoları
çalıştırıldı. Her senaryoda tam kimlik eşleşmesi, çıktı sözleşmesi ve Türkçe dil
sinyalleri denetlendi; ham yanıt/prompt loglanmadı. Gerçek testler varsayılan
paketten ayrı çalıştırıldı: 228 standart + 3 gerçek model testi, toplam 231
başarılı test vakası. Bu bir örnek doğrulama koşusudur; bütün model sürümleri,
girdi boyutları veya dil kalitesi için garanti değildir.
Ruff (API ve Faz 1/2/3/3.5 testleri), src/tests derleme ve diff whitespace
kontrolleri başarılıdır. Önceden var olan Starlette TestClient/HTTPX deprecation
uyarısı test sonucunu etkilemez.
