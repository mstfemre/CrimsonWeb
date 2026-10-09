# CrimsonWeb — Faz 1

## Mevcut proje ve geliştirme planı

Proje zaten `src/crimsonweb` altında CLI, servis keşfi, web kontrolleri,
raporlama ve testler içeriyordu. Kullanıcıya ait mevcut değişiklikler korundu.
Yeni HTTP değerlendirme API'si `src/crimsonweb/api` altında bağımsız servis
katmanı olarak eklendi; mevcut CLI'nin ağ/egress akışını kullanmaz.

Plan: kapsam doğrulama → HTTP motoru → başlık bulguları → API/JSON → yerel
laboratuvar → otomatik ve gerçek soket testleri. Faz 2–5 bu değişikliğin kapsamında değildir.

## Kurulum

API için Python 3.12+ önerilir; mevcut CLI'nin Python >=3.11 uyumluluğu korunur.

Windows PowerShell (proje kökünde):

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install -e ".[api,dev]"
.venv\Scripts\python.exe -m uvicorn crimsonweb.api.app:app --app-dir src --host 127.0.0.1 --port 8000 --no-proxy-headers
```

Linux/macOS:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -e '.[api,dev]'
.venv/bin/python -m uvicorn crimsonweb.api.app:app --app-dir src --host 127.0.0.1 --port 8000 --no-proxy-headers
```

OpenAPI: http://127.0.0.1:8000/docs. Yapılandırma süreç ortamından okunur;
`.env.example` örnektir, `.env` otomatik yüklenmez. API token yoksa yalnızca
loopback istemciler kabul edilir. Dış arayüze açmak için güçlü `CRIMSON_API_TOKEN`
ve HTTPS terminasyonu gerekir; tüm servis çağrılarında Bearer token kullanın.
Proxy başlıklarının istemci adresini değiştirmemesi için `--no-proxy-headers` kullanın.

## Yerel örnek sunucu

İkinci terminalde:

```powershell
.venv\Scripts\python.exe -m uvicorn crimsonweb.api.lab:app --app-dir src --host 127.0.0.1 --port 8001
```

Örnek yollar: `/` eksik başlıklar, `/hardened` yapılandırılmış başlıklar,
`/redirect` yerel yönlendirme, `/blocked` 403, `/limited` 429.
Bunlar kontrollü test yanıtlarıdır; gerçek WAF tespiti olarak sunulmaz.

## Analiz ve JSON raporu

```powershell
$body = @{url='http://127.0.0.1:8001/redirect'; engagement_id='local-lab'; authorized=$true} | ConvertTo-Json
$scan = Invoke-RestMethod http://127.0.0.1:8000/scans -Method Post -ContentType 'application/json' -Body $body
Invoke-RestMethod "http://127.0.0.1:8000/scans/$($scan.id)"
# Durum completed, blocked veya failed olduktan sonra:
Invoke-WebRequest "http://127.0.0.1:8000/scans/$($scan.id)/report" -OutFile "reports/local-lab.json"
```

`POST /scans` 202 döndürür. İzin beyanı (`authorized: true`) ve
`engagement_id` zorunludur. `GET /scans` geçmişi listeler. `GET /scans/{id}`
ilerlemeyi, `/report` JSON indirmesini sunar; çalışan rapor için 409 döner.
Geçersiz hedef 422, bilinmeyen tarama 404, iş kapasitesi 429 döndürür.

## Kapsam ve güvenli HTTP davranışı

Varsayılan hostlar localhost, 127.0.0.1 ve ::1; ağlar loopback'tir.
Başka izinli hedef için **hem** tam hostname allowlist'i **hem** izinli CIDR'leri
`CRIMSON_ALLOWED_HOSTS` ve `CRIMSON_ALLOWED_NETWORKS` değişkenleriyle ayarlayın.
Wildcard hostname desteği yoktur. Portlar 1–65535 olabilir; izin kapsamının
bu portları da kapsadığından emin olun. Kapsam raporda kayıtlıdır.

Her DNS yanıtındaki tüm IP'ler doğrulanır. İstek doğrulanmış ilk IP'ye sabitlenir;
Host ve TLS SNI orijinal hostname'i korur. Sertifika doğrulaması açık kalır.
Sistem proxy ortamı kullanılmaz. Her yönlendirme yeniden doğrulanır; HTTPS→HTTP
geçişi, döngü, kapsam dışına çıkış ve altı isteği aşma durdurulur.
URL kimlik bilgileri, query ve fragment kabul edilmez. Gövdeler okunmaz;
cookie, Server ve diğer hassas başlıklar raporda tutulmaz.

403 erişim reddi, 429 rate limit olarak ayrı kaydedilir; bunlar tek başına WAF
veya IP engeli kanıtı değildir. Bu durumlarda tekrar denenmez. Faz 1'de bağlantı
hataları da otomatik tekrar edilmez. Motor genelinde saniyede en fazla bir yeni
istek başlatılır; istek timeout'u 5 saniye, görev timeout'u 60 saniyedir.
DNS timeout'u 5 saniyedir. En fazla dört görev ve son 100 bellek içi rapor tutulur.
Servis kapanınca aktif görevler iptal edilir; yeniden başlatınca geçmiş silinir.

Başlık gözlemleri CSP, HSTS (yalnız HTTPS), nosniff, referrer ve framing politikasını
kapsar. [OWASP Secure Headers](https://owasp.org/www-project-secure-headers/)
referans alınır. Eksik başlıklar doğrulanmış açıklık sayılmaz; uygulama bağlamı
ve manuel doğrulama gerekir. LLM değerlendirmesi henüz yoktur (`ai_analysis: null`).
Yapılandırılmış tamamlanma logları tarama kimliği, durum ve istek sayısını içerir;
URL veya yanıt gövdesi loglanmaz.

## Testler

```powershell
.venv\Scripts\python.exe -m pytest -q
.venv\Scripts\python.exe -m ruff check src/crimsonweb/api tests/test_phase1_api.py tests/test_phase1_integration.py
```

Yeni testler kapsam, karma DNS yanıtı, IP sabitleme/SNI, yönlendirme,
403/429 durdurma, bağlantı/timeout hataları, başlık bağlamı, raporlama ve API
erişim kontrolünü kapsar. Testler dış hedefleri taramaz.

## Sonraki faz

Faz 2: kalıcı veritabanı ve geçmiş, TLS sürüm/sertifika incelemesi,
cookie/CORS analizi ve savunma logları. Dashboard, LLM, PDF/HTML raporları ve
ModSecurity/CRS Docker laboratuvarı daha sonraki fazlardır.

## Faz 1 tamamlanma durumu — 8 Ekim 2026

Tamamlandı: modüler proje yapısı, FastAPI uygulaması ve OpenAPI,
yetkilendirilmiş hedef/kapsam kontrolü, DNS adres doğrulama ve bağlantı sabitleme,
HTTPX motoru, yönlendirme denetimi, başlık gözlemleri, timeout/istek limitleri,
403/429 durdurma, asenkron işler, yapılandırılmış loglama, JSON rapor indirme,
yerel örnek sunucu, kurulum/kullanım dokümanı ve otomatik testler.
Faz 1'in istenen maddelerinde açık iş kalmadı.

Son doğrulama Python 3.12.14 / HTTPX 0.28.1 / FastAPI 0.143.0 ortamında:
**87 test geçti** (23 yeni Faz 1 testi dahil), **yeni modül ve testlerde Ruff geçti**,
API Python derleme kontrolü geçti. Entegrasyon testi gerçek loopback soketleriyle
API + laboratuvar sunucularını başlatıp kapatarak çalıştı. Windows sandbox içindeki
asenkron soket testleri ilerlemediği için son pytest doğrulaması izinli sandbox dışı
çalıştırmada yapıldı; dış hedeflere istek gönderilmedi.

Bir bağımlılık uyarısı var: Starlette TestClient, HTTPX test adaptörünün ileride
kaldırılacağını bildiriyor. Testler başarılı; üretim HTTPX istemcisine ilişkin
bir hata değil. HTTPS bağlantısında standart sertifika doğrulaması kullanılır;
gerçek TLS laboratuvarı/sürüm test matrisi bu fazda çalıştırılmadı.
Bellek içi geçmiş kalıcı değildir; çoklu worker ile paylaşılmaz. Bu MVP için
tek Uvicorn worker kullanın. Kalıcı geçmiş ve ileri TLS analizi Faz 2'ye aittir.
