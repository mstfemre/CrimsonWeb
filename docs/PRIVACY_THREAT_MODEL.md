# Privacy threat model — Faz 5A

Bu belge Faz 5A kodundan önce hazırlanmıştır. Privacy değerlendirmesi anonimlik
sertifikası değildir. `secure_observed` yalnız belirli bir kontrollü gözlemi anlatır.

## Saldırgan ve güven sınırı

İzinsiz hedef, HTTP echo sunucusu, DNS cevabı, response/prompt metni ve ortam proxy
değişkenleri güvenilmeyen girdidir. Kötü niyetli API istemcisi başka workspace'in
profil/kanıt/assessment kayıtlarına erişmeye çalışabilir. API ortak operatör token'ını
korur; token sahibi operatör scope ve privacy yapılandırmasını yönetebilir. SQLite
dosyasına veya çalışan Python process'ine sahip yönetici bu uygulamanın güven sınırıdır.
OS/root compromise, ISP/AS düzeyi izleme, küresel trafik korelasyonu ve fiziksel cihaz
güvenliği bu fazın koruma kapsamına girmez.

## Tehditler ve ölçülebilir davranış

| Tehdit | Faz 5A davranışı ve sınırı |
|---|---|
| Beklenmedik bağlantıda gerçek IP | Yalnız exact allowlisted verifier + ProgramPolicy; response IP untrusted; eşleşmeyen echo tek başına validated leak değildir |
| İstenmeyen DNS resolver | Config snapshot ve A/AAAA ayrı gözlem; gerçek paket yoluna bağımsız kanıt yoksa inconclusive |
| Beklenmeyen IPv6 | Local socket capability, response IP ailesi ve native connection ailesi ayrı; capability egress kanıtı değildir |
| Proxy/VPN düşmesi ve direct fallback | Mevcut direct pinned transport değişmez; managed_egress unsupported ve gönderimden önce reddedilir; alternatif yola retry yok |
| Yanlış interface | Zorunlu interface kısıtı mevcut transportta enforce edilemezse aktif gözlem blocked_by_policy; OS routing doğrulanmış sayılmaz |
| OS proxy ayarları | HTTPX trust_env=False değişmez; bu, OS VPN/routing/WinHTTP durumunu doğrulamaz |
| Header/TLS fingerprint korelasyonu | Bu faz fingerprint toplamaz/sahtelenmez; açık risk, Faz 5C lab tasarımına bırakılır |
| Workspace veri sızıntısı | Servis/API qualifier ve profile/assessment/evidence bileşik FK'leri; shared token multi-user RBAC değildir |
| Loglarda IP/secret | Privacy evidence ve audit raw IP/body/header tutmaz; scope admission'ın privacy çağrıları da IP listesini kaydetmez; geçmiş kayıtlar silinmez |
| Prompt injection | Echo sadece bounded IP JSON; DNS/provider metadata whitelist; AI çağrısı yok; gelecekte veri untrusted kalır |
| DNS cache/OS route etkisi | Application resolver, local system lookup ve proxy DNS ayrı; OS lookup/proxy ölçülmediyse not_tested, packet path yoksa inconclusive |

## Kanıt statüleri

- secure_observed: kontrollü gözlem beklenen koşulu karşıladı; genel koruma iddiası yok.
- leak_suspected: echo mismatch veya capability/config göstergesi; independently proven egress leak değildir.
- leak_validated: yalnız doğrudan transport metadata ile doğrulanabilen dar iddia
  veya trusted lab instrumentation ile gözlenen resolver yolu
  (örneğin IPv4-only beklentiye karşın açıkça izinli lab testinde gerçek IPv6 bağlantısı).
- inconclusive: timeout, çelişkili/eksik echo, bilinmeyen resolver yolu veya ölçülmeyen route.
- not_tested: test yapılmadı; olumsuz veya olumlu leak sonucu üretilemez.
- blocked_by_policy: scope/privacy/unsupported mode/revision/defense kararı gönderimi engelledi.

Echo sunucusu yanlış IP bildirebilir. DNS A/AAAA kaydı public egress IP veya DNS leak
kanıtı değildir. Bağlantının peer ailesi, sunucunun bildirdiği client IP ailesinden
ayrı tutulur. Önceden gönderilmiş DNS/HTTP baytları policy update/iptalle geri alınamaz;
sonraki admission ve persist kararı güncel policy ile fence edilir.

## Veri ve operational sınırlar

Beklenen IP/resolver kimlikleri profile'a özgü salted HMAC ile karşılaştırılır; raw
gözlenen IP'ler persist edilmez. Bu pseudonymization'dır, disk şifreleme değildir.
HMAC anahtarı DB'de profile'a özel private sütundadır; DB'yi okuyabilen kişi IP
adaylarını deneyebilir. Bu güvence database compromise için anonimleştirme değildir.
Uygulamanın privacy kayıtları minimaldir; bağımsız web-server access logları veya
operatörün açtığı HTTPX/httpcore debug logları bu uygulama tarafından maskelenmez.
Explicit hedef URL/CIDR yapılandırması mevcut scope/config bilgisidir; raw gözlem
geçmişi ile karıştırılmaz. Retention süresi ve expires_at metadata olarak belirtilir;
otomatik silme/secure erasure bu fazda uygulanmaz ve enforced=false olarak gösterilir.
Gelecekte temizleme aktif job/lease'leri koruyan, preview ve backup/rollback planı olan
sınırlı batch işlemi olmalıdır. Eski scan/discovery/audit geçmişi otomatik temizlenmez.

Tek cooperating local worker ve OS lifetime lock, crash sonrası sahipliği bilinen
privacy lease'lerinin ancak eski worker'ın sona erdiği kanıtlandıktan sonra açılmasını
sağlar. PID veya timeout tek başına yeterli değildir. Network/cloud filesystem veya
birden fazla host için distributed koordinasyon sağlamaz.

## Gelecek egress trust boundary

Faz 5B EgressTransport scope kararından ayrı bir route verifier kullanmalıdır.
Client→proxy peer, proxy→target DNS/peer, orijinal hostname/SNI, certificate validation
ve CNAME/IP scope doğrulamasının her biri için ayrı kanıt gerekir. Proxy DNS yalnız
client tarafı pinning'e dayanarak güvenli ilan edilemez. Proxy failure direct fallback
oluşturmamalı; gerekiyorsa request reddedilmelidir. Uygulama fail-closed kararı OS kill
switch değildir. OS enforcement, admin yetkisi, allowlisted control channel, geri alma,
boot/crash recovery ve ağ bağlantısı kaybı senaryolarıyla ayrı WFP fizibilitesi ister.
