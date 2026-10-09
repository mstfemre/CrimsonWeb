# Faz 5 mimarisi

Bu görev yalnız 5A implementasyonudur. 4C/4D ve 5B–5F kodlanmaz.

## Katmanlar ve sorumluluk

- Privacy Engine (5A): profile/policy, izinli echo, DNS ve IPv6 evidence,
  deterministik assessment, minimal audit, kalıcı ve iptal edilebilir işler.
- Secure Egress Engine (5B planı): sabit onaylı çıkış ağı ve ayrı EgressTransport.
- Network Fingerprint Intelligence (5C planı): yalnız lab server'da TLS/ALPN/HTTP
  özelliklerinin ölçümü ve ilişkilendirme riskinin açıklanması.
- Authorized Security Research (mevcut): WorkspaceService, scanner/discovery,
  TLS/HTTP/WAF evidence; modüller yeniden yazılmaz.
- AI Privacy Analyst (5E planı): ayrı masked privacy evidence sözleşmesi; deterministic
  status/network kararlarını değiştiremez, shell/URL/proxy aracı verilmez.
- Dashboard (5F planı): geçmiş ve canlı gözlemi ayırır; kanıtsız Protected/Anonymous etiketi yok.

ProgramPolicy hedefin test edilmesine izin verir. PrivacyPolicy bu izne yalnız ek
kısıt getirir: exact verifier allowlist, test türü, explicit approval/expiry, diagnostic
budget/rate, IPv6 probe onayı ve veri minimizasyonu. Profile expected identity, resolver,
family/interface ve retention beklentisidir; hedef izni değildir. PrivacyPolicy scope'u
genişletemez. Diagnostic preflight pasif/advisory'dir; DNS veya HTTP göndermez.

Aktif DNS/HTTP, aynı WorkspaceService karar/lease/HTTPX pinning yolu ile çalışır.
Privacy owner/revision/cancel fence ve audit minimizasyonu bookkeeping katmanındadır;
`engine.pinned_response`, DNS scope kuralları ve Ollama production sözleşmesi değişmez.
Her assessment en fazla bir logical network observation yapar; redirect takip etmez.
Policy budget diagnostics admission'ını, ProgramPolicy budget gerçek guarded admission'ı
sayar. A/AAAA packet sayısı logical observation sayısı değildir.

## 5B teknik planı — kod yok

EgressProfileManager, TrustedProxyConfiguration, EgressRouteVerifier,
ProxyCredentialVaultAdapter, ConnectionFailClosedGuard ve EgressAuditService ayrı
katmandır. Açık proxy toplama/rotasyon/engel aşma yoktur. Sabit trusted egress,
ephemeral credential access, proxy peer ve target peer doğrulaması, proxy DNS scope
kanıtı, TLS SNI/certificate ve fail-closed error matrisi release ön koşuludur.
Mevcut pinned direct transport proxy seçeneği eklenerek sessizce dönüştürülmez.

Windows WFP/uygun OS filtering için feasibility: admin elevation sınırı, imzalı kurulum,
process/interface/DNS/v4/v6 filtre matrisi, control-channel allowlist, minimum yetki,
policy corruption/boot/crash, emergency rollback ve ağ erişimi kaybı recovery planı.
OS filtre geliştirilmeden kill switch veya genel IP koruması ilan edilmez.

## 5C–5F teknik planı — kod yok

5C: izole TLS/HTTP echo fixture, negotiated protocol/ALPN/HTTP version/header/UA/IP family
ve zaman bilgisi; client advertised özellikleri negotiated özelliklerden ayrılmalı.
Spoofing veya WAF fingerprint bypass yok.

5D: Workspace → Authorization → Privacy Preflight → Authorized Scan →
WAF/TLS/HTTP Observations → Evidence → Report. Privacy preflight gerçek gönderimin
yetkisi yerine geçmez. 403/429 access_denied/rate_limited kalır; WAF/IP attribution
bağımsız defense logs gerektirir. Legacy modüller yeniden yazılmaz.

5E: Gemma `gemma4:26b`, thinking=false/context8192/output4096/timeout300/concurrency1;
alternatif `qwen3.5:9b`. İki modeli eşzamanlı yükleme yok; historical 0,89 GiB RAM boşluğu
model admission için feasibility riskidir. Yeni privacy schema adapter ve evidence enum
mevcut finding/WAF schema'sından ayrı olmalı. Model status önerisi yalnız yorumdur.
`https_redirect=incomplete` ve test edilmemiş DNS/IPv6 kontrolleri confirmed leak'e
terfi ettirilemez; completeness/provenance kuralları deterministic server validation ister.

5F: Workspace/Profile/egress/DNS/IPv6/route/history/WAF/AI/evidence ekranları;
timestamp, source, test coverage, evidence ve unknown/inconclusive sınırı birlikte
sunulmalı. Canlı state ile eski ölçüm birleştirilmez. Bu fazda React/dashboard yok.
