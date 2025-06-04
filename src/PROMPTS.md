# Siber Güvenlikte Kapsamlı Ağ Keşfi, Zafiyet Analizi ve Savunma Stratejileri

## 1. Giriş
Siber güvenlik alanında proaktif bir duruş sergilemek, potansiyel tehditleri ve zafiyetleri henüz bir saldırıya dönüşmeden önce tespit etmekle başlar. Keşif (reconnaissance) ve analiz, bu sürecin temel taşlarıdır. Ağdaki cihazları, açık portları, çalışan servisleri ve bunların sürümlerini belirlemek, bir sistemin güvenlik duruşunu anlamak için kritik ilk adımlardır. Bu bilgiler, sızma testleri, zafiyet değerlendirmeleri ve genel ağ güvenliği yönetimi için hayati önem taşır.

Bu rapor, ağ keşfinin temel bileşenlerinden başlayarak, sistem ve sürüm bilgilerinin nasıl elde edileceğini, bulunan güvenlik açıklarının nasıl analiz edilip derecelendirileceğini, bu verilerin nasıl görselleştirileceğini, ağdaki cihazların MAC adreslerinin nasıl tespit edileceğini ve son olarak, güvenlik duvarlarını atlatma yöntemlerini detaylı bir şekilde ele alacaktır. Amacımız, okuyucuya bu siber güvenlik alanlarında derinlemesine bir anlayış ve pratik uygulama yeteneği kazandırmaktır.

Siber güvenlikte keşif ve savunma mekanizmaları arasında sürekli bir gelişim gözlemlenmektedir. Port tarama ve bilgi toplama teknikleri (Nmap, Masscan gibi araçlarla) sürekli olarak evrimleşirken, güvenlik duvarları ve Saldırı Tespit/Önleme Sistemleri (IDS/IPS) de bu taramaları tespit etmek ve engellemek için sürekli olarak güncellenmektedir. Bu durum, siber güvenlikte dinamik bir "kedi fare oyunu" olduğunu ortaya koymaktadır. Saldırganlar yeni atlatma yöntemleri geliştirirken, savunmacılar da bu yöntemlere karşı koymak için savunmalarını günceller. Bu sürekli gelişim, güvenlik uzmanlarının sadece mevcut araçları kullanmayı değil, aynı zamanda bu araçların altında yatan mekanizmaları ve karşı savunma tekniklerini de anlamalarını zorunlu kılar. Örneğin, TCP SYN taraması gibi yarı açık taramaların neden tam bağlantı taramalarından daha gizli olduğunu anlamak, savunma mekanizmalarının nasıl çalıştığına dair derinlemesine bir kavrayış sağlar. Bu dinamik ortam, siber güvenlik profesyonellerinin sürekli öğrenme ve adaptasyon içinde olmalarını gerektiren temel bir gerçeği ortaya koyar. Statik güvenlik çözümleri, hızla değişen tehdit ortamında yetersiz kalacaktır.

## 2. Açık Port Taraması
Port taraması, bir hedef sistemdeki açık veya kapalı portları belirlemek için kullanılan temel bir ağ keşif yöntemidir. Güvenlik uzmanları ve kötü niyetli aktörler, hedefin ağ üzerindeki ayak izini çıkarmak için çeşitli teknikler kullanır.

### Port Tarama Teknikleri
- **TCP Bağlantı Taraması (Connect Scan - -sT):** Hedef port ile tam bir TCP üç yönlü el sıkışmasını (SYN, SYN/ACK, ACK) tamamlamaya çalışır. En kolay tespit edilebilir yöntemdir çünkü sistemin bağlantı kayıtlarında iz bırakır. SYN taramasının mümkün olmadığı durumlarda kullanılır.
- **TCP SYN Taraması (Yarı Açık Tarama / Stealth Scan - -sS):** Bağlantıyı tamamlamadan (SYN, SYN/ACK, RST) açık portları belirlemek için SYN paketleri gönderir. Tam bağlantı kurmadığı için daha gizlidir ve alarm sinyali verme olasılığı daha düşüktür.
- **UDP Taraması (-sU):** Bağlantısız UDP protokolünü kullanan portları bulmak için UDP paketleri gönderir. TCP taramalarına göre daha yavaş ve zordur çünkü UDP yanıtları daha az tahmin edilebilirdir. DNS, SNMP ve DHCP gibi popüler servisler UDP kullanır.
- **FIN, Xmas ve Null Taramaları:** Güvenlik duvarlarını ve IDS sistemlerini atlatmak için alışılmadık bayrak kombinasyonlarına sahip paketler gönderir. İşletim sistemine bağlı olarak farklı yanıtlar alınabilir.
- **Ping Süpürme (Ping Sweep / ICMP Scan - -sn):** Bir ağdaki etkin ana bilgisayarları keşfetmek için ICMP Yankı istekleri gönderir. Genellikle kolayca tespit edilebilir.
- **Boşta Tarama (Idle Scan):** Tarama yapmak için saldırganın IP adresini gizleyen bir "zombi" ana bilgisayar kullanır. Çok yüksek gizlilik sağlar.

### Popüler Araçlar: Nmap ve Masscan Kullanımı
#### Nmap (Network Mapper)
Nmap, ağ tarama, zafiyet tespiti ve bilgi toplama amacı ile kullanılan açık kaynaklı, çok yönlü bir araçtır. Siber güvenlik sektöründe en popüler araçlardan biridir.

**Nmap ile Temel ve Gelişmiş Port Taramaları:**
- **Temel Komut Yapısı:** `nmap [tarama türü][tarama opsiyonları][hedef veya hedefler]`
- **Hedef Belirleme:** Tek bir IP adresi, IP aralığı veya CIDR adreslemesi ile hedefler belirlenebilir.
- **Port Belirleme:** `-p` parametresi ile belirli portlar, `-p-` ile tüm 65535 port veya `--top-ports` ile en çok kullanılan portlar taranabilir.
- **Port Durumları:** Açık, kapalı, filtrelenmiş, erişilebilir ancak durumu tespit edilememiş gibi bilgiler döner.
- **Hızlı Tarama:** `-F` parametresi daha hızlı tarama yapar.
- **Detaylı Çıktı:** `-v`, `-vv`, `-vvv` parametreleri detayları artırır.
- **DNS Çözümlemesi Kontrolü:** `-n`, `-R`, `--system-dns`, `--dns-server` parametreleri DNS kontrolü için kullanılır.
- **Ping Atma:** `--Pn` parametresi ping atmayı devre dışı bırakır.
- **Agresif Tarama:** `-A` parametresi, işletim sistemi tespiti, sürüm tespiti ve script taraması gibi özellikleri etkinleştirir.
- **Çıktı Formatları:** `-oX` (XML), `-oN` (Normal), `-oG` (Grepable) gibi formatlarda kaydedilebilir.
- **Hostları Rastgeleleştirme:** `--randomize-hosts` parametresi taramayı belirginsizleştirir.
- **Neden (Reason) Parametresi:** `--reason` parametresi port durumunun sebebini gösterir.
- **Paket İzleme:** `--packet-trace` parametresi gönderilen ve alınan paketlerin detaylarını gösterir.

#### Masscan ile Yüksek Hızlı Tarama Yetenekleri
Masscan, tüm interneti veya büyük ağları hızlıca taramak için tasarlanmış bir port tarayıcıdır.

- **Temel Kullanım:** `masscan <hedef> -p<portlar>`
- **Hız Kontrolü:** `--rate` parametresi ile saniyedeki paket sayısı ayarlanabilir.
- **Çoklu Port ve Aralık Taraması:** `-p80,443` veya `-p22-25` gibi.
- **Top Portlar:** `--top-ports` en yaygın portları tarar.
- **Hedefleri Hariç Tutma:** `--excludefile` ile IP aralıkları hariç tutulabilir.
- **Duraklatma ve Devam Ettirme:** `paused.conf` dosyası ile tarama devam ettirilebilir.
- **Çıktı Formatları:** XML, JSON, Grepable gibi formatlar desteklenir.
- **Kendi TCP/IP Yığını:** Yerel TCP/IP yığını ile çakışmaları önlemek için ayrı IP veya port engellemesi gerekir.
- **IPv6 Desteği:** IPv4 ve IPv6’yı aynı anda destekler.

### Port Tarama Teknikleri Karşılaştırması
| Tarama Tekniği              | Amaç                                                                 | Gizlilik Seviyesi | Tespit Edilebilirlik       | Örnek Nmap Parametresi |
|----------------------------|----------------------------------------------------------------------|-------------------|----------------------------|------------------------|
| TCP Bağlantı Taraması      | Tam TCP bağlantısı kurarak açık portları kontrol eder                 | Düşük             | Kolayca tespit edilebilir  | `-sT`                 |
| TCP SYN Taraması           | Bağlantıyı tamamlamadan açık portları belirler                       | Orta              | Daha az tespit edilebilir  | `-sS`                 |
| UDP Taraması               | Açık UDP portlarını bulur                                           | Düşük             | Güvenilmez, tespit edilebilir | `-sU`              |
| FIN, Xmas ve Null Taramaları | Güvenlik duvarlarını atlayarak açık portları gizlice tespit eder    | Yüksek            | Gizli                      | `-sF`, `-sX`, `-sN`   |
| Ping Süpürme               | Etkin ana bilgisayarları keşfetmek                                  | Düşük             | Kolayca tespit edilebilir  | `-sn`                 |
| Boşta Tarama               | "Zombi" ana bilgisayar ile IP adresini gizler                       | Çok Yüksek        | Son derece gizli           | `-sI`                 |
| Sürüm Tarama               | Yazılım sürümlerini ve zafiyetleri tespit eder                      | Düşük ila Orta    | Değişken                   | `-sV`                 |

Hız ve gizlilik arasındaki denge, siber güvenlik operasyonlarında sürekli bir zorluktur. Masscan gibi araçlar yüksek hız sunarken, tespit edilme riskini artırır. FIN, Xmas, Null veya Boşta Tarama gibi teknikler daha gizlidir ancak daha yavaştır veya özel koşullar gerektirir.

## 3. Sistem Bilgileri ve Sürüm Tespiti
Sistem ve sürüm tespiti, bir hedef sistemde çalışan servisler hakkında detaylı bilgi toplama sürecidir. Bu bilgiler, potansiyel güvenlik açıklarını belirlemek için kritik öneme sahiptir.

### Banner Grabbing Nedir ve Nasıl Yapılır?
Banner grabbing, bir sunucuda çalışan servisler hakkında (yazılım türü, sürüm numarası, işletim sistemi bilgisi gibi) detaylı bilgi toplama tekniğidir.

- **Aktif Yöntemler:** Hedef sunucuya doğrudan paketler gönderip yanıtları analiz eder. Hızlı ancak tespit edilme riski yüksektir.
- **Pasif Yöntemler:** Sensörler veya üçüncü taraf araçlarla bilgi toplar. Daha gizlidir ve alarm verme olasılığı düşüktür.

**Banner Grabbing Araçları:**
- **Telnet:** Belirlenen IP ve porta bağlanarak servis sürümü bilgisi alınır.
- **Wget ve cURL:** HTTP başlıklarını çeker ve banner grabbing’i otomatikleştirir.
- **NetCat:** `echo "" | nc -vv -n -w1 <hedef IP> <hedef port>` ile banner bilgisi alınır.
- **Nmap:** Açık portları tarar ve yazılım sürümleri hakkında bilgi sağlar.

### Nmap ile Servis ve Sürüm Tespiti (-sV parametresi)
- `-sV`: Açık portta çalışan servisin ne olduğunu bulur.
- `--version-intensity`: Servis analizinin derinliğini kontrol eder (0-9).
- `-A`: İşletim sistemi tespiti, sürüm tespiti ve script taramasını otomatikleştirir.

Banner grabbing ile elde edilen bilgiler (ör. ProFTPD 1.3.5), CVE’ler ile ilişkilendirilebilir. Örneğin, ProFTPD 1.3.5, CVE-2015-3306’ya karşı savunmasızdır. Bu nedenle servis banner’larının gizlenmesi ve bilinen açıkların yamalanması kritik öneme sahiptir.

## 4. Güvenlik Açığı Analizi ve Derecelendirme
Güvenlik açığı analizi, sistemlerdeki zafiyetleri tespit etme, değerlendirme ve önceliklendirme sürecidir.

### Güvenlik Açığı Tarama Araçları
- **Nessus:** >59.000 CVE’yi kapsar, 130.000+ eklenti sunar.
- **OpenVAS:** Açık kaynaklı, güncel CVE veritabanları ile çalışır.
- **Qualys:** Bulut tabanlı, gerçek zamanlı görünürlük sağlar.
- **Burp Suite:** Web uygulamaları için manuel ve otomatik testler sunar.
- **Acunetix:** Kullanıcı dostu, web uygulamalarına odaklanır.
- **Nikto:** Web sunucusu zafiyetlerini tarar.
- **Wireshark:** Ağ trafiğini analiz eder.

### CVE (Common Vulnerabilities and Exposures) Veritabanı Entegrasyonu
CVE, zafiyetleri kataloglayan yetkili bir kaynaktır. Zafiyet tarayıcıları, bulguları NVD gibi veritabanlarıyla karşılaştırır. Birden fazla CVE veritabanı kullanımı, kapsamlı zafiyet kapsamı ve gerçek zamanlı güncellemeler sağlar.

### CVSS (Common Vulnerability Scoring System) Detaylı Açıklama
CVSS, zafiyetlerin teknik şiddetini 0.0-10.0 arasında puanlar:
- **Temel (Base) Metrikler:** Sömürülebilirlik (Saldırı Vektörü, Karmaşıklık, Gerekli Ayrıcalıklar, Kullanıcı Etkileşimi, Kapsam) ve Etki (Gizlilik, Bütünlük, Erişilebilirlik).
- **Zamansal (Temporal) Metrikler:** Sömürü Kodu Olgunluğu, Düzeltme Seviyesi, Rapor Güvenilirliği.
- **Çevresel (Environmental) Metrikler:** Güvenlik Gereksinimleri ve Değiştirilmiş Temel Metrikler.

**CVSS Puanlama:**
| Derecelendirme | CVSS Puanı |
|----------------|------------|
| Yok            | 0.0        |
| Düşük          | 0.1–3.9    |
| Orta           | 4.0–6.9    |
| Yüksek         | 7.0–8.9    |
| Kritik        | 9.0–10.0   |

### Nmap Scripting Engine (NSE) ile Zafiyet Tespiti
NSE, Lua ile yazılmış betiklerle zafiyet tespiti ve bilgi toplama yapar. Örnek kategoriler: `auth`, `broadcast`, `brute`, `default`, `discovery`, `dos`, `exploit`, `external`, `fuzzer`, `intrusive`, `malware`, `safe`, `version`, `vuln`.

**Örnek Kullanımlar:**
- Varsayılan scriptler: `nmap -sC <target>`
- Belirli kategori: `nmap --script discovery <target_ip>`
- Zafiyet filtreleme: `nmap --script=vulners --script-args mincvss=5.0 example.com`

## 5. Güvenlik Taraması Sonuçlarının Görselleştirilmesi
Veri görselleştirme, tarama sonuçlarını anlaşılır içgörülere dönüştürür.

### Popüler Görselleştirme Araçları
- **Grafana:** Açık kaynaklı, güvenlik tarama verilerini görselleştirir.
- **Diğer Araçlar:** Tableau, PowerBI, Plotly, D3.js, Google Charts.

### Nmap XML Çıktılarının Grafana ile Entegrasyonu
- **nmap-did-what** projesi, Nmap XML çıktısını SQLite veritabanına işler ve Grafana ile görselleştirir.
- **Kurulum Adımları:**
  1. nmap-did-what deposu klonlanır.
  2. Nmap XML çıktısı SQLite’a işlenir.
  3. Docker Compose ile Grafana başlatılır.
  4. http://localhost:3000 adresinden panel görüntülenir.

## 6. MAC Adresi Tespiti
MAC adresi, cihazları benzersiz şekilde tanımlayan 48 bitlik bir adrestir.

### MAC Adresi Bulma Yöntemleri
| İşletim Sistemi | Yöntem/Komut                     | Açıklama                                      |
|-----------------|----------------------------------|-----------------------------------------------|
| Windows         | `getmac /v`, `ipconfig /all`     | "Fiziksel Adres" altında MAC adresi gösterir.  |
| Linux           | `ifconfig -a`, `arp -a`          | "HWaddr" veya IP-MAC eşleşmeleri gösterir.     |
| macOS           | Sistem Ayarları > Ağ > Gelişmiş | Donanım sekmesinde MAC adresi bulunur.         |
| iOS/Android     | Ayarlar > Wi-Fi > Gelişmiş       | "Wi-Fi Adresi" olarak MAC adresi gösterir.     |

### OUI (Organizationally Unique Identifier) Veritabanı Kullanımı
OUI, MAC adresinin ilk 24 bitini temsil eder ve üreticiyi tanımlar. `oui.is` veya `dnschecker.org/mac-lookup.php` gibi araçlarla üretici bilgisi bulunabilir.

## 7. Güvenlik Duvarı Atlatma Yöntemleri
Güvenlik duvarları, ağ trafiğini filtreler, ancak atlatma yöntemleri vardır.

### Güvenlik Duvarı Türleri
- **Paket Filtreleme:** IP ve port numaralarına göre filtreler.
- **Durum Denetimi:** Bağlantı durumunu izler.
- **Uygulama Katmanı:** Protokol düzeyinde analiz yapar.
- **Yeni Nesil (NGFW):** Antivirüs, IPS gibi özellikler sunar.

### Güvenlik Duvarı Tespit Teknikleri
- **Nmap:** `-sA` (ACK taraması), `firewall-bypass.nse` scripti.
- **Hping3:** TCP, UDP, ICMP paketleriyle güvenlik duvarı test edilir.

### Paket Manipülasyonu Stratejileri
- **Parçalama:** `-f` veya `--mtu` ile paketler parçalanır.
- **Decoy Tarama:** `-D RND:10` ile sahte IP’ler kullanılır.
- **Kaynak Port Manipülasyonu:** Port tabanlı kısıtlamaları atlatır.
- **Yavaş Tarama:** Tespit edilmekten kaçınır.

### Tünelleme Yöntemleri
- **SSH Tünelleme:** `ssh -D` ile trafik tünellenir.
- **SSL/TLS Tünelleme:** HTTPS ile içeriği gizler.

### Proxy Zincirleme
- **Proxychains-ng:** `/etc/proxychains4.conf` ile yapılandırılır.
- **Zincir Türleri:** Dinamik, Katı, Dairesel, Rastgele.

### Rate Limiting Bypass Yöntemleri
- IP adresi değiştirme, birden fazla hesap kullanımı, istek geciktirme, HTTP başlık manipülasyonu, dinamik token kullanımı.

## 8. Sonuç ve Öneriler
### Temel Çıkarımlar
- **Dinamik Keşif ve Savunma:** Sürekli öğrenme ve adaptasyon gereklidir.
- **Bilgi Toplama:** Banner grabbing ve sürüm tespiti zafiyetleri ortaya çıkarır.
- **Zafiyet Yönetimi:** Risk odaklı önceliklendirme ve CVE entegrasyonu kritiktir.
- **Veri Görselleştirme:** Grafana ile tarama verileri anlamlı hale gelir.
- **MAC Adresi:** Cihaz tanımlama için önemlidir, ancak spoofing’e karşı dikkatli olunmalıdır.
- **Atlatma ve Savunma:** Çok katmanlı savunma stratejileri gereklidir.

### Öneriler
- Sürekli eğitim ve beceri geliştirme.
- Katmanlı güvenlik yaklaşımı benimsenmeli.
- Risk odaklı zafiyet yönetimi uygulanmalı.
- Otomatik tarama ve görselleştirme kullanılmalı.
- Güvenlik duvarı kuralları düzenli test edilmeli.
- Tehdit istihbaratı entegre edilmeli.
- Araçlar etik ve yasal sınırlar içinde kullanılmalı.

Siber güvenlik, sürekli değişen bir manzara olduğundan, proaktif bir yaklaşımla tehditlere karşı dirençli kalmak elzemdir.
