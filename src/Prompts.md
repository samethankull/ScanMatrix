Siber Güvenlikte Kapsamlı Ağ Keşfi, Zafiyet Analizi ve Savunma Stratejileri
1. Giriş
Siber güvenlik alanında proaktif bir duruş sergilemek, potansiyel tehditleri ve zafiyetleri henüz bir saldırıya dönüşmeden önce tespit etmekle başlar. Keşif (reconnaissance) ve analiz, bu sürecin temel taşlarıdır. Ağdaki cihazları, açık portları, çalışan servisleri ve bunların sürümlerini belirlemek, bir sistemin güvenlik duruşunu anlamak için kritik ilk adımlardır. Bu bilgiler, sızma testleri, zafiyet değerlendirmeleri ve genel ağ güvenliği yönetimi için hayati önem taşır.
Bu rapor, ağ keşfinin temel bileşenlerinden başlayarak, sistem ve sürüm bilgilerinin nasıl elde edileceğini, bulunan güvenlik açıklarının nasıl analiz edilip derecelendirileceğini, bu verilerin nasıl görselleştirileceğini, ağdaki cihazların MAC adreslerinin nasıl tespit edileceğini ve son olarak, güvenlik duvarlarını atlatma yöntemlerini detaylı bir şekilde ele alacaktır. Amacımız, okuyucuya bu siber güvenlik alanlarında derinlemesine bir anlayış ve pratik uygulama yeteneği kazandırmaktır.
Siber güvenlikte keşif ve savunma mekanizmaları arasında sürekli bir gelişim gözlemlenmektedir. Port tarama ve bilgi toplama teknikleri (Nmap, Masscan gibi araçlarla) sürekli olarak evrimleşirken, güvenlik duvarları ve Saldırı Tespit/Önleme Sistemleri (IDS/IPS) de bu taramaları tespit etmek ve engellemek için sürekli olarak güncellenmektedir. Bu durum, siber güvenlikte dinamik bir "kedi fare oyunu" olduğunu ortaya koymaktadır. Saldırganlar yeni atlatma yöntemleri geliştirirken, savunmacılar da bu yöntemlere karşı koymak için savunmalarını günceller. Bu sürekli gelişim, güvenlik uzmanlarının sadece mevcut araçları kullanmayı değil, aynı zamanda bu araçların altında yatan mekanizmaları ve karşı savunma tekniklerini de anlamalarını zorunlu kılar. Örneğin, TCP SYN taraması gibi yarı açık taramaların neden tam bağlantı taramalarından daha gizli olduğunu anlamak, savunma mekanizmalarının nasıl çalıştığına dair derinlemesine bir kavrayış sağlar. Bu dinamik ortam, siber güvenlik profesyonellerinin sürekli öğrenme ve adaptasyon içinde olmalarını gerektiren temel bir gerçeği ortaya koyar. Statik güvenlik çözümleri, hızla değişen tehdit ortamında yetersiz kalacaktır.
2. Açık Port Taraması
Port taraması, bir hedef sistemdeki açık veya kapalı portları belirlemek için kullanılan temel bir ağ keşif yöntemidir. Güvenlik uzmanları ve kötü niyetli aktörler, hedefin ağ üzerindeki ayak izini çıkarmak için çeşitli teknikler kullanır.
Port Tarama Teknikleri

TCP Bağlantı Taraması (Connect Scan - -sT): Bu teknik, hedef port ile tam bir TCP üç yönlü el sıkışmasını (SYN, SYN/ACK, ACK) tamamlamaya çalışır. En kolay tespit edilebilir yöntemdir çünkü sistemin bağlantı kayıtlarında iz bırakır. SYN taramasının mümkün olmadığı durumlarda kullanılır.
TCP SYN Taraması (Yarı Açık Tarama / Stealth Scan - -sS): Bağlantıyı tamamlamadan (SYN, SYN/ACK, RST) açık portları belirlemek için SYN paketleri gönderir. Tam bağlantı kurmadığı için daha gizlidir ve alarm sinyali verme olasılığı daha düşüktür. Bu yöntem, tam bir TCP bağlantısı kurmadan veya alarm sinyali vermeden açık portları ortaya çıkarır.
UDP Taraması (-sU): Bağlantısız UDP protokolünü kullanan portları bulmak için UDP paketleri gönderir. TCP taramalarına göre daha yavaş ve zordur çünkü UDP yanıtları daha az tahmin edilebilirdir. DNS, SNMP ve DHCP gibi popüler servisler UDP kullanır. Güvenlik uzmanları genellikle bu taramaları ihmal etme hatasına düşebilir, ancak UDP portlarına yönelik güvenlik açıkları da bulunmaktadır.
FIN, Xmas ve Null Taramaları: Bu teknikler, güvenlik duvarlarını ve saldırı tespit sistemlerini (IDS) atlatmak için alışılmadık bayrak kombinasyonlarına sahip (FIN, URG, PSH, ACK, RST, SYN) paketler göndermeyi içerir. İşletim sistemine bağlı olarak farklı yanıtlar alınabilir, bu da gizli ağ haritalamasına olanak tanır.
Ping Süpürme (Ping Sweep / ICMP Scan - -sn): Bir ağdaki etkin ana bilgisayarları keşfetmek için ICMP Yankı istekleri gönderir. Genellikle kolayca tespit edilebilir. Nmap'te -sn parametresi, port taraması yapmadan sadece host keşfi için kullanılır.
Boşta Tarama (Idle Scan): Tarama yapmak için saldırganın IP adresini gizleyen bir "zombi" ana bilgisayar kullanır. Bu, çok yüksek gizlilik sağlayan bir yöntemdir.

Popüler Araçlar: Nmap ve Masscan Kullanımı
Nmap (Network Mapper)
Nmap, ağ tarama, zafiyet tespiti ve bilgi toplama amacı ile kullanılan açık kaynaklı, çok yönlü bir araçtır. Siber güvenlik sektöründe en popüler araçlardan biridir ve birçok tarama işlemi gerçekleştirebilir.
Nmap ile Temel ve Gelişmiş Port Taramaları:

Temel Komut Yapısı: Nmap'in kullanımı ilk bakışta karmaşık görünse de, basit ve sade bir mantığa sahiptir: nmap [tarama türü][tarama opsiyonları][hedef veya hedefler].
Hedef Belirleme: Tek bir IP adresi, bir IP adresi aralığı veya CIDR (Classless Inter-Domain Routing) adreslemesi kullanılarak hedefler belirlenebilir.
Port Belirleme: -p parametresi ile belirli portlar (örn. -p 21,22,80), -p- ile tüm 65535 port veya --top-ports ile en çok kullanılan portlar taranabilir.
Port Durumları: Tarama sonrası open (açık), closed (kapalı), filtered (filtrelenmiş), unfiltered (erişilebilir ancak durumu tespit edilememiş), open|filtered (açık veya filtrelenmiş olduğu tespit edilememiş) ve closed|filtered (kapalı veya filtrelenmiş olduğu tespit edilememiş) gibi farklı bilgiler dönecektir.
Hızlı Tarama: -F parametresi daha hızlı tarama yapar.
Detaylı Çıktı: -v, -vv, -vvv parametreleri ekrana gösterilecek detayları artırır.
DNS Çözümlemesi Kontrolü: -n parametresi DNS çözümlemesi yapmazken, -R ters DNS çözümlemesi yapar. --system-dns ve --dns-server parametreleri DNS sunucularını kontrol etmek için kullanılır.
Ping Atma: --Pn parametresi ping atmak istenmediğinde kullanılır.
Agresif Tarama: -A parametresi, işletim sistemi tespiti, sürüm tespiti ve script taraması gibi birçok keşif özelliğini otomatik olarak etkinleştirir.
Çıktı Formatları: -oX (XML), -oN (Normal), -oG (Grepable) gibi parametrelerle tarama günlüğü belirli dosyalara kaydedilebilir.
Hostları Rastgeleleştirme: --randomize-hosts parametresi, ağda yapılan taramayı belirginsizleştirerek bazı IDS ve IPS sistemlerinin taramayı tespit edip engellemesini zorlaştırır.
Neden (Reason) Parametresi: --reason parametresi, Nmap taramasında hedef makinesinin hangi keşif testlerine yanıt verdiğini açıklayarak port durumunun sebebini gösterir.
Paket İzleme: --packet-trace parametresi, tarama süresince gönderilen ve alınan her paketin detaylarını (sıra numaraları, TTL değerleri, TCP bayrakları gibi) gösterir.

Masscan ile Yüksek Hızlı Tarama Yetenekleri
Masscan, tüm interneti veya çok büyük ağları mümkün olan en kısa sürede taramak için tasarlanmış, saniyede milyonlarca paket gönderebilen yüksek hızlı bir port tarayıcıdır. Robert Graham'a göre, tüm interneti saniyede yaklaşık 10 milyon paket hızında 6 dakikadan daha kısa sürede tarayabilir.

Temel Kullanım: masscan <hedef> -p<portlar> temel komut yapısıdır.
Hız Kontrolü: --rate parametresi ile saniyedeki paket sayısı ayarlanabilir (varsayılan 100 pps, 10 milyon pps'ye kadar). Ancak bu kadar hızlı taramalar, sistemin internette engellenmesine veya barındırma sağlayıcısına şikayetlere yol açabilir.
Çoklu Port ve Aralık Taraması: Birden fazla port virgülle (örn. -p80,443) veya bir port aralığı tire ile (örn. -p22-25) belirtilebilir.
Top Portlar: --top-ports parametresi, Nmap'in en popüler portları gibi en yaygın portları taramak için kullanılır.
Hedefleri Hariç Tutma: --excludefile parametresi ile hariç tutulacak IP aralıklarını içeren bir dosya belirtilebilir.
Duraklatma ve Devam Ettirme: Masscan'a özgü bir özellik, taramaları kolayca duraklatıp devam ettirebilmesidir. Ctrl-C tuşuna basıldığında, taramanın tüm ayarlarını ve ilerlemesini içeren paused.conf adlı bir dosya oluşturulur ve bu tarama --resume paused.conf ile devam ettirilebilir.
Çıktı Formatları: Masscan, varsayılan olarak metin dosyaları üretir, ancak bunları XML (-oX), Binary, Grepable (-oG), JSON (-oJ) ve List (-oL) gibi çeşitli formatlara dönüştürmek kolaydır.
Kendi TCP/IP Yığını: Masscan, kendi ad hoc TCP/IP yığınını kullanır. Bu durum, yerel TCP/IP yığını ile çakışmalara (RST paketleri) neden olabilir. Bunu önlemenin en kolay yolu, Masscan'a ayrı bir IP adresi atamak veya Masscan'ın kullandığı kaynak portu güvenlik duvarında engellemektir (örn. iptables -A INPUT -p tcp --dport 61000 -j DROP).
IPv6 Desteği: Masscan, özel bir mod olmaksızın hem IPv4 hem de IPv6 adreslerini aynı anda destekler.

Port Tarama Teknikleri Karşılaştırması
Aşağıdaki tablo, farklı port tarama tekniklerinin temel özelliklerini, amaçlarını ve güvenlik sistemleri tarafından ne kadar kolay veya zor tespit edilebildiklerini karşılaştırmaktadır. Bu, güvenlik profesyonellerinin hangi senaryoda hangi tarama tekniğini kullanması gerektiği konusunda bilinçli kararlar vermesine yardımcı olur. Özellikle gizlilik seviyesi ve tespit edilebilirlik bilgisi, bir saldırının "ayak izini" minimize etme stratejilerini belirlemede kritik bir referans noktasıdır.



Tarama Tekniği
Amaç
Gizlilik Seviyesi
Tespit Edilebilirlik
Örnek Nmap Parametresi



TCP Bağlantı Taraması
Hedef portun açık olup olmadığını kontrol etmek için tam TCP bağlantısı kurar.
Düşük
Kolayca tespit edilebilir
-sT


TCP SYN Taraması
TCP el sıkışmasını tamamlamadan açık portları belirler.
Orta
Daha az tespit edilebilir
-sS


UDP Taraması
Hedef sistemdeki açık UDP portlarını bulur.
Düşük
Güvenilmez ve tespit edilebilir
-sU


FIN, Xmas ve Null Taramaları
Güvenlik duvarlarını atlamak ve açık portları gizlice tespit etmek.
Yüksek
Gizli
-sF, -sX, -sN


Ping Süpürme
Bir ağdaki etkin ana bilgisayarları keşfetmek.
Düşük
Kolayca tespit edilebilir
-sn


Boşta Tarama
Saldırganın IP adresini gizleyen "zombi" ana bilgisayar kullanır.
Çok Yüksek
Son derece gizli
-sI


Sürüm Tarama
Yazılım sürümlerini belirlemek ve güvenlik açıklarını tespit etmek.
Düşük ila Orta
Değişken
-sV


Hız ve gizlilik arasındaki denge, siber güvenlik operasyonlarında sürekli bir zorluktur. Masscan gibi araçlar interneti dakikalar içinde tarayabilecek kadar yüksek hız sunarken, bu hız genellikle tespit edilme riskini artırır. Yüksek hızlı taramalar, genellikle daha fazla ağ trafiği ve "gürültü" üretir, bu da IDS/IPS sistemleri tarafından kolayca algılanabilir. Öte yandan, FIN, Xmas, Null gibi taramalar veya Boşta Tarama gibi teknikler çok daha gizlidir ancak genellikle daha yavaştır veya özel koşullar gerektirir. Bu durum, sızma testlerinde veya keşif operasyonlarında hız ile gizlilik arasında sürekli bir denge kurma ihtiyacını ortaya koyar. Güvenlik profesyonelleri, hedeflerine ve operasyonlarının hassasiyetine göre doğru aracı ve tekniği seçmelidir. Her zaman en hızlı tarama en iyi tarama değildir; bazen tespit edilmekten kaçınmak, bilgi toplama sürecinin başarısı için daha önemlidir.
3. Sistem Bilgileri ve Sürüm Tespiti
Sistem ve sürüm tespiti, bir hedef sistemde çalışan servisler hakkında detaylı bilgi toplama sürecidir. Bu bilgiler, potansiyel güvenlik açıklarını belirlemek için kritik öneme sahiptir.
Banner Grabbing Nedir ve Nasıl Yapılır?
Banner grabbing, bir sunucuda çalışan servisler hakkında (yazılım türü, sürüm numarası, işletim sistemi bilgisi gibi) detaylı bilgi toplama tekniğidir. Bu bilgiler, saldırganlar için ağa sızma yollarını daraltabilir ve hatta sömürülebilir zafiyetleri ortaya çıkarabilir.

Aktif Yöntemler: Hedef sunucuya doğrudan paketler gönderip yanıtları analiz etmeyi içerir. Bu yöntemler daha hızlı bilgi sağlar ancak tespit edilme riski daha yüksektir.
Pasif Yöntemler: Ağdaki stratejik olarak yerleştirilmiş sensörlere veya üçüncü taraf ağ araçlarına dayanır. Sunucuyla doğrudan etkileşim kurmadan bilgi topladığı için daha gizlidir ve alarm verme olasılığı daha düşüktür.

Banner Grabbing Araçları

Telnet: Belirlenen bir IP adresi ve porta bağlantı açarak servis sürümü hakkında bilgi edinmek için kullanılabilir. Özellikle 23 numaralı port (Telnet servisleri) detaylı servis bilgisi için sıkça hedeflenir.
Wget ve cURL: Wget, bir sunucudan dosya indirme yeteneğiyle banner bilgisi toplamaya yardımcı olabilir. cURL ise HTTP başlıklarını (sunucu tipi, çerezler gibi) çekebilir ve banner grabbing görevlerini otomatikleştirmek için betiklenebilir.
NetCat: Linux sistemlerinde önceden yüklü gelen popüler bir araçtır. echo "" | nc -vv -n -w1 <hedef IP adresi> <hedef port> gibi komutlarla banner bilgisi çekilebilir.
Nmap: Açık portları tarayan ve işletim sistemleri ile yazılım sürümleri hakkında detaylı bilgi sağlayan güçlü bir araçtır. Sistemin yapılandırması ve potansiyel zafiyetler hakkında detaylı bilgiler sağlayabilir.

Nmap ile Servis ve Sürüm Tespiti (-sV parametresi)
Nmap'in en güçlü özelliklerinden biri, açık portlarda çalışan servislerin ne olduğunu ve sürüm bilgilerini tespit etme yeteneğidir.

-sV parametresi, açık portta çalışan servisin ne olduğunu bulmaya çalışır. Bu, potansiyel güvenlik açıklarını tespit etmek için temel bir adımdır.
--version-intensity bayrağı (0 ile 9 arasında ayarlanabilir), servis analizinin derinliğini kontrol etmeye olanak tanır. Daha az müdahaleci ve hızlı banner grabbing için --version-intensity 0 kullanılabilir.
-A (Agresif Tarama) parametresi, işletim sistemi tespiti, sürüm tespiti (-sV) ve varsayılan script taraması (-sC) gibi birçok keşif özelliğini otomatik olarak etkinleştirir.

Banner grabbing ile elde edilen sürüm bilgileri (örneğin, ProFTPD 1.3.5) doğrudan bilinen güvenlik açıkları (CVE'ler) ile ilişkilendirilebilir. Bu, bilgi toplama aşamasının neden sızma testlerinin ve zafiyet yönetiminin kritik bir parçası olduğunu gösterir. Örneğin, ProFTPD 1.3.5 sürümünün CVE-2015-3306'ya karşı savunmasız olduğu NVD (National Vulnerability Database) üzerinden hızlıca araştırılmıştır. Bu, bir aracın (Nmap/Telnet/Netcat) çıktısının başka bir bilgi kaynağı (NVD) ile entegre edilerek eyleme dönüştürülebilir bir bilgiye nasıl dönüştürüldüğünü gösterir. Basit bir sürüm bilgisi, saldırganlar için potansiyel bir "anahtar" haline gelebilir. Bu nedenle, savunmacıların servis banner'larını gizlemesi veya gereksiz bilgileri ifşa etmemesi, bilinen güvenlik açıklarını yamalaması ve ifşa edilen bilgilerin yetkisiz erişime yardımcı olmamasını sağlaması kritik öneme sahiptir.
4. Güvenlik Açığı Analizi ve Derecelendirme
Güvenlik açığı analizi, sistemlerdeki zafiyetleri tespit etme, değerlendirme ve önceliklendirme sürecidir. Bu süreçte çeşitli araçlar ve standart metodolojiler kullanılır.
Güvenlik Açığı Tarama Araçları
Bu araçlar, bilinen güvenlik açıklarını ve zafiyetleri tespit etmek için veritabanlarını kullanır, detaylı raporlar sunar ve düzeltme önerileri sağlar.

Nessus: En popüler ve kapsamlı ticari güvenlik açığı tarama araçlarından biridir. Geniş bir zafiyet veritabanına, gelişmiş tarama yeteneklerine ve sık güncellenen bir veritabanına sahiptir. Ağ cihazları, sunucular, iş istasyonları ve yapılandırma incelemeleri için derinlemesine değerlendirmeler sunar. 59.000'den fazla CVE'yi kapsar ve 130.000'den fazla eklentiye sahiptir. Nessus Essentials ile 16 IP'ye kadar ücretsiz tarama imkanı sunar.
OpenVAS (Open Vulnerability Assessment System): Açık kaynaklı bir zafiyet tarama platformudur. Nessus'a benzer şekilde çalışır, kapsamlı analizler için güncel CVE veritabanları ile entegre çalışır ve detaylı risk analiz raporları sunar. Ücretsiz olması nedeniyle popüler bir tercihtir.
Qualys: Bulut tabanlı kapsamlı bir zafiyet yönetimi platformudur. Gerçek zamanlı görünürlük ve eyleme dönüştürülebilir içgörüler sağlar. Web uygulamaları, ağlar ve işletim sistemleri dahil geniş bir yelpazede tarama yapabilir.
Burp Suite: Özellikle web uygulama güvenliği için kullanılan bir güvenlik açığı tarama aracıdır. XSS (Cross-Site Scripting), SQL Enjeksiyonu gibi web tabanlı zafiyetleri tespit eder. Manuel ve otomatik testler için geniş bir araç seti sunar ve sızma testlerinde yaygın olarak tercih edilir.
Acunetix: Web uygulamaları için tasarlanmış, kullanıcı dostu arayüze ve güçlü raporlama özelliklerine sahip bir tarama aracıdır.
Nikto: Web sunucularındaki bilinen zafiyetleri tarar.
Wireshark: Ağ trafiğini yakalayıp detaylı analiz ederek ağdaki olası güvenlik açıklarını tespit edebilir.

Aşağıdaki tablo, piyasada yaygın olarak kullanılan güvenlik açığı tarama araçlarını karşılaştırarak, güvenlik profesyonellerinin kendi ihtiyaçlarına en uygun aracı seçmesine yardımcı olur. Her aracın kendine özgü güçlü yönleri ve odak alanları vurgulanarak, karar verme süreci kolaylaştırılır. CVE kapsamı ve entegrasyon yetenekleri gibi bilgiler, modern zafiyet yönetiminde bir aracın ne kadar etkili olabileceğini gösterir.



Araç Adı
Tür
Odak Alanı
CVE Kapsamı
Önemli Özellikler



Nessus
Ticari
Ağ, Sunucu, İş İstasyonu
>59.000 CVE
Kapsamlı veritabanı, 130.000+ eklenti, detaylı raporlama, esnek lisanslama


OpenVAS
Açık Kaynak
Ağ, Web Uygulaması, İşletim Sistemi
Güncel CVE veritabanları
Ücretsiz, kapsamlı analiz, detaylı risk raporları


Qualys
Bulut Tabanlı
Web Uygulaması, Ağ, İşletim Sistemi
Geniş kapsamlı
Gerçek zamanlı görünürlük, eyleme dönüştürülebilir içgörüler, güçlü API entegrasyonu


Burp Suite
Ticari/Ücretsiz
Web Uygulaması
Web tabanlı zafiyetler
Manuel ve otomatik testler için geniş araç seti


Acunetix
Ticari
Web Uygulaması
SQLi, XSS, yapılandırma hataları
Kullanıcı dostu arayüz, güçlü raporlama


Nikto
Açık Kaynak
Web Sunucusu
Bilinen web sunucusu zafiyetleri
Web sunucusu yapılandırma ve zafiyet taraması


Wireshark
Açık Kaynak
Ağ Trafiği Analizi
Ağdaki olası açıklar
Paket analizi, veri akışındaki tehdit tespiti


CVE (Common Vulnerabilities and Exposures) Veritabanı Entegrasyonu
CVE, halka açık olarak açıklanmış siber güvenlik zafiyetlerini kataloglayan yetkili bir kaynaktır. Bu veritabanları, zafiyet tarama araçlarının bilinen zafiyetleri tespit etmesi için temel oluşturur.

Entegrasyon Metodolojileri: Zafiyet tarayıcıları, hedef ortamdaki bulgularını NVD (National Vulnerability Database) gibi CVE veritabanlarındaki girdilerle karşılaştırır. Bir eşleşme bulunduğunda, zafiyeti işaretler, raporlar ve düzeltme seçenekleri sunar.
Birden Fazla CVE Veritabanı Entegrasyonunun Faydaları: Birden fazla CVE veritabanı ile entegrasyon, kapsamlı zafiyet kapsamı (çeşitli yetkili kaynaklardan veri çekme), gerçek zamanlı güncellemeler (yeni zafiyetler açıklandığında anında bildirim), gelişmiş tespit güvenilirliği (çapraz doğrulama ile yanlış pozitifleri azaltma), derinlemesine analiz, proaktif tehdit azaltma (erken uyarı sistemi ve bilinçli karar verme) ve sorunsuz entegrasyon (mevcut altyapı ile uyum) gibi önemli faydalar sunar.
NVD (National Vulnerability Database): ABD hükümeti tarafından yönetilen, SCAP (Security Content Automation Protocol) kullanarak standart tabanlı zafiyet yönetimi verilerini içeren bir depodur. NVD, CVE listesinden gelen zafiyetlere CVSS puanları atar. NVD API'si, tek bir CVE veya CVE koleksiyonu hakkında bilgi almak için kullanılır, ancak büyük veri kümeleri için ofset tabanlı sayfalama uygular ve 120 günlük tarih aralığı sınırı gibi kısıtlamaları vardır. Yerel bir CVE veritabanı kurmak (örneğin, PostgreSQL ile CVE Database Manager kullanarak), API hız sınırlamalarını aşma ve daha hızlı erişim sağlama faydaları sunar, özellikle hava boşluklu (air-gapped) veya yüksek güvenlikli ortamlarda kullanışlıdır.

CVSS (Common Vulnerability Scoring System) Detaylı Açıklama
CVSS, güvenlik zafiyetlerinin teknik şiddetini değerlendirmek ve iletmek için endüstri standardı bir çerçevedir. FIRST tarafından sürdürülür ve her zafiyete 0.0 ile 10.0 arasında bir puan atar. Bu puanlar, ekiplerin riskleri önceliklendirmesine yardımcı olur. CVSS, zafiyetleri tutarlı bir şekilde karşılaştırmak için güvenlik ekiplerine standart bir yöntem sunar.
Temel (Base) Metrikler
Zafiyetin doğasında bulunan, zamanla ve farklı dağıtım ortamlarında sabit kalan özelliklerini yansıtır. Sömürülebilirlik (Exploitability) ve Etki (Impact) olmak üzere iki ana bileşeni vardır.
Sömürülebilirlik Metrikleri:

Saldırı Vektörü (AV): Saldırganın zafiyeti nasıl sömürebileceğini gösterir (Ağ (N), Komşu Ağ (A), Yerel (L), Fiziksel (P)). Ağ üzerinden sömürülebilen zafiyetler daha yüksek puan alır.
Saldırı Karmaşıklığı (AC): Sömürünün gerektirdiği koşulları (Düşük (L)/Yüksek (H)) tanımlar. Daha az karmaşık saldırılar daha yüksek puan alır.
Gerekli Ayrıcalıklar (PR): Saldırganın sömürüden önce sahip olması gereken ayrıcalık seviyesi (Yok (N), Düşük (L), Yüksek (H)). Ayrıcalık gerektirmeyen saldırılar daha yüksek puan alır.
Kullanıcı Etkileşimi (UI): Saldırının başarılı olması için kullanıcı etkileşimi gerekip gerekmediğini (Yok (N), Gerekli (R)) gösterir. Kullanıcı etkileşimi gerektirmeyen saldırılar daha yüksek puan alır.
Kapsam (S): Zafiyetin yalnızca bileşeni mi yoksa güvenlik kapsamının dışındaki kaynakları mı etkilediğini gösterir (Değişmedi (U), Değişti (C)). Kapsam değişikliği olan zafiyetler daha yüksek puan alır.

Etki (Impact) Metrikleri (CIA):Başarılı bir şekilde sömürülen zafiyetin gizlilik (Confidentiality - C), bütünlük (Integrity - I) ve erişilebilirlik (Availability - A) üzerindeki etkisini ölçer (Yüksek (H), Düşük (L), Yok (N)).
Zamansal (Temporal) Metrikler
Sömürü tekniklerinin veya kodunun mevcut durumu, yamaların veya geçici çözümlerin varlığı veya zafiyetin açıklamasındaki güvenilirlik gibi zamanla değişebilen faktörlere göre puanı ayarlar.

Sömürü Kodu Olgunluğu (E): Zafiyetin saldırıya uğrama olasılığını ölçer (Tanımlanmamış (X), Yüksek (H), Fonksiyonel (F), Kavram Kanıtı (P), Kanıtlanmamış (U)).
Düzeltme Seviyesi (RL): Düzeltme işlemi tamamlandıkça azalan aciliyeti yansıtır (Tanımlanmamış (X), Kullanılamıyor (U), Geçici Çözüm (W), Geçici Düzeltme (T), Resmi Düzeltme (O)).
Rapor Güvenilirliği (RC): Zafiyetin varlığına ve bilinen teknik detayların güvenilirliğine olan güven derecesini ölçer (Tanımlanmamış (X), Onaylandı (C), Makul (R), Bilinmiyor (U)).

Çevresel (Environmental) Metrikler
Analistin, etkilenen BT varlığının kuruluş için önemi, tamamlayıcı/alternatif güvenlik kontrolleri, gizlilik, bütünlük ve erişilebilirlik gereksinimleri gibi belirli bir ortama göre CVSS puanını özelleştirmesine olanak tanır.

Güvenlik Gereksinimleri (CR, IR, AR): Kuruluş için gizlilik, bütünlük ve erişilebilirliğin önemine göre puanı özelleştirir (Tanımlanmamış (X), Yüksek (H), Orta (M), Düşük (L)).
Değiştirilmiş Temel Metrikler (MAV, MAC, MPR, MUI, MS, MC, MI, MA): Kullanıcının ortamının belirli özelliklerine göre bireysel Temel metrikleri geçersiz kılar. Bu, belirli bir ortamdaki hafifletmeleri veya artan şiddeti yansıtmak için kullanılır.

CVSS Puanlama ve Şiddet Derecelendirmesi
CVSS puanları, belirli şiddet bantlarına ayrılır:



Derecelendirme
CVSS Puanı



Yok
0.0


Düşük
0.1 – 3.9


Orta
4.0 – 6.9


Yüksek
7.0 – 8.9


Kritik
9.0 – 10.0


CVSS Sınırlamaları
CVSS, zafiyetin teknik şiddetini ölçer ancak gerçek riskin tamamını yansıtmaz. Sömürü olasılığını (EPSS gibi sistemler bunu ekler) veya iş etkisini dikkate almaz. NVD'ye CVE'lerin yayınlanmasında gecikmeler yaşanabilir. Bu durum, zafiyet yönetiminin sadece tarama ve puanlamadan ibaret olmadığını, aynı zamanda sürekli izleme ve risk odaklı önceliklendirme gerektirdiğini gösterir.
Nmap Scripting Engine (NSE) ile Zafiyet Tespiti
NSE, Nmap'in en güçlü ve esnek özelliklerinden biridir. Kullanıcıların Lua programlama dilini kullanarak çeşitli ağ görevlerini otomatikleştiren betikler yazmasına olanak tanır. Bu betikler, ağdaki cihazları keşfetme, servisleri tanımlama, bilgi toplama, zafiyet tespiti ve hatta zafiyet sömürüsü gibi geniş bir yelpazede kullanılabilir.
NSE Script Kategorileri
Betikler, kullanım amaçlarına göre kategorilere ayrılır. Başlıca kategoriler şunlardır:



Kategori Adı
Açıklama
Örnek Scriptler



auth
Kimlik doğrulama ve kullanıcı ayrıcalıklarıyla ilgili testler yapar.
ftp-anon, x11-access


broadcast
Ağ keşfi için yayın sorguları kullanır.



brute
Kaba kuvvet saldırılarıyla kimlik bilgilerini test eder.
dns-brute, smb-brute, http-brute


default
-sC parametresiyle varsayılan olarak çalıştırılan yaygın betikler. Bazıları müdahaleci olabilir.
ssh-hostkey, html-title


discovery
Hedef sistem hakkında bilgi toplar (OS, servisler, açık portlar).
smb-enum-shares, snmp-sysdescr


dos
Hizmet reddi saldırılarına neden olabilecek testler yapar.
dns-fuzz


exploit
Bilinen zafiyetleri aktif olarak sömürmeyi amaçlar. Tehlikeli olabilir.
ftp-vsftpd-backdoor (CVE-2011-2523), smb-vuln-ms08-067


external
Üçüncü taraf hizmetlerle veya veritabanlarıyla etkileşime girer.
whois-ip


fuzzer
Uygulamalara, servislere veya ağlara karşı fuzzing saldırıları yapar.
dns-fuzz


intrusive
Hedef sistemi etkileyebilecek veya kötü niyetli olarak algılanabilecek agresif betiklerdir.
http-open-proxy, snmp-brute


malware
Hedef sistemde kötü amaçlı yazılım varlığını tespit eder.
smtp-strangeport


safe
Güvenli ve müdahaleci olmayan betiklerdir.
ssh-hostkey, html-title


version
Daha gelişmiş sürüm tespiti için kullanılır.



vuln
Belirli bilinen zafiyetleri kontrol eder ve yalnızca bulunduğunda sonuç raporlar.
realvnc-auth-bypass, smtp-vuln-cve2020-28017-through-28026-21nails.nse, firewall-bypass.nse


Örnek Script Kullanımları

Tüm varsayılan scriptleri çalıştırmak: nmap -sC <target>.
Belirli bir kategorideki scriptleri çalıştırmak: nmap --script discovery <target_ip>.
Birden fazla kategori veya wildcard ile çalıştırmak: nmap --script "default or safe" <target> veya nmap --script "http-*" <target>.
Belirli scriptleri hariç tutmak: nmap --script "not intrusive" <target>.
Script argümanları sağlamak: --script-args <n1>=<v1>.
Zafiyetleri CVSS puanına göre filtrelemek için vulners scripti: nmap --script=vulners --script-args mincvss=5.0 example.com.
Kendi scriptlerinizi çalıştırmak: nmap --script /your-scripts <target_ip>.

Zafiyet yönetiminde sürekli izleme ve risk odaklı önceliklendirme hayati önem taşır. Zafiyet tarama araçları, bilinen zafiyetleri tespit etmek için CVE veritabanlarını kullanır. Ancak, NVD'ye CVE'lerin yayınlanmasında gecikmeler olabilir ve CVSS puanları tek başına sömürü olasılığını veya iş etkisini yansıtmaz. Bu durum, zafiyet yönetiminin sadece tarama ve puanlamadan ibaret olmadığını, aynı zamanda sürekli izleme ve risk odaklı önceliklendirme gerektirdiğini gösterir. Bir zafiyetin CVSS puanı yüksek olsa bile, eğer aktif olarak sömürülmüyorsa veya kritik bir varlığı etkilemiyorsa, daha düşük puanlı ancak aktif olarak sömürülen bir zafiyetten daha az acil olabilir. Bu nedenle, "risk tabanlı önceliklendirme" (sömürü erişilebilirliği, varlık kritikliği, tehdit istihbaratı) hayati önem taşır. Sürekli tarama ve birden fazla CVE veritabanı entegrasyonu, bu dinamik tehdit ortamına ayak uydurmak için gereklidir. Kuruluşlar, sadece teknik şiddete değil, aynı zamanda zafiyetin sömürülebilirlik olasılığına, etkilenen varlığın iş kritiklik düzeyine ve mevcut tehdit istihbaratına dayalı olarak zafiyetleri önceliklendirmelidir. Bu yaklaşım, kaynakların en yüksek riskli alanlara odaklanmasını sağlar ve "uyarı yorgunluğunu" azaltır.
5. Güvenlik Taraması Sonuçlarının Görselleştirilmesi
Güvenlik taramalarından elde edilen büyük ve karmaşık veri setlerinin (açık portlar, servis sürümleri, CVE'ler, zafiyet puanları) anlaşılır, eyleme dönüştürülebilir içgörülere dönüştürülmesi için veri görselleştirme kritik öneme sahiptir. Görselleştirmeler, trendleri, anormallikleri ve riskleri hızlıca fark etmeyi sağlar.
Veri Görselleştirmenin Önemi ve En İyi Uygulamalar
Güvenlik taramaları sonucunda toplanan ham veriler, genellikle büyük hacimli ve karmaşıktır. Bu verilerin etkin bir şekilde analiz edilmesi ve karar verme süreçlerine entegre edilmesi için görselleştirme vazgeçilmezdir. Görselleştirmeler, güvenlik ekiplerinin ağın genel güvenlik duruşunu bir bakışta anlamasını, trendleri tespit etmesini ve en kritik zafiyetleri hızlıca belirlemesini sağlar.
En İyi Uygulamalar: Görselleştirmelerde mesajın net ve kolay anlaşılır olmasını sağlamak için etiket ekleme, renkleri ayarlama, verileri filtreleme, gruplama ve dönüştürme gibi teknikler kullanılmalıdır. Verilerin doğru bağlamda sunulması, yanlış yorumlamaların önüne geçer.
Popüler Görselleştirme Araçları

Grafana: Açık kaynaklı bir analiz ve izleme çözümüdür. Metrik verilerini görselleştirmek, filtrelemek ve dönüştürmek için esnek ve güçlü araçlar sunar. Güvenlik taraması sonuçları gibi çeşitli veri kaynaklarından gelen verileri görselleştirmek için kullanılabilir. Grafana, sunucu izleme, performans testi, OpenVPN bağlantı izleme, Docker izleme gibi birçok farklı amaç için panolar oluşturma yeteneğine sahiptir.
Diğer Popüler Araçlar: Tableau, PowerBI, QlikView, Looker, Plotly, D3.js, Google Charts, Highcharts, MATLAB, TIBCO Spotfire ve hatta Excel gibi araçlar da veri görselleştirme için yaygın olarak kullanılmaktadır. Her birinin kendine özgü güçlü yönleri ve kullanım alanları bulunur.

Nmap XML Çıktılarının Grafana ile Entegrasyonu
Nmap, tarama sonuçlarını XML formatında çıktı olarak verebilir. Bu XML çıktıları, Grafana gibi görselleştirme araçlarına aktarılarak zengin güvenlik panelleri oluşturulabilir.
Veri Akışı ve Kurulum Adımları:nmap-did-what projesi, bu entegrasyon için pratik bir çözüm sunar. Bu proje, Nmap XML çıktısını ayrıştırıp bir SQLite veritabanına depolayan bir Python betiği ve bu verileri görselleştirmek için önceden yapılandırılmış bir panoya sahip bir Grafana Docker kapsayıcısından oluşur.

nmap-did-what GitHub deposu klonlanır.
Nmap XML çıktısı, Python betiği (nmap-to-sqlite.py) ile SQLite veritabanına işlenir.
Docker Compose kullanılarak Grafana kapsayıcısı başlatılır.
Tarayıcıdan http://localhost:3000 adresinden Grafana paneline erişilir.
Varsayılan kimlik bilgileriyle (admin/admin) giriş yapılır. Nmap paneli, taranan varlıkların, uygulamaların, işletim sistemi ailelerinin, servislerin, açık portların ve tespit edilen CVE'lerin genel bir görünümünü sunarak tarama verilerini gösterecektir. Birden fazla tarama, zaman filtreleri kullanılarak incelenebilir.

Örnek Güvenlik Panelleri (Dashboard):Grafana'da Nmap verileriyle oluşturulan panolar, ağın genel güvenlik duruşunu görsel olarak temsil eder. Bu panolar, taranan varlıkların, uygulamaların, işletim sistemi ailelerinin, servislerin, açık portların ve tespit edilen CVE'lerin sayısını ve dağılımını göstererek ağa ve açık servislere genel bir bakış sağlar. Ayrıca sunucu izleme, performans testi, OpenVPN bağlantı izleme, Docker izleme gibi çeşitli güvenlik ve operasyonel metrikler için de özelleştirilebilir panolar oluşturulabilir.
Çıktı Formatları (JSON, CSV) ve Entegrasyon Kolaylığı
Güvenlik tarama araçları (Nmap, Masscan, FFUF gibi) genellikle JSON ve CSV gibi standart formatlarda çıktı sağlar. Bu formatlar, verilerin diğer güvenlik araçlarına (SIEM sistemleri, zafiyet yönetimi platformları) veya görselleştirme araçlarına kolayca entegre edilmesini sağlar. CSV dosyaları, sütun adları, benzersiz anahtar sütunları ve tıklanabilir arama sonucu URL'leri gibi yapısal bilgilerle zenginleştirilebilir.
Görselleştirme ile stratejik karar alma, ham tarama verilerinin değerini artırır. Ham tarama verileri (örneğin, binlerce açık port ve CVE listesi) tek başına bir anlam ifade etmez ve "uyarı yorgunluğuna" yol açabilir. Bu verilerin Grafana gibi araçlarla görselleştirilmesi, yöneticilerin ve güvenlik ekiplerinin ağın genel güvenlik duruşunu bir bakışta anlamasını, trendleri tespit etmesini ve en kritik zafiyetleri hızlıca belirlemesini sağlar. Görselleştirme, zafiyetlerin zaman içindeki değişimini, yeni ortaya çıkan tehditleri ve düzeltme çabalarının etkinliğini izlemek için bir köprü görevi görür. Örneğin, Nmap taramalarından elde edilen CVE verilerini Grafana'da bir zaman çizgisi üzerinde görselleştirmek, hangi dönemlerde daha fazla kritik zafiyetin ortaya çıktığını veya düzeltme hızının nasıl olduğunu gösterir. Bu, stratejik planlama ve kaynak tahsisi için temel oluşturur. Veri görselleştirme, teknik güvenlik bulgularını iş liderlerinin anlayabileceği risk ve performans metriklerine dönüştürerek, siber güvenliğin sadece teknik bir mesele olmadığını, aynı zamanda iş sürekliliği ve stratejik bir öncelik olduğunu vurgular.
6. MAC Adresi Tespiti
MAC (Media Access Control) adresi, bir ağdaki elektronik aygıtları benzersiz bir şekilde tanımlamak için kullanılan 12 alfasayısal karakterden (48 bit) oluşan fiziksel bir adrestir. Yönlendiriciler ve anahtarlar, ağa erişimi kontrol etmek için MAC adreslerini kullanır. Her ağ bağdaştırıcısının (NIC) benzersiz bir MAC adresi vardır.
MAC Adresi Bulma Yöntemleri
Farklı işletim sistemlerinde MAC adresini bulmak için çeşitli yöntemler bulunmaktadır:
Windows:

Komut İstemi (CMD) açılır (Başlat, Çalıştır, CMD yazılır, ardından CMD.exe'ye sağ tıklanır ve Yönetici Olarak Çalıştır seçilir).
getmac /v komutu ile "Fiziksel Adres" etiketi altında xx-xx-xx-xx-xx-xx biçiminde MAC adresi görüntülenir.
ipconfig /all komutu da MAC adresini ve diğer ağ bilgilerini döndürür.

Linux:

Terminalde ifconfig -a komutu kullanılır. "eth0" veya diğer arayüzlerin "HWaddr" alanı MAC adresini gösterir.
arp -a komutu da ağdaki cihazların MAC adreslerini gösterebilir.

macOS:

"Sistem Ayarları" > "Genel" > "Hakkında" veya "Paylaşma" bölümlerinde bilgisayar adı, yerel sunucu adı ve ağ adresi gibi tanımlayıcılar bulunabilir. Doğrudan MAC adresi için genellikle ağ arayüzü ayarlarına bakılır.

Mobil Cihazlar (iOS, Android):

Genellikle "Ayarlar" > "Genel" > "Hakkında" veya "Kablosuz Ağlar" > "Wi-Fi Ayarları" > "Gelişmiş" gibi menülerde "Wi-Fi Adresi" veya "MAC Adresi" olarak bulunur.

Diğer Yöntemler: DHCP Sunucusu günlükleri, ağ yapılandırma yönetim araçları, ağ izleme araçları (Wireshark, TCPDump), ağ envanter yönetim araçları veya ağ tarayıcıları (Nmap, Angry IP Scanner) da MAC adresi tespiti için kullanılabilir.
Aşağıdaki tablo, farklı işletim sistemlerinde MAC adresini tespit etmek için kullanılan pratik komutları ve adımları bir araya getirir. Bu, okuyucunun kendi ortamında hızlıca cihaz kimliği belirlemesi için bir referans noktası sağlar. MAC adresinin bir cihazın üreticisini (OUI aracılığıyla) belirlemede nasıl kullanılabileceği bilgisiyle birleştiğinde, bu keşif adımı ağ envanteri ve güvenlik denetimi için temel bir yetenek haline gelir.



İşletim Sistemi
Yöntem/Komut
Açıklama/Örnek Çıktı



Windows
getmac /v
"Fiziksel Adres" altında xx-xx-xx-xx-xx-xx formatında listeler.



ipconfig /all
"Fiziksel Adres" veya "HWaddr" alanında MAC adresini gösterir.


Linux
ifconfig -a
"eth0" veya diğer arayüzlerin "HWaddr" alanında MAC adresini gösterir.



arp -a
Ağdaki cihazların IP ve MAC adres eşleşmelerini gösterir.


macOS
Sistem Ayarları > Ağ > Gelişmiş > Donanım
Ağ bağdaştırıcısının MAC adresini gösterir.


iOS
Ayarlar > Genel > Hakkında > Wi-Fi Adresi
Wi-Fi adaptörünün MAC adresini gösterir.


Android
Ayarlar > Kablosuz & Ağlar > Wi-Fi Ayarları > Gelişmiş
Wi-Fi adaptörünün MAC adresini gösterir.


OUI (Organizationally Unique Identifier) Veritabanı Kullanımı

OUI Nedir ve MAC Adresi ile İlişkisi: OUI, IEEE (Institute of Electrical and Electronics Engineers) tarafından ağ arayüzleri üreticilerini (ağ kartları, Wi-Fi adaptörleri gibi) tanımlamak için atanan, küresel olarak benzersiz 24 bitlik bir tanımlayıcıdır. Bir MAC adresinin ilk üç baytı (ilk 6 onaltılık karakter) OUI'ye karşılık gelirken, kalan üç bayt üretici tarafından kendi cihazlarını benzersiz bir şekilde tanımlamak için kullanılır. Bu hiyerarşik yapı, ağ yöneticilerinin bir cihazın MAC adresine bakarak üreticisini kolayca tanımlamasını sağlar.
Üretici Bilgisi Tespiti: Bir cihazın MAC adresindeki OUI'ye bakarak üreticisini kolayca tanımlamak mümkündür. Örneğin, 00:0A:E4 ile başlayan bir MAC adresi Cisco Systems, Inc. tarafından üretilen bir cihaza aittir. Bu, ağ yöneticilerinin cihazların menşeini belirlemesine, ağ sorunlarını gidermesine, güvenlik politikalarını uygulamasına ve uyumluluğu sağlamasına yardımcı olur.
OUI Veritabanı Araçları: oui.is ve dnschecker.org/mac-lookup.php gibi çevrimiçi araçlar, bir MAC adresi veya OUI girerek üretici bilgisini hızlıca bulmayı sağlar. Bu araçlar, verilerini doğrudan IEEE kayıt otoritelerinden alır ve düzenli olarak güncellenir.

MAC adresleri, ağ güvenliği ve izleme için temel bir tanımlayıcı olsa da, tek başına yeterli bir güvenlik kontrolü değildir. MAC adresleri genellikle yerel ağda bir cihazı benzersiz şekilde tanımlamak için kullanılır ve OUI kısmı üreticiyi gösterir. Ancak, MAC adresleri kolayca taklit edilebilir (MAC spoofing), bu da güvenlik kontrollerinin sadece MAC adresine dayanmaması gerektiğini gösterir. Bir siber saldırıda, saldırganlar MAC adreslerini taklit ederek ağdaki izlerini gizlemeye veya belirli ağ filtrelerini atlatmaya çalışabilir. Bu durum, MAC adresi tespitinin sadece envanter için değil, aynı zamanda şüpheli aktiviteleri ve potansiyel spoofing girişimlerini belirlemek için de önemli olduğunu vurgular. OUI veritabanı, bilinmeyen bir MAC adresinin üreticisini hızlıca belirleyerek, cihazın yasal olup olmadığına dair ilk ipuçlarını verebilir. Bu nedenle, güvenlik politikaları, MAC adres filtrelemesinin yanı sıra daha gelişmiş kimlik doğrulama, ağ segmentasyonu ve davranışsal analiz gibi katmanlı yaklaşımları içermelidir.
7. Güvenlik Duvarı Atlatma Yöntemleri
Güvenlik duvarları (firewall), internet ile özel bir ağ arasında bir filtre görevi görerek gelen ve giden trafiği önceden belirlenmiş güvenlik kurallarına göre denetler ve düzenler. Ancak, saldırganlar bu savunma mekanizmalarını atlatmak için çeşitli yöntemler geliştirmişlerdir.
Güvenlik Duvarı Türleri ve Çalışma Prensipleri

Paket Filtreleme Güvenlik Duvarı (Packet Filtering Firewall): Ağ katmanında çalışır, bireysel veri paketlerini inceler ve kaynak/hedef IP, port numaraları gibi bilgilere göre filtreleme yapar. Durum bilgisi olan ve olmayan olarak ikiye ayrılır.
Durum Denetimi Güvenlik Duvarı (Stateful Inspection Firewall): Ağ bağlantılarının durumunu izler ve ağ iletişiminin bağlamını korur. Paket filtrelemeden daha gelişmiştir.
Uygulama Katmanı Güvenlik Duvarı (Application Layer Firewall / Proxy Tabanlı Güvenlik Duvarı): Uygulama protokolü düzeyinde trafiği analiz eder ve ağ kaynaklarını korumak amacıyla uygulama katmanındaki mesajları filtreler. Daha derinlemesine inceleme sağlar.
Yeni Nesil Güvenlik Duvarı (Next-Generation Firewall - NGFW): Antivirüs, kötü amaçlı yazılım tespiti, saldırı önleme (IPS) gibi özelliklere sahiptir ve internet trafiğini analiz ederek korur. Kural setlerine bağlı olarak sahtecilik, SQL enjeksiyonu gibi saldırılara karşı etkilidir.

Güvenlik Duvarı Tespit Teknikleri (Nmap ve Hping3 Kullanımı)
Saldırganlar, bir güvenlik duvarının varlığını ve kurallarını anlamak için çeşitli araçlar kullanır.
Nmap ile Firewall Tespiti

ACK Taraması (nmap -sA): Bu tarama, portun erişilebilir ancak durumunun tespit edilemediğini (Unfiltered) gösterir veya filtrelendiğini anlamak için kullanılır. Bir ACK paketine yanıt gelmemesi, güvenlik duvarının paketi filtrelediğini, RST yanıtı ise portun filtrelenmemiş ancak kapalı olduğunu gösterir.
firewall-bypass.nse scripti: Bu Nmap Scripting Engine (NSE) betiği, netfilter ve diğer güvenlik duvarlarındaki yardımcı programların (örneğin, FTP, SIP) dinamik olarak port açma zafiyetlerini tespit eder. Betik, hedef sunucudan gelen bir paketi taklit ederek güvenlik duvarının ilgili protokol yardımcı portu üzerinden bağlantı açmasını sağlar. Bu saldırının çalışması için saldırgan makinesinin güvenlik duvarıyla aynı ağ segmentinde olması gerekir.

Hping3 ile Firewall Testi
Hping3, TCP, UDP ve ICMP paketlerini özel parametrelerle oluşturarak güvenlik duvarı güvenliğini değerlendirmek için güçlü bir araçtır.

Temel Ping Taraması (hping3 -1): Çoğu güvenlik duvarı standart ICMP isteklerini engeller. Yanıt alınmaması, ICMP'nin engellendiğini gösterir.
TCP SYN Taraması (hping3 -S): SYN-ACK yanıtı portun açık olduğunu, RST-ACK kapalı olduğunu, yanıt olmaması paket filtrelemesini gösterebilir.
Gizli Tarama (FIN Scan - hping3 -F): FIN paketlerinin engellenip engellenmediğini kontrol eder.
ACK Taraması (hping3 -A): Güvenlik duvarı kural setlerini test eder. Yanıt yoksa filtreleme, RST ise portun filtrelenmemiş ama kapalı olduğu anlaşılır.
UDP Taraması (hping3 --udp): UDP trafiğinin engellenip engellenmediğini test eder. ICMP "port unreachable" mesajı portun kapalı olduğunu gösterir.
Durumlu (Stateful) vs. Durumsuz (Stateless) Güvenlik Duvarı Testi: Paketlerin sıralı gönderilmesiyle yanıtların farklılaşıp farklılaşmadığına bakılarak güvenlik duvarının durum bilgisi tutma yeteneği anlaşılır.
Parçalanmış Paket Saldırısı Simülasyonu (hping3 -f): Güvenlik duvarlarının parçalanmış paketleri doğru bir şekilde birleştirip birleştirmediğini kontrol eder. Yanlış yapılandırmalar atlatmaya izin verebilir.
Sahte Kaynak IP Testi (hping3 -a ): Güvenlik duvarının basit kaynak tabanlı filtrelemeye dayanıp dayanmadığını test eder.
IDS/IPS Davranışı Testi (hping3 --rand-source --flood): IDS/IPS sistemlerinin trafik modellerini analiz etme ve anormallikleri tespit etme etkinliğini değerlendirir.

Paket Manipülasyonu Stratejileri

Parçalama (Fragmentation): Paketleri daha küçük parçalara ayırarak güvenlik duvarlarının tamamını incelemesini veya doğru birleştirmesini zorlaştırır. Nmap'te -f veya --mtu parametreleri kullanılır. Bu, özellikle paket filtreleme güvenlik duvarlarını atlatmada etkili olabilir.
Decoy Tarama (Decoy Scanning): Birden fazla sahte kaynak IP adresi oluşturarak taramanın gerçek kaynağını gizler. Güvenlik duvarı günlüklerini karıştırarak izlemeyi zorlaştırır. Nmap'te -D RND:10 gibi komutlar kullanılır.
Kaynak Port Manipülasyonu: Kaynak port numaralarını değiştirerek port tabanlı kısıtlamaları atlatmayı amaçlar.
Yavaş Tarama (Slow Scanning): Tarama hızını düşürerek güvenlik sistemleri tarafından tespit edilmekten kaçınır. Bu teknik, özellikle imza tabanlı IDS/IPS sistemlerini atlatmak için kullanılır.

Tünelleme Yöntemleri
Ağ trafiğini başka bir protokol içine kapsülleyerek güvenlik duvarı kurallarını atlatma yöntemleridir.

SSH Tünelleme (ssh -D): Güvenli bir SSH bağlantısı üzerinden trafik tünellenir, bu da güvenlik duvarlarının içerideki trafiği incelemesini zorlaştırır. Bu yöntem, genellikle kısıtlı ağlarda dışarıya veya içerideki diğer sistemlere erişim sağlamak için kullanılır.
SSL/TLS Tünelleme: HTTPS gibi şifreli protokoller üzerinden trafiği tünelleyerek içeriğin incelenmesini engeller. Çoğu güvenlik duvarı şifreli trafiğin içeriğini inceleyemediği için bu yöntem etkili olabilir.

Proxy Zincirleme (Proxy Chaining)
Proxy zincirleme, internet trafiğini birden fazla proxy sunucusu üzerinden yönlendirerek çevrimiçi anonim kalmayı veya coğrafi kısıtlamaları aşmayı sağlar. Özellikle sızma testleri sırasında trafiğin kaynağını gizlemek ve farklı bir konumdan geliyormuş gibi göstermek için kullanılır.

Çalışma Prensibi: Veri paketleri, doğrudan hedefe gitmek yerine bir proxy sunucusuna gönderilir, bu sunucu paketi bir sonrakine iletir ve bu işlem zincirdeki tüm proxy'ler boyunca devam eder. Her adımda IP adresi değişir, bu da orijinal kimliği gizler. Bu çok katmanlı yapı, saldırganın izini sürmeyi son derece zorlaştırır.
Zincir Türleri:
Dinamik Zincir (Dynamic Chain): Proxy'leri listede belirtilen sırayla kullanmaya çalışır, başarısız olanları atlar. Güvenilirlik ve esneklik sunar.
Katı Zincir (Strict Chain): Her proxy listedeki sırayla kullanılır. Bir proxy başarısız olursa tüm bağlantı başarısız olur. Trafiğin her zaman aynı yolu izlemesini sağlar.
Dairesel Zincir (Round-Robin Chain): Zincirlenmiş proxy'ler, bağlantıyı sağlanan proxy'ler arasında dağıtmak için dairesel olarak kullanılır. Her yeni bağlantı isteği listedeki bir sonrakine gider ve sona ulaştığında baştan başlar. Yük dengeleme için idealdir.
Rastgele Zincir (Random Chain): Her bağlantı için proxy'leri rastgele bir sırayla seçer. Proxy'leri sırayla kullanmaz ve listelenen her proxy üzerinden benzersiz bir yol sağlar. Daha yüksek anonimlik sağlayabilir.


Kullanım ve Yapılandırma: Proxychains-ng aracı Kali Linux'ta önceden yüklü gelir. Yapılandırma dosyası (/etc/proxychains4.conf) düzenlenerek proxy sunucuları eklenebilir ve zincir türü seçilebilir. Herhangi bir uygulamayı veya aracı proxy'ler üzerinden yönlendirmek için komutun başına proxychains4 eklemek yeterlidir (örn. proxychains4 curl ipinfo.io).
Tor ile Entegrasyon: Proxychains, Tor ("The Onion Router") ile birlikte de kullanılabilir. Tor, trafiği dünya genelindeki gönüllü sunucular üzerinden yönlendirerek anonim iletişim sağlar.
Pivotlama ile Kullanım: Proxychains, Chisel, SSHuttle ve Metasploit gibi pivotlama araçlarıyla birlikte de kullanılabilir. Pivotlama, ele geçirilmiş bir ana bilgisayarı atlama noktası olarak kullanarak normalde saldırı makinesinden erişilemeyen dahili ağlardaki diğer ana bilgisayarlara erişmenizi sağlar.

Rate Limiting Bypass Yöntemleri
Rate limiting (oran sınırlama), bir kullanıcının, IP adresinin veya hesabın belirli bir süre içinde bir web hizmetine, API'ye veya web sitesine yapabileceği istek sayısını sınırlayan bir erişim kontrol mekanizmasıdır. Bu, sunucu aşırı yüklenmesini önlemeye ve Hizmet Reddi (DoS) saldırıları gibi kötü niyetli faaliyetlere karşı koruma sağlamaya yardımcı olur. Rate limit bypass, saldırganların bu istek kısıtlamalarını aşarak sistemin izin verdiğinden önemli ölçüde daha fazla istek göndermesine olanak tanıyan bir tekniktir.

Riskler: Rate limit bypass, sistem aşırı yüklenmesi, toplu veri kazıma, spam, kaba kuvvet saldırıları, DDoS saldırıları ve veri gizliliği ihlalleri gibi ciddi riskler taşır.
Bypass Yöntemleri:
IP Adreslerini Değiştirme: Saldırganlar genellikle VPN'ler, proxy sunucuları veya anonimleştiriciler kullanarak sürekli IP adreslerini değiştirir. Oran sınırlaması IP adresine göre uygulandığında, bu taktik kısıtlamaları aşmalarını sağlar.
Birden Fazla Hesap Kullanma: Oran sınırlamaları hesap başına ayarlanmışsa, saldırganlar çok sayıda hesap oluşturarak tek bir hesabın izin verdiğinden çok daha fazla istek gönderebilir.
İstekleri Geciktirme: Bazı bypass yöntemleri, oran sınırlamalarını hızlıca aşmaktan kaçınmak için istekleri aralıklı göndermeyi içerir. Birçok isteği aynı anda göndermek yerine, saldırganlar bypass'ı daha az fark edilebilir hale getirmek için duraklamalar ekler.
HTTP Başlıklarını Manipüle Etme: Bazı oran sınırlama sistemleri, istek kaynaklarını User-Agent veya Referer gibi HTTP başlıklarına göre tanımlar. Başlıkları değiştirmek veya taklit etmek, saldırganların tespit edilmekten ve engellenmekten kaçınmasına yardımcı olabilir. X-Forwarded-For gibi başlıklar kullanılarak IP kaynağı değiştirilebilir.
Dinamik Erişim Tokenları Kullanma: Erişim tokenlarına (OAuth gibi) dayanan sistemler, token başına erişimi sınırlayabilir. Saldırganlar, bu tür sınırlamaları aşmak için tokenları sık sık değiştirebilir veya yenileyebilir.
Özel Karakter Kullanımı: Bazı sistemler, %00 (null byte), %0d%0a (CRLF), %09 (yatay sekme) gibi özel karakterlerin isteklerde kullanılmasıyla oran sınırlamalarını atlatmaya izin verebilir.
Önbellek Tabanlı Mekanizmaları Sömürme: Zayıf önbellek tabanlı mekanizmalar, saldırganların oran sınırlamasını aşmasına ve kaba kuvvet korumalarını etkisiz hale getirmesine olanak tanır. Örneğin, bir önbelleğin kapasitesini aşan farklı kullanıcılar için oturum açma denemeleriyle önbelleği doldurmak, belirli bir hesabın (örn. yönetici hesabı) başarısız denemelerini önbellekten çıkararak oran sınırlamasını sıfırlayabilir.



Güvenlik duvarı atlatma yöntemlerinin sürekli gelişimi ve savunma stratejileri, siber güvenlikte sürekli bir mücadeleyi temsil eder. Saldırganlar, güvenlik duvarlarını ve IDS/IPS sistemlerini atlatmak için sürekli olarak yeni ve sofistike teknikler (paket parçalama, decoy tarama, tünelleme, proxy zincirleme, oran sınırlama bypass) geliştirirken, savunmacılar da bu tehditlere karşı koymak için çok katmanlı ve adaptif savunma stratejileri uygulamak zorundadır. Bu dinamik ortam, güvenlik profesyonellerinin sadece mevcut savunma mekanizmalarını değil, aynı zamanda saldırı tekniklerinin altında yatan prensipleri de derinlemesine anlamalarını gerektirir. Örneğin, paket parçalamanın neden etkili olduğunu anlamak, güvenlik duvarının paketleri nasıl incelediğine dair bir bilgiye dayanır. Bu sürekli adaptasyon, kuruluşların siber güvenlik duruşlarını güçlendirmeleri ve hızla değişen tehdit ortamında dirençli kalmaları için kritik öneme sahiptir.
8. Sonuç ve Öneriler
Bu rapor, siber güvenlikte açık portların taranması, sistem ve sürüm bilgilerinin elde edilmesi, güvenlik açığı analizi, sonuçların görselleştirilmesi, MAC adresi tespiti ve güvenlik duvarı atlatma yöntemleri gibi kritik alanları detaylı bir şekilde incelemiştir. Elde edilen bilgiler, modern siber güvenlik tehdit ortamında proaktif savunma ve etkili risk yönetimi için temel bir anlayış sağlamaktadır.
Temel Çıkarımlar

Dinamik Keşif ve Savunma: Ağ keşif teknikleri (Nmap, Masscan) ve güvenlik duvarı/IDS/IPS sistemleri sürekli olarak evrimleşmektedir. Bu durum, siber güvenlikte sürekli bir adaptasyon ve öğrenme döngüsünü zorunlu kılmaktadır. Hız ve gizlilik arasındaki denge, her operasyonun doğasına göre dikkatle seçilmesi gereken kritik bir faktördür.
Bilgi Toplamanın Kritikliği: Banner grabbing ve sürüm tespiti gibi bilgi toplama teknikleri, potansiyel zafiyetleri (CVE'ler) belirlemede hayati rol oynamaktadır. Basit bir sürüm bilgisi, ciddi bir güvenlik açığına işaret edebilir, bu da savunmacıların gereksiz bilgi ifşasını önlemesini gerektirir.
Kapsamlı Zafiyet Yönetimi: Güvenlik açığı tarama araçları (Nessus, OpenVAS, Qualys vb.) ve CVE/CVSS veritabanları, bilinen zafiyetleri tespit etme ve derecelendirmede temel taşlardır. Ancak, CVSS puanlamasının sınırlılıkları göz önüne alındığında, risk odaklı önceliklendirme ve birden fazla CVE kaynağının entegrasyonu, zafiyet yönetiminin etkinliğini artırmaktadır.
Veri Görselleştirmenin Gücü: Ham güvenlik taraması verileri, Grafana gibi araçlarla görselleştirildiğinde, yöneticilerin ve güvenlik ekiplerinin ağın genel güvenlik duruşunu hızlıca anlamasını, trendleri tespit etmesini ve stratejik kararlar almasını sağlar. Bu, "uyarı yorgunluğunu" azaltır ve kaynakların daha verimli kullanılmasına olanak tanır.
MAC Adresinin Rolü: MAC adresleri ve OUI veritabanları, ağdaki cihazları tanımlama ve envanter oluşturma için önemlidir. Ancak, MAC adreslerinin taklit edilebilir olması, güvenlik kontrollerinin yalnızca bu adrese dayanmaması gerektiğini, daha katmanlı kimlik doğrulama ve ağ segmentasyonu yaklaşımlarının benimsenmesi gerektiğini göstermektedir.
Sürekli Atlatma ve Savunma Mücadelesi: Güvenlik duvarı atlatma teknikleri (paket manipülasyonu, tünelleme, proxy zincirleme, oran sınırlama bypass) sürekli olarak gelişmekte olup, savunmacıların çok katmanlı, adaptif ve davranışsal analize dayalı güvenlik çözümleri uygulamalarını zorunlu kılmaktadır.

Öneriler

Sürekli Eğitim ve Gelişim: Siber güvenlik profesyonelleri, hem saldırı hem de savunma tekniklerindeki en son gelişmeleri takip etmek için sürekli eğitim almalı ve pratik becerilerini geliştirmelidir. Bu, dinamik tehdit ortamına uyum sağlamak için hayati öneme sahiptir.
Katmanlı Güvenlik Yaklaşımı: Kuruluşlar, tek bir güvenlik mekanizmasına (örn. sadece güvenlik duvarı) güvenmek yerine, derinlemesine savunma (defense-in-depth) stratejisini benimsemelidir. Bu, ağ segmentasyonu, güçlü kimlik doğrulama, IDS/IPS, uç nokta koruması ve güvenlik duvarlarının entegre bir şekilde kullanılmasını içerir.
Risk Odaklı Zafiyet Yönetimi: Zafiyetler, sadece teknik şiddetlerine (CVSS puanı) göre değil, aynı zamanda sömürülebilirlik olasılığına, etkilenen varlığın iş kritiklik düzeyine ve mevcut tehdit istihbaratına dayalı olarak önceliklendirilmelidir. Bu, sınırlı kaynakların en yüksek riskli alanlara odaklanmasını sağlar.
Otomatik Tarama ve Görselleştirme: Güvenlik açığı taramaları düzenli olarak otomatikleştirilmeli ve elde edilen veriler Grafana gibi araçlarla görselleştirilerek eyleme dönüştürülebilir panolar oluşturulmalıdır. Bu, güvenlik duruşunun gerçek zamanlı olarak izlenmesini ve hızlı karar alınmasını kolaylaştırır.
Güvenlik Duvarı Yapılandırmalarının Periyodik Denetimi: Güvenlik duvarı kuralları, hping3 gibi araçlarla düzenli olarak test edilmeli ve zafiyetlere karşı (örn. firewall-bypass.nse scripti ile) denetlenmelidir. Gereksiz açık portlar kapatılmalı ve kural setleri "en az ayrıcalık" prensibine göre sıkılaştırılmalıdır.
Tehdit İstihbaratının Entegrasyonu: CVE veritabanları gibi tehdit istihbaratı kaynakları, zafiyet tarama süreçlerine entegre edilmeli ve birden fazla kaynaktan gelen veriler çapraz doğrulanarak daha kapsamlı ve güncel bir tehdit görünümü elde edilmelidir.
Sorumlu Kullanım: Sızma testi ve keşif araçları (Nmap, Masscan, Proxychains, Hping3) güçlü yeteneklere sahiptir. Bu araçlar, yalnızca yasal ve etik sınırlar içinde, yetkilendirilmiş ortamlarda ve sorumlu bir şekilde kullanılmalıdır. Yanlış kullanım, yasal sonuçlara ve sistem hasarına yol açabilir.

Siber güvenlik, sürekli değişen bir manzara olduğundan, kuruluşların ve bireylerin bu alandaki bilgi ve becerilerini sürekli güncellemeleri, proaktif bir yaklaşımla tehditlere karşı dirençli kalmaları için elzemdir.
