# ScanMatrix

## Proje Adı
ScanMatrix

## Takım Üyeleri
- Samethan Kül
- Eren Ergün
- İbrahim Yiğit Çetin

## Açıklama
ScanMatrix, Network Security alanında geliştirilmiş bir Python aracıdır. Bu araç, bir host üzerinde kapsamlı analizler gerçekleştirerek ağ güvenliği değerlendirmesi yapmayı amaçlar.

## Hedefler
ScanMatrix, aşağıdaki işlemleri gerçekleştirmek üzere tasarlanmıştır:
- **Port Tarama**: Hedef host üzerindeki açık portların tespiti.
- **Servis ve Versiyon Tespiti**: Açık portlarda çalışan servislerin ve versiyonlarının belirlenmesi.
- **MAC Adresi ve Üretici Tespiti**: Hedef cihazın MAC adresinin ve üreticisinin tanımlanması.
- **Firewall Tespiti**: Hedef sistemde firewall varlığının kontrolü.
- **CVE Sorgulama**: Sistemde bulunan açıkların CVE (Common Vulnerabilities and Exposures) veritabanında sorgulanması.
- **Görselleştirme**: Elde edilen verilerin analizini kolaylaştırmak için grafik oluşturma.

## Bağlantılar
- [Proje Repository'si](#) *(Lütfen repository bağlantısını ekleyin)*
- [Dokümantasyon](#) *(Lütfen varsa dokümantasyon bağlantısını ekleyin)*
- [İletişim](#) *(Lütfen varsa iletişim bilgilerini ekleyin)*

## Kurulum
1. Depoyu klonlayın:
   ```bash
   git clone [repository-link]
   ```
2. Gerekli bağımlılıkları yükleyin:
   ```bash
   pip install -r requirements.txt
   ```
3. Aracı çalıştırın:
   ```bash
   python scanmatrix.py
   ```

## Kullanım
```bash
python scanmatrix.py --host [HEDEF_IP] --ports [PORT_ARALIĞI] --options [SECENEKLER]
```
- **--host**: Taranacak hedef IP adresi.
- **--ports**: Taranacak port aralığı (ör. 1-65535).
- **--options**: Ek seçenekler (ör. --cve, --visualize).

## Katkıda Bulunma
1. Bu projeye katkıda bulunmak için lütfen bir fork oluşturun.
2. Yeni bir özellik dalı oluşturun (`git checkout -b feature/yeni-ozellik`).
3. Değişikliklerinizi yapın ve commit edin (`git commit -m 'Yeni özellik eklendi'`).
4. Dalınızı ana depoya push edin (`git push origin feature/yeni-ozellik`).
5. Bir Pull Request oluşturun.

## Lisans
Bu proje [MIT Lisansı](LICENSE) altında lisanslanmıştır.
