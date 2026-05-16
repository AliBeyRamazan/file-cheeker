# file-cheeker

`file-cheeker`, Linux uzerinde dosya ve binary on analizi yapmak icin hazirlanmis Go tabanli bir CLI aracidir.

ELF dosyalari icin daha detayli bilgi verir; PE, PDF, ZIP ve script dosyalarini da temel seviyede tanir. Hash, entropi, string, imza ve risk puani cikarir.

## Linux kurulumu

Once Go kurulu mu kontrol et:

```bash
go version
```

Eger `go: command not found` veya `go: komut bulunamadi` hatasi alirsan Go kur:

```bash
sudo apt update
sudo apt install golang-go -y
```

Sonra projeyi indirip derle:

```bash
git clone https://github.com/AliBeyRamazan/file-cheeker.git
cd file-cheeker
go build -o fc .
```

Istersen binary dosyasini PATH icine koy:

```bash
sudo install -m 755 fc /usr/local/bin/fc
```

## Kullanim

Eger `fc` dosyasini sadece proje klasorunde derlediysen komutu `./fc` seklinde calistir:

```bash
./fc ./dosya
```

Tam analiz:

```bash
./fc ./dosya -a
```

Stringleri goster:

```bash
./fc ./dosya -s
```

PE import fonksiyonlarini goster:

```bash
./fc ./sample.exe -i
```

Alternatif komut bicimi:

```bash
./fc scan ./sample.elf -a
```

Klasor icindeki dosyalari taramak icin klasor yolunu ver:

```bash
./fc ~/Downloads -a
```

USB disk taramak icin USB'nin Linux'taki mount yolunu ver. Cogu sistemde USB diskler `/media/$USER/USB_ADI` altinda gorunur:

```bash
ls /media/$USER
./fc /media/$USER/USB_ADI -a
```

Viruslu bulunan dosyalari karantinaya almak icin `-q` kullan:

```bash
./fc /media/$USER/USB_ADI -a -q
```

Karantina dosyalari varsayilan olarak `.fc-quarantine` klasorune tasinir. Farkli bir klasor kullanmak icin:

```bash
./fc /media/$USER/USB_ADI -a -q --quarantine-dir ~/fc-quarantine
```

Sadece verdigin klasorun icini tara, alt klasorlere girme:

```bash
./fc ~/Downloads --no-recursive
```

Eger `sudo install -m 755 fc /usr/local/bin/fc` komutunu calistirdiysan her yerden `fc` olarak kullanabilirsin:

```bash
fc ./dosya -a
```

`./dosya` yerine taramak istedigin gercek dosyanin yolunu yazmalisin. Ornek:

```bash
./fc /bin/ls -a
./fc ~/Downloads/sample.elf -a
./fc ~/Downloads/sample.exe -a
```

Bulundugun klasordeki dosyalari gormek icin:

```bash
ls
```

Sonra listede gordugun dosyayi tara:

```bash
./fc ./dosya_adi -a
```

## Sik karsilasilan hatalar

`go: command not found`

Go kurulu degildir. Kur:

```bash
sudo apt update
sudo apt install golang-go -y
```

`fc: command not found`

`fc` sistem PATH icinde degildir. Proje klasorundeysen basina `./` koy:

```bash
./fc ./dosya -a
```

Her yerden `fc` komutu calissin istiyorsan:

```bash
sudo install -m 755 fc /usr/local/bin/fc
```

`Dosya bulunamadi`

Yanlis dosya yolu yazilmis olabilir. Dosyayi listele ve tam yolunu kullan:

```bash
ls
./fc /tam/dosya/yolu -a
```

`Hash hesaplanamadi`, `Entropi hesaplanamadi` veya `okuma izni yok`

USB icindeki bazi dosyalar okunamiyor olabilir. Bu genelde izin, mount ayari veya bozuk/ozel sistem dosyalarindan kaynaklanir. Once USB yolunu kontrol et:

```bash
lsblk
ls -la /media/$USER
ls -la /media/$USER/USB_ADI
```

Dosyalar okunabiliyor mu kontrol et:

```bash
cat /media/$USER/USB_ADI/dosya_adi >/dev/null
```

Izin hatasi aliyorsan araci sudo ile deneyebilirsin:

```bash
sudo ./fc /media/$USER/USB_ADI -a
```

USB farkli bir yerde mount edildiyse dogru mount yolunu kullan:

```bash
./fc /run/media/$USER/USB_ADI -a
./fc /mnt/usb -a
```

Klasor taramasinda okunamayan dosyalar otomatik olarak `ATLANDI` diye gosterilir; tarama diger dosyalarla devam eder.

## Secenekler

- `-a`, `--all`: tam analiz yapar, stringleri ve importlari da gosterir.
- `-s`, `--strings`: cikarilan stringleri gosterir.
- `-i`, `--imports`: PE import fonksiyonlarini gosterir.
- `-q`, `--quarantine`: viruslu/cok riskli bulunan dosyalari karantinaya tasir.
- `--quarantine-dir <klasor>`: karantina klasorunu belirler. Varsayilan: `.fc-quarantine`.
- `--no-recursive`: klasor taramasinda alt klasorlere girmez.
- `-h`, `--help`: yardim ekranini gosterir.

## Virus analizi ve karantina

Araç statik analiz yapar; antivirus motoru degildir. Dosya su durumlardan birindeyse viruslu/cok riskli kabul edilir:

- Risk puani `60/100` veya daha yuksekse.
- Kritik seviyede imza eslesmesi varsa.

Karantina aktif degilse arac sadece rapor verir:

```bash
./fc ~/Downloads -a
```

Karantina aktifse viruslu/cok riskli dosyalar `.fc-quarantine` klasorune tasinir:

```bash
./fc ~/Downloads -a -q
```

Her karantina dosyasinin yanina `.meta.txt` dosyasi yazilir. Bu dosyada orijinal yol, SHA256, risk puani, entropi ve eslesen kurallar bulunur.

## Gelistirme modunda calistirma

```bash
go run . ./dosya -a
```

## Gereksinimler

- Go 1.22.2 veya daha yeni
