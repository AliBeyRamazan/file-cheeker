# file-cheeker

`file-cheeker`, Linux uzerinde dosya ve binary on analizi yapmak icin hazirlanmis Go tabanli bir CLI aracidir.

ELF dosyalari icin daha detayli bilgi verir; PE, PDF, ZIP ve script dosyalarini da temel seviyede tanir. Hash, entropi, string, imza ve risk puani cikarir.

## Linux kurulumu

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

En kisa kullanim:

```bash
fc ./dosya
```

Tam analiz:

```bash
fc ./dosya -a
```

Stringleri goster:

```bash
fc ./dosya -s
```

PE import fonksiyonlarini goster:

```bash
fc ./sample.exe -i
```

Alternatif komut bicimi:

```bash
fc scan ./sample.elf -a
```

## Secenekler

- `-a`, `--all`: tam analiz yapar, stringleri ve importlari da gosterir.
- `-s`, `--strings`: cikarilan stringleri gosterir.
- `-i`, `--imports`: PE import fonksiyonlarini gosterir.
- `-h`, `--help`: yardim ekranini gosterir.

## Gelistirme modunda calistirma

```bash
go run . ./dosya -a
```

## Gereksinimler

- Go 1.22.2 veya daha yeni
