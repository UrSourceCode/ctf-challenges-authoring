# shuff dot apeka - Proof of Concept

> JCC 2026 - Reverse Engineering - Baby - UrSourceCode

## Catatan Author

### Ide

`shuff dot apeka` dibuat sebagai challenge Reverse Engineering kategori Baby untuk peserta yang mungkin masih baru dengan APK reversing. Tujuannya adalah menjaga mekanismenya tetap sederhana: decompile aplikasinya, ikuti alur checker, lalu susun kembali data flag yang sudah diacak.

### Pembuatan Challenge

Bagian isi flag dipecah menjadi karakter-karakter lalu disimpan di `SecretData.ASCII` dalam urutan yang sudah diacak. Urutan rekonstruksi yang benar disimpan terpisah di `IndexMap.ORDER`, sedangkan `SecretData.recover()` mengikuti index map tersebut untuk menyusun kembali flag.

```text
flag
 ↓
pecah menjadi karakter
 ↓
acak ke SecretData.ASCII
 ↓
simpan urutan rekonstruksi di IndexMap.ORDER
 ↓
build APK
```

### Alur Penyelesaian

```text
APK
 ↓
decompile dengan JADX / APK decompiler lain
 ↓
ikuti input checker
 ↓
SecretData
 ↓
IndexMap.ORDER
 ↓
susun ulang karakter
 ↓
recover flag
```

Lesson yang ingin diberikan cukup sederhana: APK bisa didecompile, ditelusuri, dan dipahami tanpa harus langsung masuk ke native-code analysis.

Kita diberikan sebuah file APK. Saat dibuka, tampilannya seperti ini:

![android_view](assets/and_view.png)

Aplikasinya terlihat seperti sebuah flag checker.

## Decompile

Kita bisa melakukan decompile APK menggunakan [online decompiler](https://www.decompiler.com/jar/291e2672ccea3518ada734f6cf831d40/shuff.apk) atau JADX. Berikut hasilnya:

![main class](assets/mainclass.png)

Main class menunjukkan bahwa input checker memanggil class `SecretData`. Jika kita membuka class `SecretData`, kita mendapatkan:

```java
package com.apeka.hexshuffle;

/* JADX INFO: loaded from: classes2.dex */
public final class SecretData {
    static final String[] ASCII = {"r", "4", "t", "n", "_", "s", "a", "_", "4", "1", "0", "1", "d", "n", "0", "r", "t", "c", "_", "k", "t", "p", "_", "n", "3", "3", "u", "0", "v"};

    private SecretData() {
    }

    public static String recover() {
        StringBuilder sb = new StringBuilder();
        for (int i : IndexMap.ORDER) {
            sb.append(ASCII[i]);
        }
        return "JCC{" + ((Object) sb) + "}";
    }
}
```

Flag diacak menggunakan class `IndexMap`. Berikut class `IndexMap`:

```java
package com.apeka.hexshuffle;

/* JADX INFO: loaded from: classes2.dex */
public final class IndexMap {
    static final int[] ORDER = {1, 13, 7, 11, 23, 20, 15, 14, 12, 26, 17, 2, 9, 27, 3, 4, 16, 10, 22, 8, 21, 24, 19, 6, 18, 0, 25, 28, 5};

    private IndexMap() {
    }
}
```

## Solving

Seperti yang terlihat pada class `SecretData`, flag direkonstruksi dan dibungkus dengan `JCC{<flag>}` mengikuti urutan pada class `IndexMap`. Jadi, kita bisa membuat solver berikut:

```py
ASCII = [
    "r", "4", "t", "n", "_", "s", "a", "_", "4", "1", "0", "1", "d", "n", "0", "r", "t", "c", "_", "k", "t", "p", "_", "n", "3", "3", "u", "0", "v"
]

ORDER = [
    1, 13, 7, 11, 23, 20, 15, 14, 12, 26, 17, 2, 9, 27, 3, 4, 16, 10, 22, 8, 21, 24, 19, 6, 18, 0, 25, 28, 5
]

flag = 'JCC{' + ''.join(ASCII[i] for i in ORDER) + '}'
print(flag)
```

Flagnya adalah: `JCC{4n_1ntr0duct10n_t0_4p3ka_r3vs}`

Masukkan flag tersebut ke APK (kalau mau), dan hasilnya akan seperti ini:

![correct](assets/coorect.png)
