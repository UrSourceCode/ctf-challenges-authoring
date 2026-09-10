# Sudoku - Proof of Concept

> JCC 2026 - Reverse Engineering - Easy - UrSourceCode

Write-up ini hanya menggunakan IDA Free dan file yang diberikan ke peserta, yaitu
`release/Sudoku.exe`. Source code maupun debugger tidak diperlukan.

## Cari string yang menarik

Setelah menyelesaikan puzzle, game akan menampilkan:

```text
Secret reward unavailable.
```

![Game completed](assets/sec.png)

Buka `release/Sudoku.exe` di IDA Free, tunggu proses auto-analysis selesai, lalu
cari string tersebut melalui Strings window.

![IDA string search result](assets/secret_reward_unavailable.png)

Ikuti DATA XREF dari string tersebut. Referensinya akan mengarah ke normal-win branch
pada fungsi completion check.

![Completion check function](assets/open_string_in_ida_view.png)

## Cari hidden condition

Kalau kita melihat control-flow graph di sekitar bagian tersebut, instruksi pentingnya adalah:

```asm
mov     eax, cs:dword_1400092E8
cmp     eax, 539h
jnz     short normal_win
call    sub_140001E71
```

`539h` dalam heksadesimal adalah `1337` dalam desimal. Jadi, logikanya kurang lebih sama seperti:

```c
if (secret_score == 1337)
    reveal_flag();
else
    show_normal_win();
```

Ini menjelaskan kenapa saat game diselesaikan secara normal, program hanya menampilkan
`Secret reward unavailable.`: gameplay normal tidak pernah membuat hidden score menjadi `1337`.

## Decode flag

Ikuti fungsi `sub_140001E71`:

![reveal_flag diagram](assets/following_xref.png)

Raw decompilation dari IDA:

```c
__int64 sub_140001E71()
{
    _BYTE v1[268];
    int i;

    for (i = 0; i <= 41; ++i)
        v1[i] = byte_140006000[i];
    v1[42] = 0;
    sub_140001D1A(a1: (__int64)v1, a2: 42);
    sub_140001D98(a1: v1, a2: 42);
    sub_140001E0A(a1: v1, a2: 42);
    return sub_140001975(a1: v1);
}
```

Kalau ditulis ulang dengan nama fungsi yang lebih jelas, logikanya menjadi:

```c
void reveal_flag(void)
{
    unsigned char decoded[43];

    for (int i = 0; i < 42; i++)
        decoded[i] = encrypted_flag[i];
    decoded[42] = '\0';

    byte_reverse(decoded, 42);
    xor_with_secret_score(decoded, 42);
    nibble_swap(decoded, 42);

    show_flag(decoded);
}
```

Fungsi tersebut memanggil tiga sub-function secara berurutan.

### Stage 1 — `sub_140001D1A` (byte reverse)

Raw decompilation dari IDA:

```c
__int64 __fastcall sub_140001D1A(__int64 a1, int a2)
{
    char v3;
    int i;
    unsigned int v5;

    v5 = 0;
    for (i = a2 - 1; ; --i)
    {
        if ((int)v5 >= i)
            break;
        v3 = *(_BYTE *)((int)v5 + a1);
        *(_BYTE *)((int)v5 + a1) = *(_BYTE *)(i + a1);
        *(_BYTE *)(a1 + i) = v3;
        ++v5;
    }
    return result;
}
```

Kalau ditulis ulang dengan nama yang lebih deskriptif:

```c
void byte_reverse(unsigned char *buf, int len)
{
    int i = 0, j = len - 1;
    while (i < j) {
        unsigned char tmp = buf[i];
        buf[i] = buf[j];
        buf[j] = tmp;
        i++;
        j--;
    }
}
```

Fungsi ini membalik urutan byte di dalam buffer.

### Stage 2 — `sub_140001D98` (XOR dengan runtime-derived key)

Raw decompilation dari IDA:

```c
__int64 __fastcall sub_140001D98(__int64 a1, int a2)
{
    char v3;
    unsigned int i;

    v3 = (7 * dword_1400092E8 + 13) % 256;
    for (i = 0; ; ++i)
    {
        if ((int)i >= a2)
            break;
        *(_BYTE *)((int)i + a1) ^= v3;
    }
    return result;
}
```

Kalau ditulis ulang dengan nama yang lebih deskriptif:

```c
void xor_with_secret_score(unsigned char *buf, int len)
{
    unsigned char key = (secret_score * 7 + 13) % 256;
    for (int i = 0; i < len; i++)
        buf[i] ^= key;
}
```

`secret_score` adalah hidden variable `dword_1400092E8`. Saat `secret_score == 1337`,
XOR key yang digunakan adalah:

```text
(7 * 1337 + 13) % 256 = 0x9C
```

### Stage 3 — `sub_140001E0A` (nibble swap)

Raw decompilation dari IDA:

```c
__int64 __fastcall sub_140001E0A(__int64 a1, int a2)
{
    unsigned int i;

    for (i = 0; ; ++i)
    {
        if ((int)i >= a2)
            break;
        *(_BYTE *)((int)i + a1) = (16 * *(_BYTE *)((int)i + a1))
                                 | (*(_BYTE *)((int)i + a1) >> 4);
    }
    return result;
}
```

Kalau ditulis ulang dengan nama yang lebih deskriptif:

```c
void nibble_swap(unsigned char *buf, int len)
{
    for (int i = 0; i < len; i++)
        buf[i] = (buf[i] << 4) | (buf[i] >> 4);
}
```

Operasi ini menukar high nibble dan low nibble dari setiap byte. Operasinya juga
self-inverse, jadi kalau dilakukan dua kali hasilnya akan kembali ke byte awal.

### Solving

Encrypted flag bytes yang tersimpan pada `byte_140006000` adalah:

```text
4B CA BB 9F AA AB 69 DB AF BF AA CA AB 69 AF 1A
DB 69 CA 4A 69 AF FB 8F EA 69 BB AF FB AF 7A 69
CB 2A 9F DA CB AB 2B A8 A8 38
```

Karena `stage2_xor` bergantung pada kondisi `secret_score == 1337`, kita sudah tahu bahwa
XOR key yang digunakan adalah `0x9C`.

Ketiga stage tersebut bisa dibalik secara statis:

```python
encrypted = bytes.fromhex(
    "4B CA BB 9F AA AB 69 DB AF BF AA CA AB 69 AF 1A "
    "DB 69 CA 4A 69 AF FB 8F EA 69 BB AF FB AF 7A 69 "
    "CB 2A 9F DA CB AB 2B A8 A8 38"
)

reversed_bytes = bytes(reversed(encrypted))
key = (1337 * 7 + 13) % 256
xored = bytes(b ^ key for b in reversed_bytes)
flag = bytes(((b >> 4) | ((b & 0x0F) << 4)) & 0xFF for b in xored)

print(flag.decode("ascii"))
```

Output:

```text
JCC{sud0ku_n3v3r_g1v3_me_th3_sec23t_sc0re}
```

Jadi flag bisa direcover langsung dari executable menggunakan static analysis, tanpa perlu
menjalankan debugger.
