# Tiny Trace - Proof of Concept

> JCC 2026 - Reverse Engineering - Hard - UrSourceCode

Kita diberikan sebuah binary Windows x64 PE bernama `tinytrace.exe`. Setelah dibuka di IDA Free, ada beberapa hal yang langsung menarik:

- binary ini menggunakan console subsystem, statically linked CRT, dan tidak memakai packer
- import-nya banyak berkaitan dengan process dan pipe, seperti `CreatePipe`, `CreateProcessA`, `ReadFile`, `WriteFile`, `SetHandleInformation`, dan `GetModuleFileNameA`
- entry function mengecek `argv` untuk argument `--worker`, jadi executable yang sama ternyata bisa berjalan dalam dua mode

Kalau kita lihat main function di `sub_1400013B0`, alurnya seperti ini:

```c
for ( i = 1; i < argc; i++ )
    if ( !strcmp(argv[i], "--worker") )
        return sub_140001480(argc, argv);   // worker process
return sub_140001080();                     // parent process
```

Jadi ada dua kemungkinan:

1. kalau `--worker` tidak ada, program masuk ke `sub_140001080` sebagai parent process
2. kalau `--worker` ditemukan, program masuk ke `sub_140001480` sebagai worker process

Parent process sendiri tidak berisi validation logic yang penting. Logic utama justru ada di worker process.

### Worker Process

Masuk ke `sub_140001480`, kita mendapatkan:

```c
__int64 __fastcall sub_140001480(int a1, __int64 a2)
{
  // a1 = argc, a2 = argv (typed as __int64, so a2+16 / a2+24 = argv[2] / argv[3])
  if ( a1 >= 4 )
  {
    v3 = (void *)sub_140008920(*(_QWORD *)(a2 + 16), 0, 0);   // argv[2] -> pipe handle
    v4 = (void *)sub_140008920(*(_QWORD *)(a2 + 24), 0, 0);   // argv[3] -> pipe handle
    v5 = 0;
    memset(v15, 0, sizeof(v15));                              // input buffer, 32 bytes
    do
    {
      NumberOfBytesRead = 0;
      if ( !ReadFile(v3, (char *)v15 + v5, 33 - v5, &NumberOfBytesRead, nullptr) )
        break;
      if ( NumberOfBytesRead == 0 )
        break;
      v5 += NumberOfBytesRead;
    }
    while ( v5 < 0x21 );

    if ( v5 > 1 )
    {
      v6 = *((_BYTE *)v15 + v5 - 1);
      if ( v6 == 10 || v6 == 13 )                             // strip ONE newline
        --v5;
    }

    if ( v5 == 32 )                                           // length gate
    {
      v13[0] = -1694934140;   // 0x9AF95B84
      v13[1] = -1679077175;   // 0x9BEB50C9
      v13[2] = 1447133548;    // 0x5641816C
      v13[3] = 1155090915;    // 0x44D949E3
      v13[4] = -47635199;     // 0xFD292501
      v13[5] = 1106827868;    // 0x41F8DA5C
      v13[6] = -991992481;    // 0xC4DF655F
      v13[7] = -1115445458;   // 0xBD83A72E   <- the 32-byte KEY
      for ( i = 0; i < 32; i++ )                              // decode expected
        v14[i] = byte_140019380[i]                            // ENCODED_EXPECTED
               ^ *((_BYTE *)v13 + (i + 5) % 32)               // ^ KEY rotated by 5
               ^ 0xC3;                                        // ^ constant
      v7 = 0;
      while ( byte_140019360[(unsigned __int8)byte_140019340[v7]]      // ADD[PERM[i]]
            + (*((_BYTE *)v15 + (unsigned __int8)byte_140019340[v7])   // ^ input[PERM[i]]
             ^ *((_BYTE *)v13 + (unsigned __int8)byte_140019340[v7]))  // ^ KEY[PERM[i]]
            == v14[(unsigned __int8)byte_140019340[v7]] )              // == EXP[PERM[i]]
      {
        if ( ++v7 >= 32 )
        {
          v8 = 1;                                             // all 32 passed
          goto LABEL_17;
        }
      }
      v8 = 0;                                                 // first mismatch
LABEL_17:
      WriteFile(v4, &v8, 1u, &NumberOfBytesWritten, nullptr); // 1-byte verdict
      CloseHandle(v3);
      CloseHandle(v4);
    }
    else
    {
      WriteFile(v4, "\x00", 1u, ...);                         // wrong length -> instant reject
    }
  }
  return 0;
}
```

Kalau dibaca pelan-pelan, fungsi ini melakukan beberapa hal:

1. parent memasukkan dua pipe handle ke command line dalam bentuk angka desimal: `--worker <in> <out>`
2. `sub_140008920` hanya helper CRT mirip `strtoull` untuk mengubah angka tadi kembali menjadi handle
3. worker membaca input dari pipe, membuang satu newline kalau ada, lalu memastikan panjang input tepat 32 byte
4. `v13` berisi 8 dword, yang sebenarnya membentuk key sepanjang 32 byte
5. kondisi pada `while` adalah validation check utama

Kalau kita cek data yang dipakai oleh loop tersebut di IDA:

- `0x140019340` berisi semua angka dari `0..31` tepat satu kali, jadi ini adalah permutation untuk urutan pengecekan
- `0x140019360` berisi `13 29` yang berulang sebagai nilai tambahan
- `0x140019380` berisi 32 byte yang merupakan encoded expected values

Kalau nama variabelnya kita rapikan, logic-nya jadi jauh lebih jelas:

```c
i = 0;
while ( true )
{
    idx = PERM[i];                                 // which character gets checked now

    if ( ADD[idx] + (input[idx] ^ key[idx])        // compute...
         != EXP[idx] )                             // ...compare
        break;                                     // mismatch -> fall out, v8 = 0

    ++i;                                           // char survived -> next round
    if ( i >= 32 ) { v8 = 1; goto reply; }         // survived all 32 -> success
}
v8 = 0;
```

Itu basically seluruh validation check-nya.

### The Key

`v13` bukan dihitung saat runtime. Compiler sudah melakukan folding pada fungsi pembentuk key, jadi hasil akhirnya menjadi constant yang langsung ditulis ke stack:

```c
v13[0] = 0x9AF95B84;
v13[1] = 0x9BEB50C9;
v13[2] = 0x5641816C;
v13[3] = 0x44D949E3;
v13[4] = 0xFD292501;
v13[5] = 0x41F8DA5C;
v13[6] = 0xC4DF655F;
v13[7] = 0xBD83A72E;
```

Karena value di atas adalah 32-bit dword, kita harus ingat urutan little-endian. Jadi:

```text
0x9AF95B84 -> 84 5B F9 9A
```

bukan:

```text
9A F9 5B 84
```

Kalau seluruh 8 dword digabungkan dalam urutan byte yang benar, kita mendapatkan key:

```text
84 5B F9 9A C9 50 EB 9B 6C 81 41 56 E3 49 D9 44
01 25 29 FD 5C DA F8 41 5F 65 DF C4 2E A7 83 BD
```

### The Expected Values

`EXP` juga tidak disimpan dalam bentuk plain table. Data pada `0x140019380` masih encoded dan baru didecode sebelum comparison loop:

```c
EXP[i] = ENCODED_EXPECTED[i] ^ key[(i + 5) % 32] ^ 0xC3
```

Jadi static path-nya cukup jelas:

```text
read ENCODED_EXPECTED
-> decode dengan KEY yang dirotasi 5 posisi
-> XOR dengan 0xC3
-> dapatkan EXP
```

Hasil `EXP` yang sudah didecode:

```text
e1 41 cd 0a c2 89 9a 20 6f 1f 31 8a 9e a3 99 50
7c 3d 58 c2 16 e1 9d 9b 7e 37 c2 1d 32 f2 0a e9
```

### The Inversion

Validation check-nya bisa ditulis menjadi:

```text
EXP[idx] = (input[idx] ^ KEY[idx]) + ADD[idx]   (mod 256)
```

Untuk membaliknya, kurangi `ADD` terlebih dahulu, lalu XOR dengan `KEY`:

```text
input[idx] = ((EXP[idx] - ADD[idx]) mod 256) ^ KEY[idx]
```

Ada satu hal yang cukup penting di sini: `EXP`, `ADD`, dan `KEY` semuanya memakai `idx` yang sama.

Artinya, setiap posisi bisa direcover secara independen.

`PERM` hanya menentukan urutan pengecekan. Misalnya karakter index 7 bisa dicek lebih dulu daripada index 0, tetapi hubungan antara `input[7]`, `KEY[7]`, `ADD[7]`, dan `EXP[7]` tetap sama.

Jadi kita tidak perlu melakukan un-permute terhadap flag.

Solver-nya menjadi:

```python
KEY = bytes.fromhex("845bf99ac950eb9b6c814156e349d944"
                    "012529fd5cdaf8415f65dfc42ea783bd")
ADD = bytes([0x13, 0x29] * 16)
ENC = bytes.fromhex("726995a5800b0f00e505b6487849a7cf"
                    "6506da5eb0fd9a761a77bc5aaac853e")

EXP = bytes(
    ENC[i] ^ KEY[(i + 5) % 32] ^ 0xC3
    for i in range(32)
)

flag = bytes(
    ((EXP[i] - ADD[i]) & 0xFF) ^ KEY[i]
    for i in range(32)
)

print(flag.decode())
```

Hasilnya:

```text
JCC{f0ll0w_7h3_ch1ld_br34kp01nt}
```

### Dynamic Solve (WinDbg)

Selain static analysis, challenge ini juga bisa diselesaikan secara dynamic menggunakan WinDbg.

Karena worker berjalan sebagai child process, pertama kita minta debugger untuk ikut attach ke child:

```text
0:000> .childdbg 1
Processes created by the current process will be debugged
0:000> g
```

`g` akan menjalankan parent. Parent kemudian membuat worker dengan argument `--worker <in> <out>`, lalu debugger akan attach ke child tersebut.

Setelah worker berhenti di initial breakpoint, masukkan candidate salah sepanjang 32 karakter, misalnya:

```text
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Karena ASLR aktif, kita pakai module-relative address.

Instruction yang membandingkan value berada di:

```text
tinytrace+0x160C
```

sedangkan conditional jump yang keluar saat mismatch berada di:

```text
tinytrace+0x1610
```

Kita bisa memasang breakpoint berikut:

```text
1:002> bp tinytrace+0x160C ".printf \"HIT idx=%d add=%02x key=%02x exp=%02x\\n\", @rcx, by(@r8+@rcx+0x19360), by(@rbp+@rcx-0x31), by(@rbp+@rcx-0x11); eb tinytrace+0x1610 90 90; gc"
1:002> g
```

Breakpoint itu melakukan beberapa hal sekaligus:

1. `@rcx` berisi `idx`, yaitu posisi karakter yang sedang dicek
2. `by(@r8+@rcx+0x19360)` membaca `ADD[idx]`
3. `by(@rbp+@rcx-0x31)` membaca `KEY[idx]`
4. `by(@rbp+@rcx-0x11)` membaca `EXP[idx]`
5. `eb tinytrace+0x1610 90 90` mengganti `jne` dengan dua `NOP`, jadi loop tidak berhenti pada mismatch pertama
6. `gc` melanjutkan execution ke iteration berikutnya

Hasilnya akan muncul seperti:

```text
HIT idx=7 add=29 key=9b exp=20
HIT idx=1 add=29 key=5b exp=41
HIT idx=9 add=29 key=81 exp=1f
HIT idx=16 add=13 key=01 exp=7c
...
HIT idx=4 add=13 key=c9 exp=c2
HIT idx=11 add=29 key=56 exp=8a
```

Perhatikan bahwa `idx` muncul mengikuti urutan `PERM`, bukan `0..31`.

Jadi hasil breakpoint perlu di-sort berdasarkan `idx` terlebih dahulu.

Setelah itu, rumus inversion-nya tetap sama:

```python
hits = [
    (7, 0x29, 0x9b, 0x20),
    (1, 0x29, 0x5b, 0x41),
    (9, 0x29, 0x81, 0x1f),
    (16, 0x13, 0x01, 0x7c),
    ...
]

hits.sort()

print(''.join(
    chr(((exp - add) & 0xFF) ^ key)
    for idx, add, key, exp in hits
))
```

Hasilnya tetap:

```text
JCC{f0ll0w_7h3_ch1ld_br34kp01nt}
```

Dynamic solve ini basically menggunakan validation logic yang sama dengan static solve. Bedanya, `ADD`, `KEY`, `EXP`, dan `idx` kita ambil langsung dari runtime melalui breakpoint, bukan direcover satu-satu dari `.rdata` dan stack layout.
