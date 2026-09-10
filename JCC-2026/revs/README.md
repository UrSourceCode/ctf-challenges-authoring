# JCC 2026 — Reverse Engineering

Reverse Engineering challenges I authored for JCC 2026.

| Challenge | Difficulty | Artifact |
| --- | --- | --- |
| Shuff / rev-101 | Baby | Android APK |
| Sudoku | Easy | Windows PE |
| Calcluator | Medium | LuaJIT bytecode |
| TinyTrace | Hard | Windows x64 PE |

## Challenge Progression

Shuff
-> decompile and reconstruct

Sudoku
-> follow hidden control flow

Calcluator
-> model state across operations

TinyTrace
-> understand process architecture and data flow

## Write-ups

Each challenge directory contains:

- `README.md` — English PoC
- `README-ID.md` — Indonesian PoC
- `release/` — participant artifact
- `solve/` — solver / debugger notes
- `assets/` — screenshots

## Challenges


### Shuff / rev-101 — Baby

A simple Android reversing challenge where the flag characters are shuffled and the reconstruction order is stored separately inside the APK. Intended as a first introduction to APK decompilation and navigating decompiled Java code.

[View challenge and PoC](./shuff-rev-101/)

### Sudoku — Easy

A Windows PE Sudoku game with a hidden `secret_score == 1337` condition behind the normal completion flow. The intended path is to find an interesting string, follow its xref, discover the hidden branch, and reverse the small flag decoder.

[View challenge and PoC](./sudoku/)

### Calcluator — Medium

A calculator compiled into LuaJIT bytecode where every operation updates both the visible answer and a hidden internal state. Participants need to reconstruct the checksum logic, recover the intended six-operation sequence, and use the final state to decrypt the flag.

[View challenge and PoC](./calculator/)

### TinyTrace — Hard

A Windows x64 PE where the same executable runs as both a parent and worker process. The actual validation happens inside the worker, so participants need to understand the process split, pipe communication, validation tables, and the reversible byte equation.

[View challenge and PoC](./tiny-trace/)

## Related

- Project page: Authoring the 2026 JCC Reverse Engineering Challenges