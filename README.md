# xtar

One binary that replaces `tar`, `cpio`, `zip`, `unzip`, and `7z` — a busybox-style
multi-call executable where `argv[0]` selects the command-line dialect, and the
*content* of the archive (not the tool name) selects the archive format.

```
$ tar -xf myfile.zip          # works. So do all of these:
$ tar -xf myfile.cpio.gz
$ cpio -itv < archive.tar.bz2
$ unzip -l archive.tar.zst
$ 7z x archive.cpio.Z
```

The design rule in one line:

> **The dialect controls syntax; the content controls format.**

Every dialect can read (extract / list / test) every supported container under
every supported stream compression, and creates archives whose container and
compression are chosen by the output filename's extension unless explicitly
overridden by flags.

All codecs come from the sibling pure-Go library [`pluto`](../pluto) — zero
external dependencies, stdlib only.

---

## Table of contents

1. [Why](#why)
2. [The multi-call binary](#the-multi-call-binary)
3. [The two axes: container vs. compression](#the-two-axes-container-vs-compression)
4. [Format detection: sniffing rules](#format-detection-sniffing-rules)
5. [The dialects](#the-dialects) — [tar](#tar-dialect) · [cpio](#cpio-dialect) · [zip](#zip-dialect) · [unzip](#unzip-dialect) · [7z](#7z-dialect) · [xtar](#xtar-dialect)
6. [Cross-tool behavior matrices](#cross-tool-behavior-matrices)
7. [Flag collisions across the real tools](#flag-collisions-across-the-real-tools)
8. [Unified semantics](#unified-semantics)
9. [Codec mapping to pluto](#codec-mapping-to-pluto)
10. [What is deliberately not supported (yet)](#what-is-deliberately-not-supported-yet)
11. [Exit codes](#exit-codes)
12. [Examples](#examples)
13. [Build and test](#build-and-test)
14. [Roadmap](#roadmap)

---

## Why

The five tools the UNIX world actually uses disagree about everything except
`-v`:

* **tar** and **cpio** stream a flat sequence of member headers+bodies and treat
  compression as an outer wrapper you apply to the whole stream.
* **zip** and **7z** are random-access containers that compress *each member*
  inside the archive.
* **unzip** cannot create archives at all; **cpio** reads from stdin by default;
  **7z** puts a directory in `-ofoo` with no space; **tar** bundles flags and
  allows `tar xf` with no dash.

Prior art already converged partway, and xtar adopts the union of those
behaviors under every name:

* GNU tar auto-detects compression when reading (no `-z` needed for `tar xf
  foo.tgz`) and has `--auto-compress`/`-a` to pick compression from the output
  extension when writing.
* bsdtar (libarchive) auto-detects *format* too — `bsdtar -xf foo.zip` and
  `bsdtar -tf foo.cpio.Z` already work — and chooses its write format from the
  `-f` extension (`bsdtar -cf foo.zip …` writes a zip).
* 7-Zip accepts many foreign formats via `-t` and (since 15.06) extracts
  compound `.tar.gz` archives in one step.

xtar is that convergence done uniformly: **every** name gets **every** format,
with each name's native flags still parsing the way its users' scripts expect.

---

## The multi-call binary

One executable, `xtar`. The behavior is selected by the name it was invoked
under (`filepath.Base(os.Args[0])`):

| invoked as      | dialect                    |
|-----------------|----------------------------|
| `tar`, `gtar`   | GNU-tar-compatible         |
| `cpio`          | GNU-cpio-compatible        |
| `zip`           | Info-ZIP-zip-compatible    |
| `unzip`         | Info-ZIP-unzip-compatible  |
| `7z`, `7za`, `7zr` | p7zip-compatible        |
| `zipinfo`, `unzip -Z` | zipinfo listing mode |
| `xtar`          | xtar's own unified dialect |

`make links` (or `make install`) drops symlinks into `bin/`:

```
bin/tar -> xtar
bin/cpio -> xtar
bin/zip -> xtar
bin/unzip -> xtar
bin/7z -> xtar
...
```

Put `bin/` on `PATH` ahead of the system tools rather than replacing `/bin/tar`
— xtar aims for script compatibility, not for being `/bin/tar`.

Invoked as plain `xtar`, it takes an explicit verb (`xtar x`, `xtar l`, …) —
see [xtar dialect](#xtar-dialect). `xtar --sniff FILE` prints the detected
format chain and exits, for debugging detection.

---

## The two axes: container vs. compression

Every archive xtar handles decomposes along two independent axes:

1. **Container** — how members are catalogued: `tar` (v7/ustar/GNU/PAX),
   `cpio` (binary/odc/newc/crc), `zip`, `7z`.
2. **Stream compression** — a whole-stream transform wrapped *around* a
   container: gzip, bzip2, compress(.Z), lz4, (xz, zstd — planned).

tar-family tools put compression *outside* the container. zip and 7z compress
*inside*, per member. Both axes can stack, so a file is an onion to peel:

```
foo.tar.gz      =  gzip( tar(members) )      compression outside
foo.zip         =  zip( deflate(member)… )   compression inside
foo.zip.gz      =  gzip( zip(…) )            both, legal
foo.tar         =  tar(members)              bare container
foo.gz          =  gzip(single stream)       no container — see below
```

Peeling rule: while the outer layer is a **stream compression** codec, decode
it and keep peeling; the first **container** layer found ends the peel. That
container is the archive. A bare compressed stream with no container inside
(`foo.txt.gz`, the domain of `gzip(1)`/`zcat`) is treated as an implicit
one-member archive whose member name is the filename minus compression
suffixes — so `tar -xf foo.txt.gz` extracts `foo.txt`, matching what `gunzip`
would leave behind. (`tar -xOf foo.txt.gz` prints it.)

---

## Format detection: sniffing rules

**Extensions are hints; magic bytes are truth.** The extension resolves
ambiguity and drives *creation*; sniffing decides *reading*.

### Magic table (read side)

| format        | magic at offset 0                        | notes                                    |
|---------------|------------------------------------------|------------------------------------------|
| gzip          | `1f 8b`                                   | multi-member files supported             |
| compress .Z   | `1f 9d` (or `1f a0`)                      | LSB-first LZW, block mode                |
| bzip2         | `"BZh"` + level digit                     | block magic `1AY&SY` follows             |
| xz            | `fd 37 7a 58 5a 00`                       | *planned*                                |
| zstd          | `28 b5 2f fd`                             | *planned*                                |
| lz4 frame     | `04 22 4d 18`                             | skippable + concatenated frames ok       |
| zip           | `PK\x03\x04` / `PK\x05\x06` (empty) / `PK\x07\x08` (spanned) | zip64 supported          |
| 7z            | `7z\xbc\xaf\x27\x1c`                      | *planned*                                |
| ar            | `!<arch>\n`                               | read-side, phase 3                       |
| rar           | `Rar!\x1a\x07`                            | out of scope (see [limits](#what-is-deliberately-not-supported-yet)) |
| cpio (odc)    | `"070707"` at 0                           | ASCII portable                           |
| cpio (newc)   | `"070701"` at 0                           | SVR4                                     |
| cpio (crc)    | `"070702"` at 0                           | newc + checksum field                    |
| cpio (binary) | `0xC7 0x71` or `0x71 0xC7` at 0           | byte-swapped variants both accepted      |
| tar           | `"ustar"` at **offset 257**              | `\x0000` = POSIX ustar, `" \x00"` = GNU  |
| tar (v7)      | no magic — header checksum validates      | extension breaks the tie                 |

### Precedence and edge rules

* Compression magics never collide with container magics, so the peel is
  deterministic. Peeling depth is capped (8) — `zip.gz.gz.gz…` loops are an
  error, not a hang.
* The empty-zip `PK\x05\x06` signature is checked before plain `PK\x03\x04`
  would fail on a zero-entry archive.
* **Conflict policy:** if the extension and the sniffed format disagree, the
  sniffed format wins and a note is printed (suppressed by `-q`). `--format`
  forces detection off entirely.
* Extension-only cases: v7 tar (no `ustar` magic; `.tar` assumed), `.lzma`
  (magic is weak/variable), and the create side, below.
* Detection works identically on stdin (`tar -xf -`), since cpio dialects
  default to stdin — sniff from a buffered head, not a seek.

### Create side: extension selects

Writing an archive with `-f NAME` picks container+compression from NAME's
suffixes (GNU tar's `-a`/`--auto-compress`, extended to containers, following
the bsdtar write-by-extension precedent):

| NAME ends in                    | written as                     |
|---------------------------------|--------------------------------|
| `.tar`                          | tar (GNU format default, see below) |
| `.tgz`, `.taz`, `.tar.gz`       | gzip( tar )                    |
| `.tbz`, `.tbz2`, `.tz2`, `.tar.bz2` | bzip2( tar )               |
| `.txz`, `.tar.xz`               | xz( tar ) *planned*            |
| `.tzst`, `.tar.zst`             | zstd( tar ) *planned*          |
| `.tar.Z`, `.taZ`                | compress( tar )                |
| `.tar.lz4`                      | lz4( tar )                     |
| `.cpio`                         | cpio newc                      |
| `.cpio.gz`, `.cpio.Z`, …        | compressed cpio, same table    |
| `.zip`                          | zip, deflate level 6           |
| `.7z`                           | 7z container *planned*         |

Explicit flags override extensions: tar's `-z/-j/-J/--zstd/-Z` and
`--format=`, cpio's `-H`, 7z's `-t`, and the global `--format=`. Creating
`tar -cf foo.zip d/` therefore writes a real zip; creating `zip -r foo.tar d/`
writes a tar — symmetric, and each prints what it chose unless `-q`.

---

## The dialects

Each dialect parses the native flag syntax of the tool it replaces (bundled
short flags, dashless first word for tar, operand positions for zip/unzip/7z).
Flags xtar does not implement **error clearly** — they are never silently
ignored, because a script that passes them depends on them.

### tar dialect

Compatible with GNU tar's common surface (bsdtar extensions accepted where
they don't conflict).

* Operations: `-c` create, `-x` extract, `-t` list, `-r` append, `-u` update,
  `-d`/`--diff` compare, `--delete`, `-A`/`--concatenate`.
* Bundled flags and the dashless word form both work: `tar -cvzf f.tgz d/`
  and `tar cvfz f.tgz d/` and `tar xf f.tgz`.
* Key modifiers: `-f`, `-C DIR`, `-v`, `-O` (to stdout), `-p`, `-m`, `-k`,
  `--overwrite`, `--skip-old-files`, `--strip-components=N`, `--exclude=PATTERN`,
  `-T/--files-from`, `--null`, `--transform`, `-w`, `-W/--verify`, `--totals`,
  `--numeric-owner`, `--owner/--group`, `--format=gnu|pax|ustar|v7`,
  compression flags `-z -j -J --zstd -Z -a`.
* Auto-detect on read; auto-compress and format-by-extension on write.
* Default write format is GNU (`gnu`) to match GNU tar; `--format` overrides.
* Append/update/delete work only on uncompressed tar — a compressed or
  non-seekable container gives GNU tar's error shape:
  `xtar: Cannot update compressed archives`.

### cpio dialect

Compatible with GNU cpio.

* Modes: `-i` extract (remaining operands are member patterns), `-o` create,
  `-p` pass-through (operand is the destination directory — no archive involved).
* Key modifiers: `-d`, `-t` (list instead of extract), `-v`, `-u`, `-m`,
  `-B`/`-C N` blocking, `-F/--file=ARCHIVE`, `-I`/`-O` input/output archive,
  `-E FILE` pattern file, `-A` append, `-H bin|odc|newc|crc|tar|ustar`,
  `--no-absolute-filenames` (default ON, as GNU cpio), `--force-local`,
  `--quiet`.
* **stdio defaults:** with no `-F/-I/-O`, copy-in reads stdin and copy-out
  writes stdout — `find . | cpio -ov > a.cpio` and `cpio -id < a.cpio` are
  the primary cpio idioms and must keep working.
* Sniffing applies to the stdin stream just as to a file, so
  `gunzip -c a.cpio.Z | cpio -id` and `cpio -id < a.cpio.Z` both work —
  the second is an xtar behavior (GNU cpio also accepts it).
* Patterns are shell-style regexes matched against member names, evaluated
  after the container is sniffed, whatever it is.

### zip dialect

Compatible with Info-ZIP zip's common surface.

* `zip [flags] ARCHIVE INFILES...` — first operand is the archive, the rest
  are inputs; adding an existing archive updates/replaces matching members by
  default (as Info-ZIP does).
* Key flags: `-r` recurse, `-e` encrypt (read side: traditional PKWARE
  encryption; writing AES-encrypted zips is phase 4+), `-0`…`-9` level
  (`-0` = store), `-x` exclude, `-i` include, `-m` move (delete inputs after),
  `-d` delete members, `-u`/`-f` update/freshen, `-g` grow in place, `-s SIZE`
  split, `-j` junk paths, `-y` store symlinks as symlinks, `-T` test after,
  `-z` comment, `-n SUFFIXES` store-by-suffix, `-F/-FF` fix, `-q -v`.
* If ARCHIVE's name selects a non-zip container (`.tar.gz`, `.cpio`, …) xtar
  writes that container instead, symmetric with `tar -cf foo.zip`.
* Text-conversion conveniences (`-l` CRLF translation, `-a`/`-aa` in unzip)
  are unsupported and error clearly — archives are byte streams, and silent
  newline mangling is a data-integrity bug, not a feature.

### unzip dialect

Compatible with Info-ZIP unzip.

* `unzip [flags] ARCHIVE[.zip] [MEMBER...] [-d DIR] [-x EXCLUDE...]` —
  `.zip` is appended if ARCHIVE is missing as-named, exactly like unzip.
* Key flags: `-l` list, `-v` verbose listing, `-p` members to stdout (no
  extraction), `-t` test CRCs, `-d DIR` target, `-x` exclude, `-o` overwrite,
  `-n` never overwrite, `-u`/`-f` update/freshen, `-j` junk paths, `-q`,
  `-P PASS` password, `-Z` (or the `zipinfo` name) zipinfo-style listing.
* Works on any container xtar reads — `unzip -l foo.tar.bz2` lists it.
* Interactive overwrite prompts behave like unzip (`[y]es, [n]o, [A]ll, [N]one,
  [r]ename`); `-o`/`-n`/`-q` suppress them, as do non-tty stdin closes.

### 7z dialect

Compatible with p7zip's command/switch shape.

* Commands: `a` add, `e` extract-flattened, `x` extract-with-paths, `l` list,
  `t` test, `u` update, `d` delete, `rn` rename, `b` benchmark, `h` hash,
  `i` show supported codecs.
* Switches: `-o{DIR}` (**no space after `-o`**), `-p{PASS}` (or `-p` to
  prompt), `-t{TYPE}` forces format, `-mx{1-9}`, `-m0=CODEC[:opts]` method
  chain, `-x{PATH}` exclude, `-r` recurse, `-si`/`-so` stdin/stdout,
  `-sdel`, `-y` assume-yes, `-mhe=on` (7z header encryption), `-v{SIZE}`.
* `e` vs `x` applies to every container: `7z e foo.tar.gz` flattens, matching
  p7zip's `e` semantics; compound archives extract in one step
  (7-Zip ≥ 15.06 behavior).
* `-t` maps to the global `--format=`; an unknown `-t` value is an error.

### xtar dialect

The native face — one verb set, all formats:

```
xtar c [flags] ARCHIVE FILES...    create
xtar x [flags] ARCHIVE [MEMBERS..] extract
xtar l [flags] ARCHIVE [MEMBERS..] list
xtar t ARCHIVE...                  test (CRCs)
xtar i                             list codecs/formats
```

It accepts the superset: `-C DIR`, `-O`, `--strip-components`, `--exclude`,
`--flatten` (= 7z `e`/unzip `-j`), `--format=`, `--encoding=`, `--stdin`/
`--stdout`, `--sniff`.

---

## Cross-tool behavior matrices

### Read matrix — every dialect reads every format

Container ↓ / dialect → | `tar -x/-t` | `cpio -i` | `unzip` | `7z x/e/l` | `xtar`
---                    | --- | --- | --- | --- | ---
tar, any compression   | ✓ | ✓ | ✓ | ✓ | ✓
cpio, any compression  | ✓ | ✓ | ✓ | ✓ | ✓
zip                    | ✓ | ✓ | ✓ | ✓ | ✓
7z *(planned)*         | ✓ | ✓ | ✓ | ✓ | ✓
bare stream (`.gz` …)  | ✓ (implicit member) | ✓ | ✓ | ✓ | ✓

Dialect-specific *semantics* ride along regardless of container: member
patterns/operands filter the same way, `7z e` still flattens, `unzip -p` still
writes to stdout, cpio's `-t` still lists instead of extracting.

### Operation matrix

Operation  | tar | cpio | zip | unzip | 7z
-----------|-----|------|-----|-------|----
extract    | `-x` | `-i` (no `-t`) | — | default | `x` / `e` (flat)
list       | `-t` | `-i -t` | `-sf`/`-l`-ish | `-l`/`-v`/`-Z` | `l`
test       | `-d` (differs) | (via `-t` CRC check of `crc` format) | `-T` | `-t` | `t`
create     | `-c` | `-o` | default | — *(none)* | `a`
append     | `-r`/`-A` (uncompressed tar only) | `-A` (uncompressed cpio only) | default (adds/replaces) | — | `a`/`u`
update     | `-u` | — | `-u`/`-f` | `-u`/`-f` | `u`
delete     | `--delete` (uncompressed tar) | — | `-d` | — | `d`
rename     | `--transform` | — | — | — | `rn`
pass-through | — | `-p DIR` | — | — | —

A cell marked — is a genuine absence in the native tool; xtar keeps it absent
in that dialect rather than inventing behavior (unzip still cannot create).

### Overwrite/interaction defaults (native, preserved)

| dialect | default on existing file |
|---------|--------------------------|
| tar     | overwrite (keep old with `-k`, never with `--skip-old-files`) |
| cpio    | refuse older files, replace newer (`-u` = replace unconditionally) |
| zip     | n/a on extract |
| unzip   | prompt `[y]es [n]o [A]ll [N]one [r]ename`; `-o`/`-n` decide |
| 7z      | prompt; `-y` decides |

---

## Flag collisions across the real tools

The reason argv[0] must select the dialect: the same letters mean different
things, sometimes opposites. xtar preserves each native meaning *in its own
dialect* and never unifies them.

| flag | tar            | cpio             | zip           | unzip          | 7z
|------|----------------|------------------|---------------|----------------|----
| `-d` | diff archive   | make directories | delete members| target dir     | —
| `-f` | archive file   | (uses `-F`)      | —             | —              | —
| `-j` | bzip2 filter   | —                | junk paths    | junk paths     | —
| `-l` | one filesystem | link (pass-thru) | CRLF text conv| **list**       | —
| `-m` | **don't** keep mtime | **keep** mtime | —         | —              | —
| `-p` | preserve perms | **pass-through mode** | —      | password (`-P`)| password `-p{pwd}`
| `-t` | list           | list (in `-i` mode) | —       | **test**       | **type switch** `-t{fmt}`
| `-u` | update archive | unconditional overwrite | update | update     | —
| `-v` | verbose        | verbose          | verbose       | verbose        | verbose (`-bb`?)
| `-x` | extract        | —                | exclude       | exclude        | —
| `-B` | —              | 5120-byte blocks | —             | —              | —
| `-Z` | compress filter| —                | —             | zipinfo mode   | —
| `-T` | files-from     | —                | test archive  | —              | —
| `-C` | change dir     | —                | —             | case-insensitive| —
| `-O` | to stdout      | —                | —             | —              | — (`-so`)

The two stars of this table: **`-m` has opposite meanings in tar and cpio**
(strip vs. preserve mtime), and **`-t` is list / list / test / type-selector**
across four tools. A single unified parser would be wrong four ways; the
dialect split is the only faithful design.

7-Zip quirks preserved: `-oDIR` and `-pPASS` take their argument **attached**
(no space), commands are bare words (`a`, `x`), and switches may come after
operands.

---

## Unified semantics

Where the tools agree in spirit but differ in spelling, xtar applies one
policy with dialect-native spellings.

* **Path safety.** On extract in every dialect: absolute member names are
  stripped to relative (warning printed, matching tar), and members whose
  cleaned path still escapes the target (`..`, or a symlink-then-write trap
  xtar can detect) are **skipped with a warning** and count toward a nonzero
  exit status at the end. This matches GNU tar's observable behavior and is
  stricter than old cpio. `--unsafe-paths` opts out (it is not the default in
  any dialect).
* **Overwrite defaults** stay per-dialect (table above) for script compat.
* **stdio.** `-` as the archive name means stdin/stdout in every dialect.
  cpio keeps its stdio default; everything else keeps file default.
* **Timestamps/permissions/ownership** are restored to the extent the
  *container* carries them: tar and cpio carry the full UNIX stat;
  zip carries perms+mtime in the external attributes; restore defaults follow
  the dialect (tar `-p` behavior as root, cpio's `-m`, unzip's
  permissions-on-extract). Ownership restoration applies only when running
  with privilege, as in the native tools; `--owner/--group/--numeric-owner`
  override on create.
* **Symlinks and hardlinks** are stored/read in tar, cpio, and 7z; zip stores
  symlinks when created with `-y` (Info-ZIP behavior). Link targets are
  subject to the same path-safety rules as member names.
* **Filename encoding.** PAX `hdrcharset` and ustar UTF-8 are honored; zip
  uses the EFS (UTF-8) bit when set, else CP437; cpio newc has no declared
  charset — bytes pass through. `--encoding=` converts member names on read
  (zips created by old Windows tools are the usual customer).
* **Sparse files.** GNU/PAX sparse tar records are read correctly; writing
  sparse is phase 4.
* **Concatenation.** Multi-member gzip, concatenated lz4 frames, and
  multi-volume zip (spanned, `PK\x07\x08`) are all read. Split-zip *writing*
  (`zip -s`) is phase 3.
* **Encryption.** zip traditional PKWARE encryption is read (passwords via
  `-P`/`-p`/prompt); AES-encrypted zips and 7z AES are read in phase 4;
  tar/cpio have no encryption and never will (dialect errors if asked).
* **Empty input.** `tar -tf` on an empty file errors with tar's message;
  an empty zip (`PK\x05\x06` only) lists zero members; both match the tools.

---

## Codec mapping to pluto

Every codec xtar uses is pluto — no stdlib `compress/*`, no third-party code:

| format / layer          | pluto package          | API shape |
|-------------------------|------------------------|-----------|
| gzip (RFC 1952)         | `pluto/gzip`           | `Compress/Expand([]byte) []byte` |
| deflate (zip members, raw) | `pluto/deflate`     | same      |
| zlib (RFC 1950)         | `pluto/zlib`           | same      |
| bzip2                   | `pluto/bzip2`          | `Compress/CompressLevel/Expand` |
| compress .Z (zopen LZW) | `pluto/compress_z`     | `Compress/CompressBits/Expand` |
| lz4 frames (v1.6.5)     | `pluto/lz4`            | same      |
| CRC-32 (gzip/zip/cpio-crc checks) | `pluto/crc` | `MakeTable32/Checksum32` |
| XXH32 (lz4 checksums)   | `pluto/lz4` (internal `xxh32.go`) | — |

`pluto/lzw`, `pluto/huffman`, and `pluto/run_length` are teaching-format
variants (different wire formats) and are **not** used for any archive format
— documented here so nobody wires them in by accident.

### Gaps that gate the roadmap

| needed for        | missing codec      |
|-------------------|--------------------|
| `.tar.xz`, `.lzma`, zip-LZMA, 7z (LZMA/LZMA2) | xz/lzma (pluto) |
| `.tar.zst`, zip-zstd | zstd (pluto)     |
| 7z container      | 7z parsing + LZMA + BCJ filters + AES |
| PPMd (7z, zip method 98) | PPMd (pluto)  |

Until a codec exists, the extension/format **errors clearly** (e.g.
`xtar: xz compression not yet supported — see README "What is deliberately
not supported"`), never silently passes bytes through.

### Memory model (current constraint)

pluto's codecs are whole-buffer (`[]byte → []byte`), not `io.Reader` streaming.
xtar phase 1–3 therefore materializes each archive layer/member in memory.
This is fine for the sizes tar/cpio/zip workflows typically see, and it is
called out honestly because `tar -xf` on a 40 GB tarball is a legitimate use.
The streaming refactor (pluto `NewReader/NewWriter` pairs) is roadmap item M4
and unlocks large-archive operation plus true stdin streaming.

---

## What is deliberately not supported (yet)

* **rar** — licensing plus a large, rarely-needed codec. Rar files error with
  a pointer to `unar`/`unrar`. Revisit only if pluto grows a rar decoder.
* **tar incremental/backups** (`-G`, `-N`, snapshot files) — a whole product
  of its own; not part of replacing day-to-day tar/cpio/zip usage.
* **Multi-tape/tape devices** (`-M`, `mt`-adjacent behavior); `TAPE`
  environment variable support follows in M2 (it's cheap).
* **`zip -e` writing AES** (reading AES arrives with 7z crypto in M5);
  traditional PKWARE encryption is read and written from M3.
* **7z writing** its own container (reading is M5, writing is M6+).
* **AppleDouble/xattr round-trip in zip** (`zip -X` adjacent metadata) and
  macOS resource forks — PAX-limited in M4 alongside sparse.

---

## Exit codes

The three tools' families already share a 0/1/2 core, which xtar adopts
everywhere:

| code | meaning                                  |
|------|------------------------------------------|
| 0    | success                                  |
| 1    | completed with warnings (e.g. skipped unsafe members, CRC mismatch on some members) |
| 2    | fatal (unreadable archive, bad flags, missing file) |

Dialect-specific codes beyond 2 are preserved where scripts depend on them
(unzip's 3/4/5/9/50 family; 7z's 7/8 codes). xtar never invents new nonzero
codes below 64; anything xtar-specific (e.g. unsupported codec) is 2 with a
message.

---

## Examples

```sh
# The headline: tar extracts a zip
tar -xf myfile.zip

# Extension lies, magic wins (prints a note; -q silences)
tar -xf actually-a-tar.tgz

# tar writes whatever the name says
tar -cf out.zip dir/                     # a real zip
tar -cf out.cpio.Z dir/                  # compress(1)-wrapped newc cpio
tar -caf out.tgz dir/                    # -a: compression from extension

# cpio idioms, format-agnostic
find . -type f | cpio -ov > a.cpio
cpio -idv < a.tar.bz2
cpio -it '*.go' < a.zip

# unzip on non-zip
unzip -l big.tar.gz
unzip -p big.tar.gz docs/readme.md
zipinfo big.cpio                          # yes

# 7z dialect everywhere
7z x foo.tar.Z -oout/                     # note: -oout, no space
7z e foo.zip                              # flattened extraction
7z l foo.cpio.gz
7z a out.tar.gz dir/                      # writes tar+gz

# What did I just download?
xtar --sniff mystery-file
# gzip → tar (GNU) : 3 members, 1.2 MB → 4.7 MB

# Safety on by default, everywhere
tar -xf evil.tar                          # "../../etc/passwd" skipped, warned, exit 1
```

---

## Build and test

```
make            # go build -o bin/xtar
make links      # bin/{tar,cpio,zip,unzip,7z,7za,7zr,zipinfo,gtar} -> xtar
make test       # unit + interop tests
make cover
```

`go.mod` requires pluto with a local `replace` while both trees are in
development (`replace github.com/pschlump/pluto => ../pluto`); drop the
replace directive before publishing the module.

**Interop tests are the acceptance bar**: for every container × codec, round-trip
with the *system* tools where installed — `system tar -cf | xtar tar -xf`,
`xtar tar -cf | system tar -tf`, same for `zip`/`unzip`/`cpio` — plus golden
fixtures generated by the real tools and committed to `testdata/`. A format is
"supported" when the other implementation reads ours byte-tolerantly and we
read theirs. Detection tests cover every magic row above, the peel-depth cap,
the empty-zip case, and extension/magic conflicts.

---

## Roadmap

| milestone | contents |
|-----------|----------|
| **M1** | skeleton: argv[0] dispatch, sniffing/peel engine, `--sniff`; tar dialect read+write (v7/ustar/GNU read, GNU write; PAX read) over the gzip layer; extract/list/create with path safety |
| **M2** | bzip2 + compress(.Z) + lz4 layers; cpio dialect (odc/newc/crc read+write, binary read); `TAPE` env; append/delete on uncompressed tar |
| **M3** | zip container read+write (deflate/store, zip64, splits read; traditional encryption read+write); zip + unzip dialects; zipinfo mode |
| **M4** | pluto streaming refactor (`io.Reader/Writer` codec APIs) → stdin streaming and large archives; PAX write; sparse tar; `--encoding` |
| **M5** | xz/lzma + zstd codecs in pluto; 7z container **read** (LZMA/LZMA2, BCJ, AES); full 7z dialect verbs over all formats |
| **M6** | 7z write; zip AES; benchmark/hash verbs; performance pass |

Each milestone ends green on `make test` including the interop suite, and each
new format lands with its golden fixtures and a README table update.
