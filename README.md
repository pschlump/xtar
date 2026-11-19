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

### The annoyance that started it

It is a nuisance to hunt down the correct command — and often a whole
toolchain to install — every time a file arrives in a format your
machine does not have: the `.7z` that needs `p7zip`, the `.zst` that
needs a new-enough `zstd`, the `.tar.lzma` that needs `xz-utils`, the
`.cpio.Z` that needs `ncompress`, the split `.z01…zip` set that needs
`zip -s-` to merge first, the AES zip that needs something newer than
Info-ZIP.  Each one is a detour through a package manager before a
single byte is extracted.

xtar ends the detour: **one binary, no external dependencies, covers
every format above** — reads them all from any of its command names,
writes them all, decrypts zip (traditional and WinZip AES) and 7z
(AES-256) given the password.  If the format is listed in the
sniffing table below, some spelling of `tar`, `cpio`, `unzip`, or
`7z` already opens it.

---

## Table of contents

1. [Why](#why)
2. [Usage guide by command](#usage-guide-by-command) — the examples, every format with every command
3. [The multi-call binary](#the-multi-call-binary)
4. [The two axes: container vs. compression](#the-two-axes-container-vs-compression)
5. [Format detection: sniffing rules](#format-detection-sniffing-rules)
6. [The dialects](#the-dialects) — [tar](#tar-dialect) · [cpio](#cpio-dialect) · [zip](#zip-dialect) · [unzip](#unzip-dialect) · [7z](#7z-dialect) · [xtar](#xtar-dialect)
7. [Cross-tool behavior matrices](#cross-tool-behavior-matrices)
8. [Flag collisions across the real tools](#flag-collisions-across-the-real-tools)
9. [Unified semantics](#unified-semantics)
10. [Codec mapping to pluto](#codec-mapping-to-pluto)
11. [What is deliberately not supported (yet)](#what-is-deliberately-not-supported-yet)
12. [Exit codes](#exit-codes)
13. [Build and test](#build-and-test)
14. [Roadmap](#roadmap)

---

## Usage guide by command

Every example below was run against this binary.  The one rule to
remember: **the command name controls syntax; the file's content
controls the format** — so any command opens any supported archive,
and the output filename's extension picks what `c`/`a` writes.

The formats on the table: `tar`, `cpio` (newc/crc/odc/binary), `zip`
(deflate/store/bzip2/LZMA/zstd members, zip64, split sets, AES),
native `7z` (LZMA/LZMA2/delta/deflate/bzip2/copy/BCJ/AES), and bare
compressed streams — gzip, bzip2, compress(.Z), lz4, xz, lzma, zstd —
wrapping any container, in any combination.

### tar / gtar — extract, list, test, create, update

```sh
# Reading: format comes from the bytes, not the name
tar -xf archive.zip                  # a zip
tar -xf archive.cpio.gz              # gzip-wrapped cpio — no -z needed
tar -xf archive.tar.xz               # xz
tar -xf archive.tar.zst              # zstd
tar -xf archive.tar.lzma             # lzma-alone
tar -xf archive.7z                   # native 7z
tar -xf archive.z01                  # a split set (z01…zNN + .zip)
tar -tf archive.tar.bz2              # list instead of extracting
tar -tvf archive.zip                 # verbose listing, permissions shown
tar -xf actually-a-tar.tgz           # extension lies; magic wins (a note prints)

# Creating: the output name picks container and compression together
tar -cf out.tar dir/
tar -cf out.zip dir/                 # a real zip
tar -cf out.tgz dir/
tar -cf out.tar.xz dir/              # also .txz
tar -cf out.tar.zst dir/             # also .tzst
tar -cf out.tar.lzma dir/
tar -cf out.tar.bz2 dir/             # also .tbz2
tar -cf out.cpio dir/                # newc
tar -cf out.cpio.Z dir/              # compress(1)-wrapped
tar -cf out.tar.lz4 dir/

# Flags override the extension when you want them to
tar --zstd -cf out.tgz dir/          # zstd under a .tgz name — reads back by sniff
tar -Jcf out.tar.xz dir/             # -J forces xz, like gtar

# Selecting what comes out
tar -xf out.tar dir/sub '*.go'       # member patterns
tar -xf out.tar --strip-components=1 # drop the leading path
tar -xf out.tar -C dest/             # extract elsewhere
tar -xOf out.tar dir/a.txt           # one file to stdout
tar -cf from-list.tar -T list.txt    # members from a list file
tar -xf out.tar --exclude='*.log'

# Pipes and stdin work everywhere (tar streams)
tar -cf - -C src . | (cd dest && tar -xf -)
cat archive.tar.gz | tar -xf -       # -f - is stdin

# Appending and deleting (uncompressed and zip-family)
tar -rf out.tar extra.txt
tar --delete -f out.tar '*.log'      # delete by pattern

# Update-style
tar -uf out.tar dir/                 # add files newer than the archived copy
tar -Wcf out.tar dir/                # create and verify in one pass

# Safety, always on
tar -xf evil.tar                     # "../../escape.txt" skipped with a warning
```

### cpio — the find(1) pipeline, freed from cpio files

```sh
# Classic shapes
find . -type f | cpio -ov > a.cpio
find . -type f | cpio -ov -H crc > a-crc.cpio    # newc (default), crc, odc
cpio -idv < a.cpio
cpio -it < a.zip                                 # list a zip
cpio -idv < a.tar.zst                            # extract zstd-wrapped tar
cpio -it '*.go' < a.tar.gz                       # member patterns

# But everything else works too
cpio -it < archive.7z
cat a.tar.xz | cpio -it

# Writing other containers from the pipe
cpio -ov -H tar > a.tar                          # -H selects the container
```

### zip — create (any container), update, zipinfo listings

```sh
zip -r out.zip dir/                 # deflate members
zip -r -Z store out.zip dir/        # stored members
zip -r -Z bzip2 out.zip dir/
zip -r -Z lzma out.zip dir/
zip -r -Z zstd out.zip dir/
zip -r -P secret out.zip dir/       # traditional encryption
zip -r -t tar out.tar.gz dir/       # explicit container override: a real tar
zip out.zip extra.txt               # add to an existing zip
zip -d out.zip '*.log'              # delete members

zipinfo out.zip                     # zipinfo-style listing
zipinfo out.cpio                    # ...of a cpio
zipinfo -1 out.tgz                  # ...of a gzip-wrapped tar (names only)
```

### unzip — list, test, extract, stdout — from anything

```sh
unzip -l big.tar.gz                 # list a gzip-wrapped tar
unzip -l archive.z01                # split set
unzip -l archive.7z
unzip -p big.tar.gz docs/readme.md  # one member to stdout
unzip -t archive.zip                # CRC-test every member
unzip -q -o archive.zip -d dest/    # overwrite into dest/
unzip archive.zip docs/ -x docs/skip-me
unzip -P secret enc.zip             # password on the command line
unzip enc.zip                       # ...or type it at the hidden prompt
```

Encrypted archives read regardless of who wrote them: traditional
PKWARE, WinZip AES-128/192/256, and 7z AES-256 all decrypt with the
password (prompted with echo off, or `-P`).

### 7z / 7za / 7zr — one front end, every format

```sh
7z a out.7z dir/                    # native 7z (LZMA2, solid)
7z a -tzip out.zip dir/             # a zip
7z a -ttar out.tar dir/             # a tar
7z a -tgzip out.tgz dir/
7z a -mx0 out.7z dir/               # stored
7z a -ppassword out.7z dir/         # AES-256
7z a -mhe=on -ppassword out.7z dir/ # encrypt names too (header encryption)
7z a -tzip -mem=aes256 -ppw out.zip dir/   # WinZip-AES zip

7z x archive.zip -oout/             # extract with paths (note -o, no space)
7z e archive.tar.zst -oout/         # flattened extraction
7z l archive.cpio.Z
7z t archive.tar.lzma               # CRC-test
7z u out.7z dir/                    # update
7z d out.7z '*.log'                 # delete
7z b                                # benchmark every codec
7z h file.txt                       # CRC-32 + SHA-256 digests
7z x -ppassword enc.7z              # password (or the hidden prompt)
```

### xtar — the native face

```sh
xtar c out.tgz dir/                 # verbs: c x l t i
xtar x archive.zip
xtar l archive.7z
xtar t archive.tar.zst              # verify structure and checksums
xtar c note.txt.gz note.txt         # a bare gzip of one file
xtar l note.txt.gz                  # ...whose member is named note.txt
xtar --sniff mystery-file           # identify without extracting:
# mystery-file: gzip → tar (gnu) : 3 members, 1.2 MB → 4.7 MB
xtar --sniff whole.z01              # the split set, assembled size
```

### Pipes, streams, and memory

Tar and cpio read **streaming** — one member at a time through the
codec chain — so a 40 GB tarball lists in a few MB of RSS, from a
file or a pipe; `-f -` is stdin and `-O` writes members to stdout.
Zip, 7z, and bare streams are whole-buffer (their directories sit at
the end or the stream is one member).

### What every command refuses to do

* Write a member outside the destination (`../` paths are skipped and
  warned, exit 1 — the tar behavior, everywhere).
* Silently pass through an unsupported codec: rar and friends error
  with a pointer to the "deliberately not supported" section below.
* Differ on exit codes: 0 clean, 1 warnings, 2 fatal everywhere (the
  unzip 3/4/5/9/50 and 7z 7/8 families preserved for scripts).

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
   container: gzip, bzip2, compress(.Z), lz4, xz, lzma, zstd
   (real greedy+predefined-FSE compression; blocks that do not shrink
   store raw).

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
| xz            | `fd 37 7a 58 5a 00`                       | xz (pluto, M5)                           |
| zstd          | `28 b5 2f fd`                             | zstd (pluto, M5)                         |
| lz4 frame     | `04 22 4d 18`                             | skippable + concatenated frames ok       |
| zip           | `PK\x03\x04` / `PK\x05\x06` (empty) / `PK\x07\x08` (spanned) | zip64 supported          |
| 7z            | `7z\xbc\xaf\x27\x1c`                      | 7z read (M5)                             |
| ar            | `!<arch>\n`                               | read-side, not yet scheduled             |
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
| `.txz`, `.tar.xz`               | xz( tar )                      |
| `.tzst`, `.tar.zst`             | zstd( tar )                    |
| `.tar.Z`, `.taZ`                | compress( tar )                |
| `.tar.lz4`                      | lz4( tar )                     |
| `.cpio`                         | cpio newc                      |
| `.cpio.gz`, `.cpio.Z`, …        | compressed cpio, same table    |
| `.zip`                          | zip, deflate level 6           |
| `.7z`                           | 7z container (read)            |

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
  `-S/--sparse`, compression flags `-z -j -J --lzma --zstd -Z` (the
  output extension already selects compression, so there is no `-a`).
  The zip dialect's `-Z` selects the member method: `store`, `deflate`,
  `bzip2`, `lzma` (method 14), `zstd` (the WinZip id; the zstd project's
  own id is read too); 7z's `-mm=lzma`/`-mm=zstd` map to the same methods
  when writing zip.
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
* Key flags: `-r` recurse, `-e` encrypt (traditional PKWARE, read and
  written; AES is M5/M6), `-0`…`-9` level
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
* Split archives read natively: opening any part of `name.z01`…`name.zNN` +
  `name.zip` assembles the whole set (unzip(1) needs `zip -s-` to merge
  first, and its best-effort read of the joined bytes drops members).
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
* Native `.7z` archives read *and write*: reading covers every method
  the 7-Zip CLI writes plus LZMA, LZMA2, delta, deflate, bzip2, copy,
  BCJ (x86), and AES256 (content or `-mhe=on` header encryption); `a
  -t7z` writes solid LZMA folders (stored at `-mx0`, AES256 with a
  password), `u`/`d` rebuild in place, and the system 7zz plus
  libarchive validate both directions.
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
  charset — bytes pass through. `--encoding=` (unzip `-O`) converts member
  names on read: `utf-8`, `cp437`, `iso-8859-1`, `mac-roman` (zips created
  by old Windows and classic-Mac tools are the usual customers; names a
  container declares UTF-8 are left alone).
* **Sparse files.** All GNU sparse tar flavors are read — old-GNU `'S'`
  headers with extension headers, PAX 1.0 (map in the data blocks), and
  PAX 0.0/0.1 (records) — and `-S`/`--sparse` writes them: the old-GNU
  form under `--format=gnu`, PAX 1.0 under `--format=pax`. Extraction
  re-creates the holes; the logical size is what listings show. Hole
  detection follows SEEK_DATA/SEEK_HOLE and falls back to a block scan,
  so zero-filled-but-allocated files (APFS allocates truncate holes)
  still store sparsely.
* **Concatenation.** Multi-member gzip and concatenated lz4 frames are read.
  Split zip sets (`name.z01`… beside the final `name.zip`) are assembled and
  read in full, opened through any member of the set: the offsets split
  writers state per part are rebuilt by a signature scan matched to the
  central directory (unzip(1) itself cannot read a set without merging it
  first, `zip -s-`). Split-zip *writing* (`zip -s`) remains deferred.
* **Encryption.** zip traditional PKWARE encryption is read and written
  (passwords via `-P`/`-p`/prompt; shipped in M3); WinZip AES zips
  (AE-2, 128/192/256 — read everywhere, written via the 7z dialect's
  `-mem=aes128|192|256`) and 7z AES256 (read and write, `-mhe=on`
  header encryption read) shipped with the M5/M6 crypto work;
  tar/cpio have no encryption and never will (dialect errors if asked).
  Password prompts hide input — terminal echo is off while the secret
  is read (a plain read when stdin is not a terminal, so piped
  passwords work); replace/confirm prompts keep echoing, matching the
  native tools.
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
| xz (LZMA2 container)    | `pluto/xz`             | same + `DecodeLZMA2` (7z members) |
| lzma-alone (.lzma)      | `pluto/lzma`            | same + `DecodeRaw` (7z/zip members) |
| zstd (RFC 8878)         | `pluto/zstd`            | same; full decode, greedy+predefined-FSE encode |
| LZMA/LZMA2/delta/BCJ/AES (7z) | `pluto/xz`, `pluto/lzma` + xtar `sevenzfmt` | — |
| CRC-32 (gzip/zip/cpio-crc checks) | `pluto/crc` | `MakeTable32/Checksum32` |
| XXH64 (zstd checksums)  | xtar `zipfmt`/pluto `zstd` (internal `xxhash.go`) | — |
| XXH32 (lz4 checksums)   | `pluto/lz4` (internal `xxh32.go`) | — |

`pluto/lzw`, `pluto/huffman`, and `pluto/run_length` are teaching-format
variants (different wire formats) and are **not** used for any archive format
— documented here so nobody wires them in by accident.

### Gaps that gate the roadmap

| needed for        | missing codec      |
|-------------------|--------------------|
| `.tar.xz`, `.lzma` | *shipped (pluto M5)* |
| PPMd (7z, zip method 98) | PPMd (pluto) |

Until a codec exists, the extension/format **errors clearly** (e.g.
`xtar: lzma/zstd compression not yet supported — see README "What is deliberately
not supported"`), never silently passes bytes through.

### Memory model (current constraint)

pluto's codecs started whole-buffer (`[]byte → []byte`), and xtar M1–M3
materialized each archive layer/member in memory. As of M4 the pluto codecs
stream (`NewReader`/`NewWriter`), and xtar reads tar and cpio — compressed
or not, from a file or a pipe — one member at a time through
`eng.Archive.Each`: memory is bounded by the largest member, not the
archive (a 40 GB tarball lists at ~6 MB RSS). Zip and bare streams stay
whole-buffer by design: the zip central directory sits at the end of the
file, and a bare compressed stream is a single member.

---

## What is deliberately not supported (yet)

* **rar** — licensing plus a large, rarely-needed codec. Rar files error with
  a pointer to `unar`/`unrar`. Revisit only if pluto grows a rar decoder.
* **tar incremental/backups** (`-G`, `-N`, snapshot files) — a whole product
  of its own; not part of replacing day-to-day tar/cpio/zip usage.
* **Multi-tape/tape devices** (`-M`, `mt`-adjacent behavior). The `TAPE`
  environment variable *is* honored (it landed with M1); multi-volume
  itself stays out.
* **`zip -e` writing AES** — the zip dialect's `-e`/`-P` still writes
  traditional PKWARE (the compat choice); AES zip writing exists via
  the 7z dialect (`7z a -tzip -mem=aes256 -p<pw>`), and both read
  everywhere.  A `zip -Z aes` spelling is a small future add.
* ~~**7z writing**~~ — native 7z write shipped with M6 (`7z a -t7z`,
  solid LZMA folders, stored at `-mx0`, AES-256; `u`/`d` rebuild).  The
  7z *dialect* has driven tar/cpio/zip since M3.
* **AppleDouble/xattr round-trip in zip** (`zip -X` adjacent metadata) and
  macOS resource forks — still out (sparse and PAX write shipped in M4).

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

| milestone | contents | status |
|-----------|----------|--------|
| **M1** | skeleton: argv[0] dispatch, sniffing/peel engine, `--sniff`; tar dialect read+write (v7/ustar/GNU read, GNU write; PAX read) over the gzip layer; extract/list/create with path safety | ✅ shipped — 9c0c43a |
| **M2** | bzip2 + compress(.Z) + lz4 layers; cpio dialect (odc/newc/crc read+write, binary read); `TAPE` env; append/delete on uncompressed tar | ✅ shipped — 66a3ebd (the codec layers and `TAPE` landed early, with M1) |
| **M3** | zip container read+write (deflate/store, zip64, splits read; traditional encryption read+write); zip + unzip dialects; zipinfo mode | ✅ shipped — 63428a3 (notes below) |
| **M4** | pluto streaming refactor (`io.Reader/Writer` codec APIs) → stdin streaming and large archives; PAX write; sparse tar; `--encoding`; terminal raw-mode so prompts stop echoing | ✅ shipped — pluto 370df4b + streaming create 44756aa + streaming read 23c43ab + PAX write/sparse/`--encoding` 78dc36d + hidden password entry 8ba8ccf |
| **M5** | xz/lzma + zstd codecs in pluto; 7z container **read** (LZMA/LZMA2, BCJ, AES); spanned/split zip assembly | ✅ shipped — xz pluto 68cf37b + xtar b6c865b · lzma pluto 1d7fccd + xtar 64a0d98 · split-zip read e91c7fe · zstd pluto ce64622+2438aee + xtar 23d40c6 · 7z read c50844f |
| **M6** | 7z write; zip AES; benchmark/hash verbs; performance pass | ✅ shipped — 7z write 4d27c8d · zip AES 426dc21 · b/h verbs f28e8f9 · perf pass b192a19 |

M3 landed ahead of the plan in three places and short in one: zip64 is
*written* as well as read (the plan only promised read); the `7z` dialect
front-end moved up from M5 (`7z a/l/t/x/e/d` drive tar/cpio/zip and the
codec layers today, native `.7z` stays M5/M6); bzip2-protocol zip members
(method 12) rode along; and split-zip reading did not make it — spanned
archives are sniffed and then error clearly until M5.

Each milestone ends green on `make test` including the interop suite, and each
new format lands with its golden fixtures and a README table update.
