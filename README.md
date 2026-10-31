# mega-hash.yazi

Checksums and signatures in a modal for [Yazi](https://github.com/sxyazi/yazi) — a terminal replacement for [GtkHash](https://github.com/tristanheaven/gtkhash).

Computes CRC32, MD5, SHA1, SHA256, SHA512, BLAKE2b and BLAKE3 in a single pass over the file, then lets you paste an expected hash and see whether anything matches. Point it at a checksum manifest instead and it verifies that; point it at a PGP key or signature and it does the gpg thing that actually applies.

## Features

- 🔢 **Every digest at once** — one `rhash` invocation reads the file once and updates all seven contexts as it goes, so a 4 GiB ISO is read once rather than seven times
- 📋 **Paste-and-compare** — the expected-hash field is open and focused the moment the modal appears, so you can paste from a download page and press enter without a keystroke to get there first. The matching row goes green, badge and all, and the cursor parks on it
- ⏳ **Opens before it hashes** — the modal appears immediately with a spinner, sized for the digests that are coming, so a large file does not look like a plugin that failed to respond
- ✅ **Verifies checksum manifests** — hover a `SHA256SUMS`, a `foo.iso.sha256`, a BSD-style `SHA256 (foo) = …` list or a `bar.sfv` and it checks the files that manifest names, relative to the manifest's own directory
- 🔍 **Detects sfv by the whole file, not one line** — sfv puts the name first (`foo.iso 1A2B3C4D`), a shape ordinary text falls into by accident: a git log line `commit abc12345` fits it exactly. So a file counts as sfv only if *every* line is an entry, a comment or blank — where GNU and BSD manifests, which no prose resembles, are recognised from a single line. Filenames containing spaces are not matched, deliberately; misreading a text file as a manifest is the failure this plugin exists to prevent
- 🔑 **Inspects and imports PGP public keys** — shows the key and its fingerprint with `gpg --show-keys` (which never touches your keyring), says whether you already have it, and offers a confirmed import if you don't
- 🖊️ **Verifies PGP signatures** — detached (`file.asc`/`.sig`/`.sign` beside the file it signs) and clear-signed. Good-and-trusted, good-but-untrusted, bad, and can't-check are reported as four different things, because gpg reports them as four different things
- 🧠 **Picks its own mode** — data file, checksum manifest, public key, signature or private key is detected from the input, not from which key you pressed
- 🚫 **Refuses what it shouldn't do** — a PGP *private* key block is never offered for import, and says so
- 📄 **Multi-select** — hash a whole selection at once; the filename column appears only when there is more than one

## Why mode detection

`rhash -c` on anything that is not a checksum manifest spills its parser's internals. On a binary that is merely unhelpful:

```
zano-linux-x64-gui-release-v2.2.3.608.AppImage:1: file is binary
```

On an armoured PGP key it is actively misleading, because base64 armor lines look enough like `<hex>  <name>` that rhash half-parses them and reports a column of phantom misses:

```
zano_build_signer.asc:1: can't parse line "-----BEGIN PGP PUBLIC KEY BLOCK-----"
zano_build_signer                    No such file or directory
zano_build_signer                    No such file or directory
...
Errors Occurred: Errors:3   Miss:9   Success:0   Total:12
```

Neither is the user's fault, so the plugin classifies the input first and only hands rhash the things rhash understands — and hands the PGP things to gpg.

## Requirements

Four binaries on `PATH`, and nothing else — no helper script, no Lua dependencies:

- [`rhash`](https://github.com/rhash/RHash) — hashing and manifest verification
- `gpg` (GnuPG) — key inspection, import and signature verification
- `file` — binary detection, which is what keeps an ISO out of the manifest parser
- `grep` — reads the PGP armor header and tests for manifest shape

`file` and `grep` are subprocesses rather than Lua because yazi's plugin API exposes no way to read a file's contents: there is `fs.cha` for metadata, but no `fs.read`.

## Installation

Clone into your plugin directory:

```sh
git clone https://github.com/guttermonk/mega-hash.yazi.git ~/.config/yazi/plugins/mega-hash.yazi
```

Add a keybinding to `~/.config/yazi/keymap.toml`:

```toml
[[mgr.prepend_keymap]]
on  = [ "c", "h" ]
run = "plugin mega-hash"
desc = "Checksums"
```

### Packaging

`main.lua` carries one placeholder per tool — `@rhash@`, `@file@`, `@grep@` and `@gpg@`. Substitute any of them with an absolute path to pin that tool; each one left alone falls back to a `PATH` lookup, so a plain clone works with the four binaries installed normally.

Pinning matters when yazi may be started with a minimal `PATH`, which is why the NixOS config this was written for substitutes all four:

```nix
pkgs.runCommandLocal "mega-hash.yazi" { } ''
  mkdir -p "$out"
  cp ${inputs.mega-hash-yazi}/main.lua "$out/main.lua"
  substituteInPlace "$out/main.lua" \
    --replace-fail '@rhash@' '${pkgs.rhash}/bin/rhash' \
    --replace-fail '@file@'  '${pkgs.file}/bin/file' \
    --replace-fail '@grep@'  '${pkgs.gnugrep}/bin/grep' \
    --replace-fail '@gpg@'   '${pkgs.gnupg}/bin/gpg'
''
```

`--replace-fail` rather than `--replace`: a renamed placeholder should break the build, not silently revert to the `PATH` lookup it was meant to replace.

## Keys

| Key | Action |
|---|---|
| *(nothing)* | For a data file the expected-hash field is already focused — paste and press enter |
| `<Enter>` | Reopen the expected-hash field to edit it. Submitting it empty clears the comparison |
| `I` | Import the PGP public key shown, after a `y`/`n` confirmation. Shift-I, because this is the only action that writes anything |
| `k` / `j`, `i` / `e`, `↑` / `↓` | Move the cursor (vim and colemak pairs both bound) |
| `q` / `<Esc>` | Close |

The footer shows only the keys that apply to what is on screen.

## Credits

UI structure follows [mega-mount.yazi](https://github.com/guttermonk/mega-mount.yazi), itself forked from [yazi-rs/plugins:mount](https://github.com/yazi-rs/plugins).

## License

MIT
