--- @since 25.12.29
--- mega-hash.yazi - checksums and signatures in a Modal, replacing gtkhash
---
--- Structure follows mega-mount.yazi (ya.sync state + Modal:children_add +
--- ya.which key loop driven by ya.join + M:new/M:layout/M:reflow/M:redraw),
--- which is the shape proven to work on this yazi. M:new is NOT optional --
--- yazi's modal.lua calls child:new(area) before every frame.
---
--- Everything the plugin does lives here: classifying the input (data file /
--- checksum manifest / PGP block), running rhash and gpg, rendering the
--- result and comparing a pasted hash against it. This used to be split, with
--- the classification and the tool calls in a `yazi-hash` shell helper that
--- the plugin shelled out to over a tab-separated porcelain protocol. The
--- split bought nothing once the helper was only ever called with
--- --porcelain, and cost a binary the plugin could not install for itself,
--- so it was folded in.
---
--- The modal opens before the hashing starts. Hashing a large file takes long
--- enough that a plugin which waited for it first looked like it had simply not
--- responded, so three coroutines run under ya.join: the key loop, the hasher,
--- and a ticker that advances the spinner while the hasher blocks.

--- Packagers may substitute absolute paths for these placeholders -- the NixOS
--- config this was written for does, so a yazi started with a minimal PATH
--- still finds the tools. Left unsubstituted each falls back to a PATH lookup,
--- so a plain clone into ~/.config/yazi/plugins works.
---
--- The `^@` test is what makes the fallback safe: an unsubstituted placeholder
--- still begins with an at-sign, and no absolute path does. Note that the
--- placeholders are deliberately NOT spelled out anywhere else in this file --
--- substituteInPlace replaces every occurrence, so a placeholder quoted in a
--- comment would come out of the build as a store path mid-sentence.
local function tool(subst, name)
	return subst:find("^@") and name or subst
end

local RHASH_BIN = tool("@rhash@", "rhash")
local FILE_BIN = tool("@file@", "file")
local GREP_BIN = tool("@grep@", "grep")
local GPG_BIN = tool("@gpg@", "gpg")

--- The canonical braille "dots" spinner -- a cluster chasing round the cell,
--- the one most TUIs use. Ten frames at 0.1s is one revolution per second,
--- which reads as working without being frantic.
local SPINNER = { "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏" }

--- Match badge: Font Awesome's check-circle (U+F058, nf-fa-check_circle) -- a
--- solid disc with the tick knocked out of it. A Nerd Font glyph rather than
--- an emoji like the green tick on purpose: emoji carry their own colour and
--- would ignore the styling applied below. Plain U+2713 was the previous badge
--- and is not in RobotoMono Nerd Font at all, so it silently fell back to
--- whatever else fontconfig found.
---
--- Written as raw UTF-8 bytes (EF 81 98) rather than the literal glyph: it is
--- in the Private Use Area and got silently stripped to an empty string
--- passing through tooling once already -- a failure that looks exactly like
--- "the badge does not render". Decimal escapes keep this line pure ASCII and,
--- unlike \u{}, parse under every Lua version.
local BADGE = "\239\129\152"

--- U+F057, the same family as BADGE, for a signature that failed. Same
--- Private-Use-Area caveat, same escaping.
local BADGE_BAD = "\239\129\151"

--- How each gpg verdict is presented. "Good" and "trusted" are deliberately
--- separate: gpg reports a good signature for any key in the keyring and puts
--- the trust caveat on its own WARNING line, so only a good AND trusted
--- signature gets the green badge the digest match uses. Anything less would
--- claim more than gpg said.
local VERDICTS = {
	good = { text = "GOOD SIGNATURE", colour = "green", badge = BADGE },
	good_untrusted = {
		text = "Good signature, but the key is NOT trusted",
		colour = "yellow",
	},
	bad = { text = "BAD SIGNATURE - the content does not match", colour = "red", badge = BADGE_BAD },
	nokey = { text = "Cannot check - the signer's key is not in your keyring", colour = "darkgray" },
	nodata = { text = "Signed file not found beside this signature", colour = "darkgray" },
	error = { text = "gpg could not verify this", colour = "red" },
}

--- Every digest computed for a data file, in the order rhash prints them:
--- CRC32, MD5, SHA1, SHA256, SHA512, BLAKE2b, BLAKE3. All seven go to ONE
--- rhash invocation, not one call per digest -- rhash reads the file once and
--- updates every context as it goes, so a 4 GiB ISO is read once rather than
--- seven times.
---
--- The count also sizes the modal before any digest has arrived; the names are
--- read back out of rhash's own output rather than listed here, so there is no
--- second list to keep in step with this one.
local DIGEST_FLAGS = { "--crc32", "--md5", "--sha1", "--sha256", "--sha512", "--blake2b", "--blake3" }

--- The armoured PGP headers worth telling apart, most specific first.
--- "-----BEGIN PGP ..." covers objects that want completely different
--- handling: a public key can be inspected and imported, a private key must
--- never be offered a casual import, and a signature is verified against a
--- separate data file rather than imported at all.
local PGP_HEADERS = {
	{ "PUBLIC KEY BLOCK", "publickey" },
	{ "PRIVATE KEY BLOCK", "privatekey" },
	{ "SIGNED MESSAGE", "clearsigned" },
	{ "SIGNATURE", "signature" },
}

--- The suffixes a detached signature conventionally carries over the file it
--- signs, longest-first so ".sign" is not mistaken for ".sig".
local SIG_SUFFIXES = { ".sign", ".asc", ".sig" }

--- The two unambiguous layouts `rhash -c` accepts, as one POSIX ERE:
---   GNU   "<hex>  name"   or "<hex> *name"
---   BSD   "SHA256 (name) = <hex>"
--- A single matching line is enough to call the file a manifest, because
--- nothing else looks like these: both start with something no prose line
--- starts with -- 8-to-128 hex digits, or "ALGO (...) = <hex>".
---
--- Deliberately conservative: a false positive here means rhash gets fed junk,
--- which is the whole problem being solved.
---
--- The shell version ran a `grep -v` first to strip blank lines and comments.
--- That pass is not needed: both branches are anchored at ^ with no
--- leading-whitespace allowance, and neither admits a leading ; or #, so no
--- comment or blank line can match in the first place.
---
--- A [==[ ]==] long string, not [[ ]], because the pattern contains
--- "[[:space:]]" -- whose trailing ]] would close a plain long bracket early.
local MANIFEST_RE =
	[==[^([0-9a-fA-F]{8,128}[[:space:]]+\*?[^[:space:]]|[A-Za-z0-9_-]+[[:space:]]*\(.+\)[[:space:]]*=[[:space:]]*[0-9a-fA-F]{8,128}[[:space:]]*$)]==]

--- SFV puts the name FIRST -- "name <crc32>" -- and that is a shape ordinary
--- text falls into by accident: a git log line "commit abc12345" fits it
--- exactly. So unlike the two above, one matching line proves nothing, and
--- SFV is recognised only when the WHOLE file is sfv: at least one entry
--- line, and no line that an sfv file could not contain.
---
--- SFV_ENTRY_RE is one entry. The name is held to a single non-blank run
--- rather than allowed to contain spaces, which costs sfv entries with spaces
--- in the filename and buys a much narrower pattern; the CRC is exactly 8 hex
--- at end of line. The leading [^#;...] keeps a bare "; abcdef12" comment
--- from reading as an entry for a file named ";".
local SFV_ENTRY_RE = [==[^[^#;[:space:]][^[:space:]]*[[:space:]]+[0-9a-fA-F]{8}[[:space:]]*$]==]

--- Every line an sfv file is allowed to contain: an entry, a blank line, or a
--- ; / # comment. `grep -v` on this finds the first line that disqualifies the
--- file, which is what separates a real sfv from a text file with one
--- sfv-shaped line in it.
local SFV_LINE_RE = [==[^([[:space:]]*([;#].*)?$|[^#;[:space:]][^[:space:]]*[[:space:]]+[0-9a-fA-F]{8}[[:space:]]*$)]==]

-- ---------------------------------------------------------------------------
-- Plumbing
-- ---------------------------------------------------------------------------

--- basename / dirname without shelling out to coreutils, which is all the
--- shell version used them for. dirname of a path with no slash is ".", and of
--- a root-level path is "/" -- the empty string the naive match returns is not
--- a directory anything can be run in.
local function basename(p) return p:match("[^/]+$") or p end

local function dirname(p)
	local d = p:match("^(.*)/[^/]*$")
	if not d then
		return "."
	end
	return d == "" and "/" or d
end

--- Run a tool and hand back its Output, or nil plus a message naming the tool
--- that could not be started. :output() force-pipes both streams, so nothing
--- here needs to ask for that; stdin stays null, which is what keeps gpg from
--- reaching for a pinentry and hanging the modal.
local function run(bin, args, cwd)
	local cmd = Command(bin):arg(args)
	if cwd then
		cmd = cmd:cwd(cwd)
	end
	local out, err = cmd:output()
	if not out then
		return nil, string.format("Could not run %s: %s", bin, tostring(err))
	end
	return out, nil
end

--- The shell captured every gpg and rhash call with `2>&1`, because gpg puts
--- its key listing on stdout and its warnings, progress and verdicts on
--- stderr, and both are wanted. Command hands them back separately, so they
--- are rejoined here -- stdout first, then stderr.
local function merged(out)
	local a, b = out.stdout or "", out.stderr or ""
	if a ~= "" and b ~= "" and not a:find("\n$") then
		a = a .. "\n"
	end
	return a .. b
end

--- Iterate non-empty lines. The `+` is what drops the blanks, matching the
--- shell's `[[ -n "$line" ]] && emit MSG "$line"`.
local function lines(text) return text:gmatch("[^\n]+") end

--- Is there a readable file at this path? Asked with `file`, not with
--- fs.cha, deliberately.
---
--- An earlier version of this used `fs.cha(Url(path), true)` and read .is_dir
--- off the result. That was the ONLY yazi API in the whole plugin that the
--- previous, working version had never called, and it sat on the path every
--- invocation took before the modal was opened -- so when the modal stopped
--- appearing at all, leaving yazi showing nothing but "1 left", this was the
--- one thing it could have been. `file` is already a dependency and is
--- already run on this very path by classify, so asking it costs nothing new
--- and keeps the plugin to the API surface that is known to work.
---
--- Returns "file", "dir" or "missing".
local function kind_of(path)
	local out = run(FILE_BIN, { "-Lb", "--mime-type", "--", path })
	if not out then
		return "missing"
	end
	local t = merged(out)
	if t:find("inode/directory", 1, true) then
		return "dir"
	elseif t == "" or t:find("cannot open", 1, true) then
		return "missing"
	end
	return "file"
end

local function skipped(path, why) return string.format("skipped (%s): %s", why, path) end

-- ---------------------------------------------------------------------------
-- Classification
-- ---------------------------------------------------------------------------

--- True when the whole file reads as sfv: it has at least one entry line, and
--- no line outside the sfv grammar. Both halves are needed -- the first alone
--- would claim any text file containing "commit abc12345", and the second
--- alone would claim every empty or all-comment file.
local function is_sfv(path)
	local any = run(GREP_BIN, { "-qE", SFV_ENTRY_RE, "--", path })
	if not (any and any.status.success) then
		return false
	end
	-- -v, so this succeeds the moment it finds a line sfv does not allow.
	local bad = run(GREP_BIN, { "-qvE", SFV_LINE_RE, "--", path })
	return not (bad and bad.status.success)
end

--- What this file is: "manifest", "pgp" (with the subtype as a second return),
--- or "data" for everything else.
---
--- Errors are swallowed rather than reported, matching the shell's
--- `2>/dev/null` on each of these: a missing `file` or `grep` degrades to
--- "data", which is the mode that needs no classification to be correct.
local function classify(path)
	-- Binary rules a manifest out outright -- no manifest is binary, and this
	-- is what catches the AppImage/ISO case, which is the common misfire.
	local out = run(FILE_BIN, { "-Lb", "--mime-encoding", "--", path })
	if out and (out.stdout or ""):match("^%s*(.-)%s*$") == "binary" then
		return "data"
	end

	out = run(GREP_BIN, { "-m1", "-E", "^-----BEGIN PGP", "--", path })
	local hdr = out and out.stdout or ""
	if hdr ~= "" then
		for _, h in ipairs(PGP_HEADERS) do
			if hdr:find(h[1], 1, true) then
				return "pgp", h[2]
			end
		end
		return "pgp", "other"
	end

	out = run(GREP_BIN, { "-qE", MANIFEST_RE, "--", path })
	if out and out.status.success then
		return "manifest"
	end

	-- Checked last, and with the whole file rather than one line, because its
	-- shape is the ambiguous one. See SFV_ENTRY_RE.
	if is_sfv(path) then
		return "manifest"
	end
	return "data"
end

--- The mode the modal runs in, decided from the input rather than from which
--- key was pressed. Returns the mode and, for the PGP modes, the subtype.
---
--- Only ever auto-selects a non-compute mode for a SINGLE argument: a
--- multi-file selection is unambiguously "hash these", even if one of them
--- happens to be a manifest.
local function detect(paths)
	if #paths ~= 1 then
		return "compute"
	end
	-- No separate "is this a regular file" guard: classify asks `file` first,
	-- and `file --mime-encoding` answers "binary" for a directory, so a
	-- directory already falls out as data and lands in compute, where it is
	-- skipped by name with a reason. One less thing to stat.
	local kind, pgp = classify(paths[1])
	if kind == "manifest" then
		return "check"
	elseif kind == "pgp" then
		if pgp == "publickey" then
			return "pgpkey", pgp
		elseif pgp == "clearsigned" or pgp == "signature" then
			return "pgpverify", pgp
		end
		return "pgp", pgp
	end
	return "compute"
end

-- ---------------------------------------------------------------------------
-- The work. Each returns a result table for set_results, or nil plus a message
-- for set_failure. All of these block, so all of them run in the worker
-- coroutine rather than in a ya.sync body.
-- ---------------------------------------------------------------------------

local function do_compute(paths)
	local rows, files, hashed = {}, {}, 0

	for _, target in ipairs(paths) do
		local args = {}
		for _, f in ipairs(DIGEST_FLAGS) do
			args[#args + 1] = f
		end
		-- --bsd gives "SHA256 (name) = hex", which is both readable and
		-- the format most download pages quote.
		args[#args + 1] = "--bsd"
		args[#args + 1] = "--"
		args[#args + 1] = target

		local out, err = run(RHASH_BIN, args)
		if not out then
			return nil, err
		end

		local before = #rows
		for line in lines(out.stdout or "") do
			-- "ALGO (name) = hex" -> ALGO and hex. The greedy `.*` splits on
			-- the LAST " = ", so a filename containing " = " cannot confuse it.
			local algo, hex = line:match("^(%S+)"), line:match(".* = (%S+)%s*$")
			if algo and hex then
				rows[#rows + 1] = { file = target, algo = algo, hex = hex }
			end
		end

		if #rows > before then
			files[#files + 1] = target
			hashed = hashed + 1
		else
			-- Nothing parsed, so rhash refused this one and said why on its
			-- message stream. Its exit status cannot be used to tell these
			-- apart: a directory exits 0 (with "Is a directory" and no digest
			-- lines) while a missing file exits 1, so the reason is read from
			-- the text rather than the code.
			local why, msg = "failed", merged(out)
			if msg:find("Is a directory", 1, true) then
				why = "directory"
			elseif msg:find("No such file or directory", 1, true) then
				why = "notfound"
			end
			rows[#rows + 1] = { text = skipped(target, why) }
		end
	end

	-- Nothing hashed, but the skip rows say why. Showing them beats a bare
	-- "Nothing hashed.": "skipped (directory): /path" is the whole answer.
	-- This is also what the shell did -- it emitted the SKIP records before
	-- exiting non-zero, and the modal rendered them.
	if hashed == 0 and #rows == 0 then
		return nil, "Nothing hashed."
	end
	return { mode = "compute", rows = rows, files = files }
end

local function do_check(paths)
	local rows, files = {}, {}

	for _, target in ipairs(paths) do
		if kind_of(target) ~= "file" then
			rows[#rows + 1] = { text = skipped(target, "notfound") }
		else
			files[#files + 1] = target
			-- Paths inside a manifest are relative to the manifest's own
			-- directory, which is almost never yazi's cwd -- hence the cwd and
			-- the bare basename rather than the full path.
			local out, err =
				run(RHASH_BIN, { "-c", "--ignore-case", "--", basename(target) }, dirname(target))
			if not out then
				return nil, err
			end
			-- rhash draws its own rules and banner, which mean nothing inside
			-- a Modal that already has a border and title. Keep the per-file
			-- verdict lines and the summary, drop the decoration.
			for line in lines(merged(out)) do
				if not line:find("^%-%-") then
					rows[#rows + 1] = { text = line }
				end
			end
		end
	end

	return { mode = "check", rows = rows, files = files }
end

--- A public key is the one PGP case with something useful to show and a safe
--- next step, so it gets its own mode. --show-keys is the explicit command for
--- reading a key file without touching the keyring; --with-fingerprint alone
--- makes gpg print "WARNING: no command supplied. Trying to guess what you
--- mean" and then guess correctly, which is not worth relying on.
local function do_pgpkey(path)
	local out, err = run(GPG_BIN, {
		"--batch",
		"--no-tty",
		"--keyid-format",
		"short",
		"--with-fingerprint",
		"--show-keys",
		"--",
		path,
	})
	if not out then
		return nil, err
	end

	local text, rows = merged(out), {}
	if not out.status.success then
		rows[#rows + 1] =
			{ text = string.format("gpg could not read this key (exit %s):", tostring(out.status.code or "?")) }
		for line in lines(text) do
			rows[#rows + 1] = { text = line }
		end
		return { mode = "pgpkey", rows = rows, files = { path }, inkeyring = false }
	end

	for line in lines(text) do
		rows[#rows + 1] = { text = line }
	end

	-- Whether the key is already known decides what the footer should offer:
	-- importing something already present is a no-op worth not suggesting.
	-- Every fingerprint in the file is checked -- a key block can carry
	-- several -- and the key counts as present only if all of them are.
	local fpr, known, any = nil, true, false
	for f in text:gmatch("Key fingerprint = ([0-9A-F ]+)") do
		-- Into a NEW local, never back into `f`. A for loop's control variable
		-- is read-only as of Lua 5.5, which is what yazi embeds: assigning to
		-- it does not fail at runtime, it makes the whole chunk refuse to
		-- compile, so the plugin never loads and yazi shows a stuck task and no
		-- window. Nothing in the file is reached, so nothing can report it.
		--
		-- Worth knowing when checking this file by hand: `luac` from Lua 5.4 or
		-- earlier accepts the assignment happily, so a green syntax check
		-- proves nothing here. Check with 5.5.
		local fp = (f:gsub("%s", ""))
		if fp ~= "" then
			any, fpr = true, fp
			local k = run(GPG_BIN, { "--batch", "--no-tty", "--list-keys", fp })
			if not (k and k.status.success) then
				known = false
			end
		end
	end

	return {
		mode = "pgpkey",
		rows = rows,
		files = { path },
		fpr = fpr,
		inkeyring = any and known,
	}
end

--- Clear-signed carries its own text, so it verifies alone. A detached
--- signature needs the file it signs, which by convention sits beside it with
--- the .asc/.sig/.sign suffix removed.
local function do_pgpverify(path, kind)
	local rows = {}
	local function msg(t) rows[#rows + 1] = { text = t } end

	local out, err
	if kind == "signature" then
		local data
		for _, s in ipairs(SIG_SUFFIXES) do
			if path:sub(-#s) == s then
				data = path:sub(1, #path - #s)
				break
			end
		end

		if not data or kind_of(data) ~= "file" then
			msg("This is a detached signature: it verifies a separate file.")
			msg("")
			msg("Nothing matching it was found beside it. Expected the same")
			msg("name without the signature suffix, e.g.")
			msg("  " .. basename(path) .. "  ->  " .. basename(path:match("^(.*)%.[^.]*$") or path))
			msg("")
			msg("Verify by hand with:")
			msg("  gpg --verify " .. basename(path) .. " <the-signed-file>")
			return { mode = "pgpverify", rows = rows, files = { path }, verdict = "nodata" }
		end

		out, err = run(GPG_BIN, { "--batch", "--no-tty", "--verify", "--", path, data })
	else
		out, err = run(GPG_BIN, { "--batch", "--no-tty", "--verify", "--", path })
	end
	if not out then
		return nil, err
	end

	-- 0 good, 1 bad, anything else could not check (usually a missing public
	-- key). "Good" is not "trusted": gpg reports a good signature for any key
	-- it holds and puts the trust caveat on a separate WARNING line, so that is
	-- tracked apart rather than collapsed into the verdict.
	local text, code, verdict = merged(out), out.status.code, nil
	if code == 0 then
		verdict = text:find("WARNING: This key is not certified", 1, true) and "good_untrusted" or "good"
	elseif code == 1 then
		verdict = "bad"
	elseif text:find("No public key", 1, true) then
		verdict = "nokey"
	else
		verdict = "error"
	end

	-- gpg's trustdb bookkeeping says nothing about this signature.
	for line in lines(text) do
		if
			not (
				line:find("checking the trustdb", 1, true)
				or line:find("marginals needed", 1, true)
				or line:find("depth:", 1, true)
			)
		then
			msg(line)
		end
	end

	return { mode = "pgpverify", rows = rows, files = { path }, verdict = verdict }
end

--- Everything else armoured: say what it is rather than pretending it is a
--- key, and point at the command that actually applies. Only `privatekey` and
--- `other` reach here -- detect() routes public keys and signatures to their
--- own modes above.
local function do_pgp(path, kind)
	local rows = {}
	local function msg(t) rows[#rows + 1] = { text = t } end

	if kind == "privatekey" then
		msg("That is a PGP PRIVATE key block.")
		msg("")
		msg("Not offered for import here on purpose -- importing a secret")
		msg("key is not something to do from a file browser by accident.")
		msg("If you meant to:  gpg --import " .. basename(path))
	else
		msg("That is an armoured PGP block, not a checksum file.")
		msg("")
		msg("  gpg --list-packets " .. basename(path))
	end

	return { mode = "pgp", rows = rows, files = { path } }
end

--- The only thing in this plugin that writes anything, which is why it is a
--- separate function reached from a separate key behind a confirmation rather
--- than a side effect of the inspect path.
---
--- The file is re-classified here rather than trusted from the modal's state:
--- the check that there is something safe to import belongs next to the write.
local function do_import(path)
	if kind_of(path) ~= "file" then
		return { { text = "Nothing to import." } }
	end

	local kind, pgp = classify(path)
	if kind ~= "pgp" or pgp ~= "publickey" then
		return { { text = "Refusing: that is not a PGP public key block." } }
	end

	local out = run(GPG_BIN, { "--batch", "--no-tty", "--import", "--", path })
	if not out then
		return nil
	end

	local rows = {}
	for line in lines(merged(out)) do
		rows[#rows + 1] = { text = line }
	end
	return rows
end

-- ---------------------------------------------------------------------------
-- State
-- ---------------------------------------------------------------------------

local toggle_ui = ya.sync(function(self)
	if self.children then
		Modal:children_remove(self.children)
		self.children = nil
	else
		self.children = Modal:children_add(self, 10)
	end
	ui.render()
end)

--- Compare the wanted hash against everything computed so far. Lives here so it
--- can run from either direction: the user pasting after the hashes arrive, or
--- the hashes arriving after the user has already pasted.
local function evaluate(self)
	if not self.want or not self.rows then
		return
	end
	-- Name the file only when there is more than one: with a single file the
	-- title already says which, and a full path here just runs off the edge.
	local multi = #(self.files or {}) > 1
	for i, r in ipairs(self.rows) do
		if r.hex and r.hex:lower() == self.want then
			local which = (multi and r.file) and ("  " .. basename(r.file)) or ""
			self.verdict = { ok = true, text = "MATCH  " .. (r.algo or "") .. which }
			-- Park the cursor on the hit so the badge is also where the eye is
			self.cursor = i - 1
			return
		end
	end
	if not self.loading then
		self.verdict = { ok = false, text = "NO MATCH  no digest here equals that hash" }
	end
end

local begin = ya.sync(function(self, files)
	self.loading = true
	-- The mode is not known yet: the worker classifies the input after the
	-- modal is already up. Tracked separately from `mode == nil`, which the
	-- redraw path treats as "a data file, probably" and draws the hash field
	-- for -- showing that field and then taking it away again if the file
	-- turns out to be a PGP key is exactly the flicker this avoids.
	self.detecting = true
	self.frame = 0
	self.rows = nil
	self.mode = nil
	self.files = files
	self.want = nil
	self.verdict = nil
	self.sigverdict = nil
	self.failure = nil
	self.note = nil
	self.cursor = 0
	ui.render()
end)

local tick = ya.sync(function(self)
	self.frame = (self.frame or 0) + 1
	ui.render()
end)

local is_loading = ya.sync(function(self) return self.loading == true end)

local stop_loading = ya.sync(function(self)
	self.loading = false
	ui.render()
end)

local set_results = ya.sync(function(self, res)
	self.loading = false
	self.mode = res.mode
	self.rows = res.rows
	self.files = res.files
	self.fpr = res.fpr
	self.inkeyring = res.inkeyring
	-- Kept apart from self.verdict, which is the hash comparison. They are
	-- different questions and never both apply.
	self.sigverdict = res.verdict
	self.cursor = 0
	evaluate(self)
	ui.render()
end)

--- Set by the worker the moment the input has been classified, which is what
--- tells redraw whether to show the expected-hash field, and tells the key
--- loop whether to focus it. Clearing `detecting` is what ends the "Looking at
--- the file..." frame.
local set_mode = ya.sync(function(self, mode)
	self.mode = mode
	self.detecting = nil
	ui.render()
end)

--- For the key loop: has the worker classified the input yet, and as what.
local mode_ready = ya.sync(function(self) return self.detecting ~= true end)
local get_mode = ya.sync(function(self) return self.mode end)

--- True only for a public key that is not already known. Importing something
--- already in the keyring is a no-op not worth offering.
local can_import = ya.sync(function(self) return self.mode == "pgpkey" and not self.inkeyring end)

local set_note = ya.sync(function(self, note)
	self.note = note
	ui.render()
end)

--- Replaces the key listing with gpg's import output and marks the key known,
--- so the footer stops offering an import that would now be a no-op.
local set_import_result = ya.sync(function(self, rows)
	self.rows = rows
	self.inkeyring = true
	self.cursor = 0
	self.note = nil
	ui.render()
end)

local set_failure = ya.sync(function(self, msg)
	self.loading = false
	self.failure = msg
	ui.render()
end)

local set_want = ya.sync(function(self, want)
	self.want = want
	self.verdict = nil
	evaluate(self)
	ui.render()
end)

local get_want = ya.sync(function(self) return self.want or "" end)

--- Where the real ya.input should be drawn: exactly over the stand-in field in
--- M:redraw, so opening it looks like that field gaining focus. ya.input's
--- "top-center" anchor counts y from the top of the screen, which is what
--- _want_area.y already is.
--- `ready` is false until M:layout has run at least once, because _want_area
--- only exists after a redraw. Opening the input before then fell back to a
--- guessed rect and drew a second, differently-sized box at the top of the
--- screen while the stand-in stayed inside the modal -- two "Expected hash:"
--- fields at once. entry() waits for this instead.
local input_pos = ya.sync(function(self)
	local a = self._want_area
	if not a then
		return { ready = false, y = 3, w = 70 }
	end
	return { ready = true, y = a.y, w = a.w }
end)

local move_cursor = ya.sync(function(self, delta)
	local n = #(self.rows or {})
	self.cursor = n == 0 and 0 or ya.clamp(0, (self.cursor or 0) + delta, n - 1)
	ui.render()
end)

--- Selected files, falling back to the hovered one. `tab.selected` yields Urls,
--- so tostring() is the right conversion -- unlike cx.yanked, which yields File
--- objects and needs .url first.
local selected_paths = ya.sync(function()
	local tab, paths = cx.active, {}
	for _, u in pairs(tab.selected) do
		paths[#paths + 1] = tostring(u)
	end
	if #paths == 0 then
		local h = tab.current.hovered
		if h then
			paths[1] = tostring(h.url)
		end
	end
	return paths
end)

local M = {}

local KEYS = {
	{ on = "q", run = "quit" },
	{ on = "<Esc>", run = "quit" },
	-- Enter alone reopens the field. There used to be a `v` here too, left over
	-- from when the input needed summoning before it was focused on open; with
	-- nothing left for it to mean it was just an arbitrary letter that appeared
	-- to wipe the field, since it reopened blank.
	{ on = "<Enter>", run = "edit" },
	-- Shift-I, not i: lowercase i is "up" in the colemak pair below, and this
	-- is the one action in the whole plugin that writes anything. It also
	-- asks for confirmation before running.
	{ on = "I", run = "import" },
	-- Both the vim pair and the colemak pair this config uses elsewhere
	{ on = "k", run = "up" },
	{ on = "j", run = "down" },
	{ on = "i", run = "up" },
	{ on = "e", run = "down" },
	{ on = "<Up>", run = "up" },
	{ on = "<Down>", run = "down" },
}

local CONFIRM = {
	{ on = "y", run = "yes" },
	{ on = "n", run = "no" },
	{ on = "<Esc>", run = "no" },
}

function M:entry(job)
	local paths = selected_paths()
	if #paths == 0 then
		return ya.notify { title = "Checksums", content = "Nothing to hash", level = "warn", timeout = 3 }
	end

	-- Open the modal BEFORE classifying, and classify inside the worker.
	--
	-- Classification used to run here, ahead of toggle_ui, so the modal could
	-- open already knowing whether an expected-hash field made sense. The cost
	-- of that ordering is that anything which goes wrong while classifying --
	-- a tool that cannot be spawned, an API that misbehaves -- happens while
	-- there is still nothing on screen, and the failure is then indistinguish-
	-- able from the plugin never having been invoked: yazi sits there showing
	-- "1 left" and no window. That is not a trade worth making for one frame
	-- of polish, so the window now always appears and the classification
	-- reports into it like everything else.
	begin(paths)
	toggle_ui()

	local function worker()
		-- One `file`, and at most three `grep`s, over the input -- not a hash,
		-- so this returns promptly even for a 4 GiB ISO.
		local mode, pgp_kind = detect(paths)
		set_mode(mode)

		local res, err
		if mode == "check" then
			res, err = do_check(paths)
		elseif mode == "pgpkey" then
			res, err = do_pgpkey(paths[1])
		elseif mode == "pgpverify" then
			res, err = do_pgpverify(paths[1], pgp_kind)
		elseif mode == "pgp" then
			res, err = do_pgp(paths[1], pgp_kind)
		else
			res, err = do_compute(paths)
		end

		if not res then
			set_failure(err or "Nothing to show")
		elseif #res.rows == 0 then
			set_failure("Nothing to show")
		else
			set_results(res)
		end
	end

	--- Advances the spinner while the worker blocks. Exits as soon as loading
	--- clears, so ya.join below is not held open by it.
	local function ticker()
		while is_loading() do
			ya.sleep(0.1)
			tick()
		end
	end

	--- Opens the real input over the stand-in field. ya.input starts focused in
	--- insert mode, so a terminal paste lands straight in with no keypress
	--- first; Esc dismisses it and leaves the modal and its table in place.
	--- `prefill` carries the current value back in, so reopening is an edit
	--- rather than a blank re-entry -- submitting an empty field is then an
	--- explicit clear, which is the only thing that should look like one.
	local function prompt(prefill)
		local p = input_pos()
		local value, event = ya.input {
			title = "Expected hash:",
			value = prefill or "",
			pos = { "top-center", y = p.y, w = p.w },
			position = { "top-center", y = p.y, w = p.w }, -- older yazi spelling
		}
		if event == 1 and value then
			local want = value:gsub("%s", ""):lower()
			set_want(want ~= "" and want or nil)
		end
	end

	local function keys()
		-- Wait for the first layout pass before opening the input: its rect is
		-- computed from the field's, and that does not exist until M:layout has
		-- run once. Normally satisfied on the very next frame.
		--
		-- Also wait for the worker to have classified the input, since that is
		-- what decides whether an input belongs here at all. Both waits are
		-- bounded: if either never arrives the loop carries on without the
		-- prompt, which leaves a usable modal and an Enter key, rather than a
		-- key loop that never starts.
		for _ = 1, 150 do
			if input_pos().ready and mode_ready() then
				break
			end
			ya.sleep(0.02)
		end

		-- Focused from the moment the mode is known, which is the whole point:
		-- paste and press enter without a keystroke to get there first. Only
		-- for a data file though -- a PGP key or a manifest has no hash of
		-- yours to compare against, so an input would just be in the way.
		if get_mode() == "compute" then
			prompt("")
		end

		while true do
			local cand = KEYS[ya.which { cands = KEYS, silent = true }]
			local run_ = cand and cand.run or nil

			if run_ == "quit" or run_ == nil then
				-- Also releases the ticker, so ya.join can return
				stop_loading()
				break
			elseif run_ == "up" then
				move_cursor(-1)
			elseif run_ == "down" then
				move_cursor(1)
			elseif run_ == "edit" then
				if get_mode() == "compute" then
					prompt(get_want())
				end
			elseif run_ == "import" then
				if not can_import() then
					set_note("nothing to import here")
				else
					-- Confirm, because this is the only thing that writes to
					-- your keyring. The fingerprint is on screen above while
					-- this is being answered, which is the point of the order.
					set_note("Import this key into your keyring?   y / n")
					local c = CONFIRM[ya.which { cands = CONFIRM, silent = true }]
					if not c or c.run ~= "yes" then
						set_note("import cancelled")
					else
						set_note("importing...")
						local irows = do_import(paths[1])
						if not irows then
							set_note("could not run " .. GPG_BIN)
						else
							set_import_result(irows)
						end
					end
				end
			end
		end
	end

	ya.join(keys, worker, ticker)
	toggle_ui()
end

function M:reflow() return { self } end

--- Required by yazi's Modal: modal.lua calls child:new(area) before every
--- redraw. Without it the component throws "attempt to call a nil value
--- (method 'new')" on each frame, the modal never paints, and the key loop
--- sits waiting -- which looks like yazi doing nothing but showing "1 left".
function M:new(area)
	self:layout(area)
	return self
end

--- Rows of chrome around the body: 2 border + 1 top pad + 3 field + 1 verdict
--- + 1 blank, and 2 at the foot for the blank and the key hints.
local CHROME_H = 10

function M:layout(area)
	-- Width stays a share of the screen -- a SHA512 digest is 128 characters
	-- and wants all of it. Height does not: it is content plus chrome, because
	-- a fixed fraction left most of the box empty for the seven rows actually
	-- in it.
	local chunks = ui.Layout()
		:direction(ui.Layout.HORIZONTAL)
		:constraints({
			ui.Constraint.Percentage(5),
			ui.Constraint.Percentage(90),
			ui.Constraint.Percentage(5),
		})
		:split(area)

	-- While loading, size for the digest count rather than the single spinner
	-- line: a data file always yields these seven, so opening at the final size
	-- stops the box growing and re-centring under the cursor the moment the
	-- hashes land. Other modes still settle to their real height.
	local body_rows = self.loading and #DIGEST_FLAGS or math.max(#(self.rows or {}), 1)
	local h = math.min(body_rows + CHROME_H, area.h)
	local y = area.y + math.max(0, math.floor((area.h - h) / 2))

	self._area = ui.Rect { x = chunks[2].x, y = y, w = chunks[2].w, h = h }

	local inner = self._area:pad(ui.Pad(1, 2, 2, 2))
	-- Three rows for the expected-hash field, then the verdict, a blank, and
	-- the body. Three because that is exactly what ya.input occupies (its own
	-- top border carries the title, one row of text, bottom border) -- the
	-- field we draw here is a stand-in that the real input lands on top of, so
	-- opening it reads as the field gaining focus rather than as a second popup.
	local parts = ui.Layout()
		:constraints({
			ui.Constraint.Length(3),
			ui.Constraint.Length(1),
			ui.Constraint.Length(1),
			ui.Constraint.Fill(1),
		})
		:split(inner)

	self._want_area = parts[1]
	self._verdict_area = parts[2]
	self._body_area = parts[4]
	self._note_area = ui.Rect {
		x = self._area.x + 2,
		y = self._area.y + self._area.h - 2,
		w = self._area.w - 4,
		h = 1,
	}
end

function M:redraw()
	local elements = {
		ui.Clear(self._area),
		ui.Border(ui.Edge.ALL)
			:area(self._area)
			:type(ui.Border.ROUNDED)
			:style(ui.Style():fg("blue"))
			:title(ui.Line(self:title()):align(ui.Align.CENTER)),
	}

	-- Expected-hash field, present from the first frame so it can be filled
	-- while the hashes are still being computed. Drawn to match ya.input's own
	-- box (rounded border, title in the top edge) because the real input opens
	-- directly over this rectangle.
	if not self.detecting and (self.mode == nil or self.mode == "compute") then
		local value, style
		if self.want then
			value, style = self.want, ui.Style():fg("white")
		else
			value, style = "paste a hash, then enter", ui.Style():fg("darkgray"):italic()
		end
		elements[#elements + 1] = ui.Border(ui.Edge.ALL)
			:area(self._want_area)
			:type(ui.Border.ROUNDED)
			:style(ui.Style():fg("darkgray"))
			:title(ui.Line("Expected hash:"):style(ui.Style():fg("blue")))
		elements[#elements + 1] =
			ui.Text({ ui.Line(value):style(style) }):area(self._want_area:pad(ui.Pad(1, 1, 1, 1)))
	end

	if self.sigverdict then
		-- gpg's answer, in its own words and its own colour. Only a good AND
		-- trusted signature earns the badge the digest match uses.
		local v = VERDICTS[self.sigverdict] or VERDICTS.error
		elements[#elements + 1] = ui.Text({
			ui.Line((v.badge and (v.badge .. "  ") or "") .. v.text)
				:style(ui.Style():fg(v.colour):bold()),
		}):area(self._verdict_area)
	elseif self.verdict then
		local style = self.verdict.ok and ui.Style():fg("green"):bold() or ui.Style():fg("red"):bold()
		elements[#elements + 1] =
			ui.Text({ ui.Line(self.verdict.text):style(style) }):area(self._verdict_area)
	end

	-- Body: spinner while loading, otherwise the results table
	if self.loading then
		local glyph = SPINNER[((self.frame or 0) % #SPINNER) + 1]
		elements[#elements + 1] = ui.Text({
			ui.Line({
				ui.Span(glyph .. "  "):style(ui.Style():fg("blue")),
				ui.Span(self:loading_text()):style(ui.Style():fg("darkgray")),
			}),
		}):area(self._body_area)
	elseif self.failure then
		elements[#elements + 1] =
			ui.Text({ ui.Line(self.failure):style(ui.Style():fg("red")) }):area(self._body_area)
	else
		elements[#elements + 1] = ui.Table(self:build_rows())
			:area(self._body_area)
			:spacing(2)
			:row(self.cursor or 0)
			-- Green when the cursor is sitting on the matching row, blue
			-- otherwise. It has to be decided here rather than on the row or its
			-- cells: ratatui paints the Table's selected-row style OVER both of
			-- those, so styling the cells green was invisible for the one row it
			-- mattered on -- the cursor is parked on the match by design.
			-- No underline either way; it ran a rule through the digest.
			:row_style(ui.Style():fg(self:cursor_on_match() and "green" or "blue"))
			:widths(self:widths())
	end

	-- A transient note (confirm prompt, import progress) takes the footer over
	-- from the key hints while it is set.
	local foot, foot_style
	if self.note then
		foot, foot_style = self.note, ui.Style():fg("yellow"):bold()
	elseif self.mode == "pgpkey" then
		foot = self.inkeyring and "already in your keyring      q  close"
			or "I  import key      q  close"
		foot_style = ui.Style():fg("darkgray")
	elseif self.mode == "pgpverify" then
		-- The one actionable case: a missing signer key is exactly what the
		-- import flow fixes, so say so rather than leaving a dead end.
		foot = self.sigverdict == "nokey"
				and "import the signer's key, then run this again      q  close"
			or "q  close"
		foot_style = ui.Style():fg("darkgray")
	elseif self.mode == "compute" or self.mode == nil then
		foot, foot_style = "enter  edit hash      q  close", ui.Style():fg("darkgray")
	else
		foot, foot_style = "q  close", ui.Style():fg("darkgray")
	end

	elements[#elements + 1] =
		ui.Text({ ui.Line(foot):style(foot_style) }):area(self._note_area)

	return elements
end

function M:multi() return #(self.files or {}) > 1 end

--- The mode is known from the classification pass before the real work starts,
--- so the waiting line can say what is actually being waited on rather than
--- claiming to hash a file that is about to be read as a key.
function M:loading_text()
	if self.detecting then
		return "Looking at the file..."
	end
	if self.mode == "pgpkey" then
		return "Reading the key..."
	elseif self.mode == "check" then
		return "Verifying against the manifest..."
	elseif self.mode == "pgpverify" then
		return "Checking the signature..."
	end
	return "Loading the file's hashes..."
end

--- True when the cursor is on the row whose digest equals the pasted hash.
function M:cursor_on_match()
	if not self.want then
		return false
	end
	local r = (self.rows or {})[(self.cursor or 0) + 1]
	return r ~= nil and r.hex ~= nil and r.hex:lower() == self.want
end

function M:title()
	local title = "Checksums"
	if self.mode == "check" then
		title = "Checksum verification"
	elseif self.mode == "pgpkey" then
		title = "PGP public key"
	elseif self.mode == "pgpverify" then
		title = "Signature"
	elseif self.mode == "pgp" then
		title = "Not a checksum file"
	end
	local files = self.files or {}
	if #files == 1 then
		title = title .. " - " .. basename(files[1])
	end
	return title
end

function M:widths()
	-- Leading 2-wide column carries the match badge; it stays reserved even
	-- with nothing to show, so rows do not shift sideways once a hash is pasted.
	if self:multi() then
		return {
			ui.Constraint.Length(2),
			ui.Constraint.Length(9),
			ui.Constraint.Length(24),
			ui.Constraint.Fill(1),
		}
	end
	return { ui.Constraint.Length(2), ui.Constraint.Length(9), ui.Constraint.Fill(1) }
end

function M:build_rows()
	local rows = {}
	local multi = self:multi()
	for _, r in ipairs(self.rows or {}) do
		if r.hex then
			-- The whole matching row goes green -- badge, algorithm and digest
			-- together, so the confirmation reads as one thing rather than a
			-- green tick sitting beside a blue cursor row.
			local hit = self.want ~= nil and r.hex:lower() == self.want
			-- basename, not the full path: the column is 24 wide, so a path
			-- renders as its own first 24 characters -- "/home/greg/Downloa" --
			-- which identifies nothing. The match line above already uses the
			-- basename for the same reason.
			local badge, algo, hex = "", r.algo or "", r.hex or ""
			local file = r.file and basename(r.file) or ""
			if hit then
				local green = ui.Style():fg("green")
				badge = ui.Line(BADGE):style(ui.Style():fg("green"):bold())
				algo = ui.Line(algo):style(green)
				hex = ui.Line(hex):style(green)
				file = ui.Line(file):style(green)
			end
			-- The filename column only earns its width when more than one file
			-- was hashed; for a single file it repeats on every row and steals
			-- space from the digest, which is the thing being read.
			if multi then
				rows[#rows + 1] = ui.Row { badge, algo, file, hex }
			else
				rows[#rows + 1] = ui.Row { badge, algo, hex }
			end
		else
			rows[#rows + 1] = multi and ui.Row { "", "", "", r.text or "" } or ui.Row { "", "", r.text or "" }
		end
	end
	return rows
end

return M
