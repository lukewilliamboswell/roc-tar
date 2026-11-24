app [main!] { pkg: "../package/main.roc" }

import pkg.Tar
import lib/Mk as Mk
import "fixtures/written.tar" as written : List(U8)
import "fixtures/written.list" as written_list : Str

main! = |_args| Ok({})

# Rule sources:
# - USTAR: POSIX.1-1988 ustar header (IEEE Std 1003.1, pax "ustar Interchange
#   Format"): the field offsets and widths, octal numbers, the prefix field.
# - PAX: POSIX.1-2001 pax extended header `x`: records "<length>
#   <key>=<value>\n" for a field that does not fit in the ustar header.
# - TOOLS: tests/fixtures/written.tar, the sample of tests/tools/tarwrite.roc.
#   scripts/writer.sh checks that GNU tar 1.35 and bsdtar 3.5.3 list and
#   extract it the same, and written.list is its GNU `tar -tv`.
# - API: the rules of README.md "How to write".

# The members of tests/tools/tarwrite.roc (keep the two the same).
sample : List(Tar.Member)
sample = {
	mid = Str.repeat("m", 60)
	long = Str.repeat("L", 120)
	[
		Tar.dir("pkg/"),
		{ ..Tar.file("pkg/main.roc", "app [main!] {}\n".to_utf8()), mode: 0o755, mtime: 315532800 },
		Tar.file("pkg/empty", []),
		Tar.file("pkg/zeta.bin", List.repeat('z', 1000)),
		Tar.dir("pkg/${mid}/${mid}/"),
		Tar.file("pkg/${mid}/${mid}/Deep.roc", "deep\n".to_utf8()),
		Tar.file("pkg/${long}/Long.roc", "long\n".to_utf8()),
		Tar.symlink("pkg/link.roc", "main.roc"),
		Tar.symlink("pkg/far", "../${long}/${long}/target"),
		Tar.hard_link("pkg/hard.bin", "pkg/zeta.bin"),
		{ ..Tar.file("pkg/owned", "o\n".to_utf8()), uid: 1000, gid: 100, uname: "build", gname: "users" },
		{ ..Tar.file("pkg/big-ids", "i\n".to_utf8()), uid: 3000000, gid: 2097152, uname: Str.repeat("u", 40), gname: Str.repeat("g", 32) },
		{ ..Tar.file("pkg/late", "t\n".to_utf8()), mtime: 9000000000 },
		Tar.file("pkg/ünïcödé-ナ.txt", "u\n".to_utf8()),
	]
}

# What the reader gives for a member: the fields of `Tar.Entry` that the
# writer sets, and the data.
Seen : { path : Str, kind : Tar.Kind, size : U64, mode : U32, link : Str, data : List(U8) }

want : Tar.Member -> Seen
want = |m| {
	base = { path: m.path, kind: File, size: 0, mode: m.mode, link: "", data: [] }
	match m.kind {
		File(data) => { ..base, size: data.len(), data }
		Dir => { ..base, kind: Dir }
		Symlink(target) => { ..base, kind: Symlink, link: target }
		HardLink(target) => { ..base, kind: HardLink, link: target }
	}
}

# The members of an archive, read in chunks of `size` bytes, each collected.
read_back : List(U8), U64 -> Try(List(Seen), Tar.Error)
read_back = |bytes, size| {
	{ events, .. } = Mk.run(Mk.chunks(bytes, size), Mk.keep)?
	Ok(
		events.keep_oks(
			|e| match e {
				Content(x, data) => Ok({ path: x.path, kind: x.kind, size: x.size, mode: x.mode, link: x.link, data })
				_ => Err(No)
			},
		),
	)
}

create : List(Tar.Member) -> List(U8)
create = |members| Tar.create(members) ?? []

# The bytes of a field.
at : List(U8), U64, U64 -> List(U8)
at = |bytes, start, len| bytes.sublist({ start, len })

# The bytes before the first NUL.
text : List(U8) -> List(U8)
text = |bytes| match bytes.find_first_index(|b| b == 0) {
	Ok(k) => bytes.take_first(k)
	Err(NotFound) => bytes
}

err_of : List(Tar.Member) -> Try(Tar.WriteError, [NoError])
err_of = |members| match Tar.create(members) {
	Err(e) => Ok(e)
	Ok(_) => Err(NoError)
}

# API: the reader gives each member of the sample back, with its data
expect read_back(create(sample), 1048576) == Ok(sample.map(want))

# API: also in chunks of each of these sizes (a split in each header, pax
# record, data and padding)
expect {
	archive = create(sample)
	whole = Ok(sample.map(want))
	[1, 7, 100, 511, 512, 513, 1000, 4096].all(|size| read_back(archive, size) == whole)
}

# TOOLS: the bytes do not change (GNU tar and bsdtar agree on this archive)
expect create(sample) == written

# TOOLS: the reader lists the fixture as GNU tar -tv lists it
expect {
	lines = match Mk.run([written], Mk.skip) {
		Ok({ events, .. }) =>
			events.keep_oks(
				|e| match e {
					Entry(x) => Ok(Mk.tv_line(x))
					_ => Err(No)
				},
			)

		Err(_) => []
	}
	lines.append("end\n") |> Str.join_with("\n") == written_list
}

# API: the chunks of Tar.writer, add and end are the bytes of Tar.create
expect {
	var $w = Tar.writer({})
	var $out = []
	for m in sample {
		match $w.add(m) {
			Ok(added) => {
				$w = added.writer
				$out = $out.concat(added.chunk)
			}

			Err(_) => {
				$out = []
			}
		}
	}
	$out.concat($w.end()) == written
}

# API: no member gives two zero blocks only
expect Tar.create([]) == Ok(List.repeat(0, 1024))

# USTAR: the header of a file, byte for byte: name, mode, uid, gid, size and
# mtime as octal digits with leading zeros and a NUL, the checksum as 6
# digits, NUL and space, magic "ustar\0" and version "00", empty uname and
# gname, device numbers 0, no prefix. Then the data, padding, end.
expect {
	zeros = List.repeat(0, 512)
	h = zeros
		|> Mk.put(0, "a.txt".to_utf8())
		|> Mk.put(100, "0000644\u(0)".to_utf8())
		|> Mk.put(108, "0000000\u(0)".to_utf8())
		|> Mk.put(116, "0000000\u(0)".to_utf8())
		|> Mk.put(124, "00000000002\u(0)".to_utf8())
		|> Mk.put(136, "00000000000\u(0)".to_utf8())
		|> Mk.put(156, ['0'])
		|> Mk.put(257, "ustar\u(0)00".to_utf8())
		|> Mk.put(329, "0000000\u(0)0000000\u(0)".to_utf8())
	header = Mk.fix_sum(h, 0)
	create([Tar.file("a.txt", "hi".to_utf8())])
		== header.concat("hi".to_utf8()).concat(List.repeat(0, 510)).concat(List.repeat(0, 1024))
}

# USTAR: the fields that a member sets: mode, uid, gid, mtime, uname, gname
expect {
	h = create([{ ..Tar.file("f", []), mode: 0o4755, uid: 1000, gid: 2097151, mtime: 8589934591, uname: Str.repeat("u", 31), gname: "g" }])
	(at(h, 100, 8), at(h, 108, 8), at(h, 116, 8), at(h, 136, 12), text(at(h, 265, 32)), text(at(h, 297, 32)), h.get(156))
		== ("0004755\u(0)".to_utf8(), "0001750\u(0)".to_utf8(), "7777777\u(0)".to_utf8(), "77777777777\u(0)".to_utf8(), List.repeat('u', 31), ['g'], Ok('0'))
}

# USTAR: the type byte, size and link field of each kind
expect {
	kinds = [Tar.dir("d/"), Tar.symlink("s", "t"), Tar.file("f", []), Tar.hard_link("h", "f")]
	match Tar.create(kinds) {
		Ok(bytes) =>
			[0, 512, 1024, 1536].map(|o| (bytes.get(o + 156) ?? 0, at(bytes, o + 124, 12), text(at(bytes, o + 157, 100))))
				== [
					('5', "00000000000\u(0)".to_utf8(), []),
					('2', "00000000000\u(0)".to_utf8(), ['t']),
					('0', "00000000000\u(0)".to_utf8(), []),
					('1', "00000000000\u(0)".to_utf8(), ['f']),
				]

		Err(_) => Bool.False
	}
}

# USTAR: the data is padded to 512: 0, 1, 512 and 513 bytes
expect [0, 1, 512, 513].map(|n| create([Tar.file("f", List.repeat('x', n))]).len()) == [1536, 2048, 2048, 2560]

# API: the defaults of the member functions
expect Tar.file("f", [1]) == { path: "f", kind: File([1]), mode: 0o644, mtime: 0, uid: 0, gid: 0, uname: "", gname: "" }
expect Tar.dir("d/") == { path: "d/", kind: Dir, mode: 0o755, mtime: 0, uid: 0, gid: 0, uname: "", gname: "" }
expect Tar.symlink("s", "t") == { path: "s", kind: Symlink("t"), mode: 0o777, mtime: 0, uid: 0, gid: 0, uname: "", gname: "" }
expect Tar.hard_link("h", "f") == { path: "h", kind: HardLink("f"), mode: 0o644, mtime: 0, uid: 0, gid: 0, uname: "", gname: "" }

# API: a directory path is written as it is, with or without a `/` at the end
expect read_back(create([Tar.dir("a"), Tar.dir("b/")]), 512).map_ok(|xs| xs.map(|x| x.path)) == Ok(["a", "b/"])

# USTAR: a path of 100 bytes is in the name field, with no NUL and no prefix
expect {
	path = Str.repeat("n", 100)
	bytes = create([Tar.file(path, [])])
	(at(bytes, 0, 100), text(at(bytes, 345, 155)), bytes.len()) == (path.to_utf8(), [], 1536)
}

# USTAR: a longer path is split at the first `/` that leaves at most 100
# bytes after it (as GNU tar), with no pax header
expect {
	path = "a/${Str.repeat("b", 60)}/${Str.repeat("c", 60)}"
	bytes = create([Tar.file(path, [])])
	(text(at(bytes, 0, 100)), text(at(bytes, 345, 155)), bytes.get(156), bytes.len())
		== (Str.repeat("c", 60).to_utf8(), "a/${Str.repeat("b", 60)}".to_utf8(), Ok('0'), 1536)
}

# USTAR: a prefix of 155 bytes and a name of 100 bytes fit; the reader gives the path
expect {
	path = "${Str.repeat("p", 155)}/${Str.repeat("n", 100)}"
	bytes = create([Tar.file(path, [])])
	(at(bytes, 345, 155), bytes.len(), read_back(bytes, 512).map_ok(|xs| xs.map(|x| x.path)))
		== (Str.repeat("p", 155).to_utf8(), 1536, Ok([path]))
}

# PAX: with no `/` that fits (a prefix of 156 bytes, a part of 101 bytes, no
# `/`), a pax `x` header has the path. Its name is "././@PaxHeader", and the
# name field of the member has the first 100 bytes.
expect {
	paths = ["${Str.repeat("p", 156)}/n", "a/${Str.repeat("n", 101)}", Str.repeat("n", 101)]
	paths.all(
		|path| {
			bytes = create([Tar.file(path, [])])
			rec = Mk.record("path", path)
			(bytes.get(156), text(at(bytes, 0, 100)), at(bytes, 512, rec.len()), bytes.get(512 + 512 + 156), at(bytes, 1024, 100), bytes.len())
				== (Ok('x'), "././@PaxHeader".to_utf8(), rec, Ok('0'), path.to_utf8().take_first(100), 2560)
				and read_back(bytes, 100).map_ok(|xs| xs.map(|x| x.path)) == Ok([path])
		},
	)
}

# PAX: the name field is cut at the start of a UTF-8 character
expect {
	path = "${Str.repeat("a", 99)}é"
	bytes = create([Tar.file(path, [])])
	text(at(bytes, 1024, 100)) == List.repeat('a', 99)
}

# USTAR, PAX: a link target of 100 bytes is in the link field; of 101 bytes,
# in a pax `linkpath` record
expect {
	t100 = Str.repeat("t", 100)
	t101 = Str.repeat("t", 101)
	a = create([Tar.symlink("s", t100)])
	b = create([Tar.symlink("s", t101)])
	(a.len(), at(a, 157, 100), b.get(156), at(b, 512, Mk.record("linkpath", t101).len()))
		== (1536, t100.to_utf8(), Ok('x'), Mk.record("linkpath", t101))
		and read_back(b, 512).map_ok(|xs| xs.map(|x| x.link)) == Ok([t101])
}

# PAX: uid and gid over 2097151, mtime over 8589934591 and uname and gname
# over 31 bytes are pax records, in the order of their keys, and the ustar
# field is 0 (a number) or cut (a name)
expect {
	m = { ..Tar.file("f", []), uid: 2097152, gid: 3000000, mtime: 8589934592, uname: Str.repeat("u", 32), gname: Str.repeat("g", 40) }
	recs = Mk.record("gid", "3000000")
		.concat(Mk.record("gname", Str.repeat("g", 40)))
		.concat(Mk.record("mtime", "8589934592"))
		.concat(Mk.record("uid", "2097152"))
		.concat(Mk.record("uname", Str.repeat("u", 32)))
	bytes = create([m])
	h = bytes.drop_first(1024)
	(at(bytes, 512, recs.len()), at(h, 108, 8), at(h, 116, 8), at(h, 136, 12), text(at(h, 265, 32)), text(at(h, 297, 32)))
		== (
			recs,
			"0000000\u(0)".to_utf8(),
			"0000000\u(0)".to_utf8(),
			"00000000000\u(0)".to_utf8(),
			List.repeat('u', 31),
			List.repeat('g', 31),
		)
		and read_back(bytes, 512).is_ok()
}

# PAX: one pax header has all the records of a member, in the order of the keys
expect {
	long = Str.repeat("x", 101)
	m = { ..Tar.symlink("${long}", long), uid: 2097152 }
	recs = Mk.record("linkpath", long).concat(Mk.record("path", long)).concat(Mk.record("uid", "2097152"))
	bytes = create([m])
	(at(bytes, 512, recs.len()), bytes.get(1024 + 156), bytes.len()) == (recs, Ok('2'), 512 + 512 + 512 + 1024)
}

# API: the reader with the default limits refuses a path of more than 4096
# bytes; the writer has no limit
expect {
	ok = "${Str.repeat("d/", 2047)}ff"
	bad = "${ok}f"
	refused = match Mk.run([create([Tar.file(bad, [])])], Mk.skip) {
		Err(PathTooLong({ bytes: 4097, limit: 4096, .. })) => Bool.True
		_ => Bool.False
	}
	read_back(create([Tar.file(ok, [])]), 4096).is_ok() and refused
}

# API: the paths that the writer refuses
expect err_of([Tar.file("", [])]) == Ok(BadPath({ path: "", problem: Empty }))
expect err_of([Tar.file("a\u(0)b", [])]) == Ok(BadPath({ path: "a\u(0)b", problem: HasNul }))
expect err_of([Tar.file("/a", [])]) == Ok(BadPath({ path: "/a", problem: Absolute }))
expect err_of([Tar.dir("/")]) == Ok(BadPath({ path: "/", problem: Absolute }))
expect err_of([Tar.file("a//b", [])]) == Ok(BadPath({ path: "a//b", problem: EmptyPart }))
expect err_of([Tar.dir("a//")]) == Ok(BadPath({ path: "a//", problem: EmptyPart }))
expect err_of([Tar.file("a/", [])]) == Ok(BadPath({ path: "a/", problem: TrailingSlash }))
expect err_of([Tar.symlink("a/", "t")]) == Ok(BadPath({ path: "a/", problem: TrailingSlash }))
expect err_of([Tar.file("./a", [])]) == Ok(BadPath({ path: "./a", problem: DotPart }))
expect err_of([Tar.dir("a/./")]) == Ok(BadPath({ path: "a/./", problem: DotPart }))
expect err_of([Tar.file("a/../b", [])]) == Ok(BadPath({ path: "a/../b", problem: ParentDir }))
expect err_of([Tar.dir("../")]) == Ok(BadPath({ path: "../", problem: ParentDir }))
expect Tar.create([Tar.file("a.b/..c/.d", []), Tar.dir("e/"), Tar.dir("f")]).is_ok()

# API: the link targets that the writer refuses; a symbolic link target can
# be absolute or have `..`
expect err_of([Tar.symlink("s", "")]) == Ok(BadLink({ path: "s", problem: Empty }))
expect err_of([Tar.symlink("s", "a\u(0)")]) == Ok(BadLink({ path: "s", problem: HasNul }))
expect Tar.create([Tar.symlink("s", "/x/../y")]).is_ok()

# API: a hard link target is an earlier regular file or hard link
expect err_of([Tar.hard_link("h", "")]) == Ok(BadLink({ path: "h", problem: Empty }))
expect err_of([Tar.hard_link("h", "f")]) == Ok(BadLink({ path: "h", problem: NotEarlierFile }))
expect err_of([Tar.hard_link("h", "f"), Tar.file("f", [])]) == Ok(BadLink({ path: "h", problem: NotEarlierFile }))
expect err_of([Tar.dir("d/"), Tar.hard_link("h", "d")]) == Ok(BadLink({ path: "h", problem: NotEarlierFile }))
expect err_of([Tar.symlink("s", "t"), Tar.hard_link("h", "s")]) == Ok(BadLink({ path: "h", problem: NotEarlierFile }))
expect Tar.create([Tar.file("f", []), Tar.hard_link("h", "f"), Tar.hard_link("i", "h")]).is_ok()

# API: a NUL in uname or gname, and a mode over 0o7777
expect err_of([{ ..Tar.file("f", []), uname: "a\u(0)" }]) == Ok(BadOwnerName({ path: "f" }))
expect err_of([{ ..Tar.file("f", []), gname: "\u(0)" }]) == Ok(BadOwnerName({ path: "f" }))
expect err_of([{ ..Tar.file("f", []), mode: 0o10000 }]) == Ok(BadMode({ path: "f", mode: 0o10000 }))
expect err_of([{ ..Tar.dir("d/"), mode: 0o40755 }]) == Ok(BadMode({ path: "d/", mode: 0o40755 }))
expect Tar.create([{ ..Tar.file("f", []), mode: 0o7777 }]).is_ok()

# API: a repeated path; `a` and `a/` are the same path
expect err_of([Tar.file("a", []), Tar.file("a", [1])]) == Ok(DuplicatePath({ path: "a" }))
expect err_of([Tar.file("a", []), Tar.dir("a/")]) == Ok(DuplicatePath({ path: "a/" }))
expect err_of([Tar.dir("a"), Tar.dir("a/")]) == Ok(DuplicatePath({ path: "a/" }))
expect err_of([Tar.dir("a/"), Tar.symlink("a", "b")]) == Ok(DuplicatePath({ path: "a" }))
expect Tar.create([Tar.file("a", []), Tar.file("A", []), Tar.file("a/b", [])]).is_ok()

# API: Tar.create stops at the first member with an error
expect err_of([Tar.file("ok", []), Tar.file("", []), Tar.file("/b", [])]) == Ok(BadPath({ path: "", problem: Empty }))

# API: after an error of add, the writer is as before
expect {
	w = Tar.writer({})
	bad = w.add(Tar.file("a//b", []))
	good = w.add(Tar.file("a", []))
	(bad.is_err(), good.map_ok(|x| x.chunk) == Ok(create([Tar.file("a", [])]).drop_last(1024)))
		== (Bool.True, Bool.True)
}

# API: a text for each writer error
expect Tar.write_err_to_str(BadPath({ path: "", problem: Empty })) == "tar: the path \"\" is empty"
expect Tar.write_err_to_str(BadPath({ path: "a", problem: HasNul })) == "tar: the path \"a\" has a NUL byte"
expect Tar.write_err_to_str(BadPath({ path: "/a", problem: Absolute })) == "tar: the path \"/a\" starts with /"
expect Tar.write_err_to_str(BadPath({ path: "a//b", problem: EmptyPart })) == "tar: the path \"a//b\" has an empty part (two / together)"
expect Tar.write_err_to_str(BadPath({ path: "./a", problem: DotPart })) == "tar: the path \"./a\" has a part that is ."
expect Tar.write_err_to_str(BadPath({ path: "../a", problem: ParentDir })) == "tar: the path \"../a\" has a part that is .."
expect Tar.write_err_to_str(BadPath({ path: "a/", problem: TrailingSlash })) == "tar: the path \"a/\" ends with /, but the member is not a directory"
expect Tar.write_err_to_str(BadLink({ path: "s", problem: Empty })) == "tar: the link target of \"s\" is empty"
expect Tar.write_err_to_str(BadLink({ path: "s", problem: HasNul })) == "tar: the link target of \"s\" has a NUL byte"
expect Tar.write_err_to_str(BadLink({ path: "h", problem: NotEarlierFile })) == "tar: the link target of \"h\" is not the path of an earlier regular file or hard link of the archive"
expect Tar.write_err_to_str(BadOwnerName({ path: "f" })) == "tar: the uname or gname of \"f\" has a NUL byte"
expect Tar.write_err_to_str(BadMode({ path: "f", mode: 0o40755 })) == "tar: the mode 0o40755 of \"f\" is more than 0o7777 (the type bits are not part of the mode)"
expect Tar.write_err_to_str(DuplicatePath({ path: "a" })) == "tar: the path \"a\" is already in the archive"
