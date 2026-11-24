app [target] {
	fuzz: platform "https://github.com/lukewilliamboswell/roc-fuzz/releases/download/0.4.3/41NK5FShyGC9Z8HNpUdUeXMWwLmLNfFxsfmLvdPL4Fxb.tar.zst",
	pkg: "../package/main.roc",
}

import fuzz.Fuzz
import pkg.Tar

# L1 (REG2, REG3, API): two writers make an archive of the same random
# members, and the reader, in chunks of a random size, gives each member back,
# in order.
# 1. The oracle: a writer in this file, independent of the package. A path
#    of at most 100 bytes goes in the name field; a longer path goes in the
#    prefix and name fields when it can, else in a pax `path` record or a GNU
#    `L` header (the `form` byte picks). Regular files only.
# 2. `Tar.create` of the package, with each member kind (the `kind` byte
#    picks), and a random mode, uid, gid, mtime, uname, gname and link target,
#    so that each pax record is used. The chunks of `Tar.writer` are the bytes
#    of `Tar.create`.

Member : { path : Str, data : List(U8), form : U8, kind : U8, ids : U64, name : List(U8), depth : U8 }

Input := { members : List({ name : List(U8), data : List(U8), form : U8, depth : U8, kind : U8, ids : U64 }), chunk : U64 }.{
	generator_for : Fuzz.FuzzEncoding -> Fuzz.Generator(Input)
	generator_for = |_| {
		members: Fuzz.list(
			{
				name: Fuzz.bytes,
				data: Fuzz.bytes,
				form: Fuzz.u8,
				depth: Fuzz.u8_in(0, 40),
				kind: Fuzz.u8,
				ids: Fuzz.u64_in(0, 20000000000),
			}.Fuzz,
			20,
		),
		chunk: Fuzz.u64_in(1, 2000),
	}.Fuzz
}

# A path from random bytes: letters only, `depth` parts of the name, so the
# length is from 1 to about 300 bytes.
members_of : Input -> List(Member)
members_of = |input| {
	var $out = []
	var $k = 0.U64
	for m in input.members.take_first(20) {
		letters = m.name.map(|b| 'a' + b % 26)
		part = if (letters.is_empty()) ['f'] else letters.take_first(12)
		var $p = "m${$k.to_str()}".to_utf8()
		for _d in 0.U8..<m.depth {
			$p = $p.concat(['/']).concat(part)
		}
		$out = $out.append({ path: Str.from_utf8($p) ?? "bad", data: m.data, form: m.form, kind: m.kind, ids: m.ids, name: letters, depth: m.depth })
		$k = $k + 1
	}
	$out
}

write : List(Member) -> List(U8)
write = |members| members.fold([], |acc, m| acc.concat(member(m))).concat(List.repeat(0, 1024))

member : Member -> List(U8)
member = |m| {
	p = m.path.to_utf8()
	n = p.len()
	size = m.data.len()
	data = m.data.concat(List.repeat(0, pad(size)))
	if n <= 100 {
		header(p, [], size, '0').concat(data)
	} else {
		# The prefix: the part before the last '/' that leaves at most 100 bytes.
		split = split_at(p)
		match split {
			Ok(k) if m.form % 3 == 0 => header(p.drop_first(k + 1), p.take_first(k), size, '0').concat(data)
			_ =>
				if m.form % 3 == 1 {
					rec = record("path", p)
					header("pax".to_utf8(), [], rec.len(), 'x').concat(rec).concat(List.repeat(0, pad(rec.len()))).concat(header("short".to_utf8(), [], size, '0')).concat(data)
				} else {
					long = p.append(0)
					header("././@LongLink".to_utf8(), [], long.len(), 'L').concat(long).concat(List.repeat(0, pad(long.len()))).concat(header("short".to_utf8(), [], size, '0')).concat(data)
				}
		}
	}
}

# The index of a '/' with at most 155 bytes before it and at most 100 after it.
split_at : List(U8) -> Try(U64, [NoSplit])
split_at = |p| {
	var $found = Err(NoSplit)
	var $k = 0.U64
	for b in p {
		if b == '/' and $k <= 155 and p.len() - $k - 1 <= 100 and $k > 0 {
			$found = Ok($k)
		}
		$k = $k + 1
	}
	$found
}

pad : U64 -> U64
pad = |n| (512 - n % 512) % 512

record : Str, List(U8) -> List(U8)
record = |key, value| {
	body = [' '].concat(key.to_utf8()).concat(['=']).concat(value).concat(['\n'])
	var $n = body.len() + 1
	while $n != body.len() + $n.to_str().count_utf8_bytes() {
		$n = $n + 1
	}
	$n.to_str().to_utf8().concat(body)
}

header : List(U8), List(U8), U64, U8 -> List(U8)
header = |name, prefix, size, type| {
	fields = name.concat(List.repeat(0, 100 - name.len()))
		.concat(octal(0o644, 8))
		.concat(octal(0, 8))
		.concat(octal(0, 8))
		.concat(octal(size, 12))
		.concat(octal(0, 12))
		.concat(List.repeat(' ', 8))
		.append(type)
		.concat(List.repeat(0, 100))
		.concat(['u', 's', 't', 'a', 'r', 0, '0', '0'])
		.concat(List.repeat(0, 80))
		.concat(prefix)
		.concat(List.repeat(0, 155 - prefix.len() + 12))
	sum = fields.fold(0.U64, |acc, b| acc + b.to_u64())
	fields.take_first(148).concat(octal(sum, 7)).append(' ').concat(fields.drop_first(156))
}

octal : U64, U64 -> List(U8)
octal = |value, width| {
	var $digits = []
	var $v = value
	for _k in 0.U64..<(width - 1) {
		$digits = $digits.prepend('0' + ($v % 8).to_u8_wrap())
		$v = $v // 8
	}
	$digits.append(0)
}

read : List(U8), U64 -> Try(List((Str, U64, List(U8))), Tar.Error)
read = |bytes, size| {
	var $t = Tar.new(Tar.Limits.{})
	var $out = []
	for c in bytes.chunks_of(size) {
		(t2, events) = $t.push(c, |_| Collect(1048576))?
		$t = t2
		for e in events {
			match e {
				Content(entry, data) => {
					$out = $out.append((entry.path, entry.size, data))
				}

				Entry(_) => {}
			}
		}
	}
	_ = $t.finish()?
	Ok($out)
}

# The members for `Tar.create`. A hard link goes to the last regular file
# before it (a file when there is none). A symbolic link target has `depth`
# times 13 letters (more than 100 bytes from depth 8). `ids` gives the mode
# and the numbers; a uid, gid or mtime that does not fit in its field is a pax
# record. A uname or gname has `depth` letters (more than 31 from depth 32).
tar_members : List(Member) -> List(Tar.Member)
tar_members = |members| {
	var $out = []
	var $last_file = Err(NoFile)
	for m in members {
		letters = if (m.name.is_empty()) ['t'] else m.name
		n = m.depth.to_u64() * 13 + 1
		var $t = []
		while $t.len() < n {
			$t = $t.concat(letters)
		}
		target = Str.from_utf8($t.take_first(n)) ?? "t"
		owner = Str.from_utf8(List.repeat(letters.first() ?? 'u', m.depth.to_u64())) ?? ""
		kind = match (m.kind % 4, $last_file) {
			(1, _) => Dir
			(2, _) => Symlink(target)
			(3, Ok(f)) => HardLink(f)
			_ => File(m.data)
		}
		path = if (kind == Dir and m.form % 2 == 0) "${m.path}/" else m.path
		if kind == File(m.data) {
			$last_file = Ok(m.path)
		}
		$out = $out.append({
			path,
			kind,
			mode: (m.ids % 4096).to_u32_wrap(),
			mtime: m.ids,
			uid: m.ids // 4096,
			gid: m.ids // 3,
			uname: owner,
			gname: Str.from_utf8(List.repeat(letters.last() ?? 'g', m.depth.to_u64())) ?? "",
		})
	}
	$out
}

# What the reader gives back for a member written by `Tar.create`.
want_tar : Tar.Member -> (Str, Tar.Kind, U64, U32, Str, List(U8))
want_tar = |m| match m.kind {
	File(data) => (m.path, File, data.len(), m.mode, "", data)
	Dir => (m.path, Dir, 0, m.mode, "", [])
	Symlink(t) => (m.path, Symlink, 0, m.mode, t, [])
	HardLink(t) => (m.path, HardLink, 0, m.mode, t, [])
}

read_all : List(U8), U64 -> Try(List((Str, Tar.Kind, U64, U32, Str, List(U8))), Tar.Error)
read_all = |bytes, size| {
	var $t = Tar.new(Tar.Limits.{})
	var $out = []
	for c in bytes.chunks_of(size) {
		(t2, events) = $t.push(c, |_| Collect(1048576))?
		$t = t2
		for e in events {
			match e {
				Content(x, data) => {
					$out = $out.append((x.path, x.kind, x.size, x.mode, x.link, data))
				}

				Entry(_) => {}
			}
		}
	}
	_ = $t.finish()?
	Ok($out)
}

# The chunks of `Tar.writer`, then its end.
streamed : List(Tar.Member) -> Try(List(U8), Tar.WriteError)
streamed = |members| {
	var $w = Tar.writer({})
	var $out = []
	for m in members {
		added = $w.add(m)?
		$w = added.writer
		$out = $out.concat(added.chunk)
	}
	Ok($out.concat($w.end()))
}

test : Input -> Fuzz.Outcome
test = |input| {
	members = members_of(input)
	want = members.map(|m| (m.path, m.data.len(), m.data))
	size = input.chunk
	if read(write(members), size) != Ok(want) {
		crash "the members read back are not the members written (oracle writer)"
	}
	written = tar_members(members)
	archive = match Tar.create(written) {
		Ok(bytes) => bytes
		Err(e) => crash Tar.write_err_to_str(e)
	}
	if streamed(written) != Ok(archive) {
		crash "the chunks of Tar.writer are not the bytes of Tar.create"
	}
	if (read_all(archive, size) == Ok(written.map(want_tar))) Fuzz.keep else crash "the members read back are not the members written (Tar.create)"
}

target = Fuzz.target_with({
	name: "roundtrip",
	generator: Input.generator_for(Default),
	test,
	show: |input| Str.inspect(tar_members(members_of(input))),
})
