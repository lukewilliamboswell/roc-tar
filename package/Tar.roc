## A streaming reader for ustar archives (POSIX.1-1988 ustar, plus the pax
## `x` and `g` headers and the GNU `L` and `K` headers), and a writer of
## ustar archives with pax `x` headers.
##
## A `Tar` is the state of one read. Give it the archive in chunks of any size
## with `push`, then call `finish` once. Each member gives one `Entry` event.
## The function that you give to `push` says, for each member, if the reader
## skips its data or collects it (with a byte limit). A collected member gives
## one `Content` event when its data is complete.
##
## The reader keeps at most one partial header (less than 512 bytes), the data
## of the member or meta header that it collects now, and the pax values that
## apply to the next member. It never keeps the data of a member that it skips.
##
## `Tar.create` writes an archive of a list of members, and `Tar.writer` one
## member at a time. The bytes are a function of the members only.
Tar :: {
	limits : Tar.Limits,
	# The count of archive bytes that the reader consumed.
	offset : U64,
	phase : Phase,
	# The bytes of a header block that is not complete (less than 512).
	pending : List(U8),
	# The data of the member or meta header that the reader collects now.
	buf : List(U8),
	# The offset of the last header block.
	at : U64,
	members : U64,
	path_bytes : U64,
	total_size : U64,
	collected : U64,
	local : Meta,
	global : Meta,
}.{

	## The limits of one read. Each field has a default: `Tar.Limits.{}` gives
	## all of them. A limit that the archive goes over gives an error.
	##
	## | Field | Default | Error |
	## | --- | --- | --- |
	## | `max_members` | 10000 | `TooManyMembers` |
	## | `max_path_bytes` | 4096 | `PathTooLong` (also a link target) |
	## | `max_total_path_bytes` | 1048576 | `TooManyPathBytes` (the sum of the paths and link targets of all members) |
	## | `max_total_size` | 268435456 | `TotalSizeTooLarge` (the sum of the member sizes) |
	## | `max_collect_bytes` | 16777216 | `CollectTooLarge` (the sum of the sizes of the collected members) |
	## | `max_meta_bytes` | 65536 | `MetaTooLarge` (the data of the pax or GNU long name header that the reader reads now, plus the pax and GNU values that it keeps for the next members) |
	Limits := {
		max_members : U64 ?? 10000,
		max_path_bytes : U64 ?? 4096,
		max_total_path_bytes : U64 ?? 1048576,
		max_total_size : U64 ?? 268435456,
		max_collect_bytes : U64 ?? 16777216,
		max_meta_bytes : U64 ?? 65536,
	}

	## The type of a member. `Other` has the type byte of the header, for
	## example `'3'` (character device), `'4'` (block device), `'6'` (FIFO)
	## or a vendor type.
	Kind : [File, Dir, Symlink, HardLink, Other(U8)]

	## One member. `path` and `link` are as in the archive, with no change:
	## the pax `path` or the GNU long name if there is one, else the ustar
	## prefix, `/` and name. `link` is the link target (empty for most
	## members). `mode` is the permission bits of the header. `offset` is the
	## archive offset of the ustar header of the member. `type_byte` is the
	## type byte (offset 156) of that header, as it is: not the byte of a pax
	## `x` or GNU `L`/`K` header before it. `kind` gives `File` for `'0'`, NUL
	## and `'7'`; `type_byte` tells them apart.
	Entry : { path : Str, kind : Tar.Kind, size : U64, mode : U32, link : Str, offset : U64, type_byte : U8 }

	## What the reader does with the data of one member. `Collect(limit)`: a
	## member of more than `limit` bytes is the error `ContentTooLarge`, never
	## a part of the data.
	Action : [Skip, Collect(U64)]

	## `Entry` comes when the header of a member is read. `Content` comes
	## after all data of a collected member is read.
	Event : [Entry(Tar.Entry), Content(Tar.Entry, List(U8))]

	## How the archive ended. `TwoZeroBlocks` is the end that POSIX
	## specifies. `NoZeroBlock`: the input ended after a complete member, with
	## no end marker.
	End : [TwoZeroBlocks, OneZeroBlock, NoZeroBlock]

	## The result of `finish`. `bytes` is the archive length.
	Summary : { end : Tar.End, members : U64, bytes : U64, total_size : U64 }

	## The errors. Each `offset` is an archive offset: of the header block for
	## a header error, of the end of the input for `Truncated`.
	Error : [
		BadChecksum({ offset : U64 }),
		BadNumber({ offset : U64, field : Str }),
		NotUstar({ offset : U64 }),
		BadPax({ offset : U64 }),
		BadPath({ offset : U64, problem : [Empty, NotUtf8, HasNul] }),
		PathTooLong({ offset : U64, bytes : U64, limit : U64 }),
		UnexpectedData({ offset : U64, size : U64 }),
		MetaWithoutMember({ offset : U64 }),
		MetaTooLarge({ offset : U64, size : U64, limit : U64 }),
		TooManyMembers({ offset : U64, limit : U64 }),
		TooManyPathBytes({ offset : U64, limit : U64 }),
		TotalSizeTooLarge({ offset : U64, limit : U64 }),
		ContentTooLarge({ offset : U64, size : U64, limit : U64 }),
		CollectTooLarge({ offset : U64, limit : U64 }),
		LoneZeroBlock({ offset : U64 }),
		DataAfterEnd({ offset : U64 }),
		Truncated({ offset : U64, inside : [Header, Data, Padding] }),
	]

	## A reader with these limits, at the start of an archive.
	new : Tar.Limits -> Tar
	new = |limits| {
		limits,
		offset: 0,
		phase: Header,
		pending: [],
		buf: [],
		at: 0,
		members: 0,
		path_bytes: 0,
		total_size: 0,
		collected: 0,
		local: no_meta,
		global: no_meta,
	}

	## Read the next chunk. A chunk can have any size and can stop in a header
	## or in member data. `choose` is called once for each member, after its
	## `Entry` is complete and before its data. The events of the chunk are
	## in archive order.
	##
	## After an error the reader is gone: do not push to it again.
	push : Tar, List(U8), (Tar.Entry -> Tar.Action) -> Try((Tar, List(Tar.Event)), Tar.Error)
	push = |tar, chunk, choose| {
		n = chunk.len()
		var $t = tar
		var $events = []
		var $i = 0
		while $i < n {
			match $t.phase {
				Ended => {
					match chunk.drop_first($i).find_first_index(|b| b != 0) {
						Ok(k) => return Err(DataAfterEnd({ offset: $t.offset + k }))
						Err(NotFound) => {
							$t = { ..$t, offset: $t.offset + (n - $i) }
							$i = n
						}
					}
				}
				Body({ left, pad, sink }) => {
					take = U64.min(left, n - $i)
					piece_buf = match sink {
						Skip => $t.buf
						_ => add_piece($t.buf, chunk.sublist({ start: $i, len: take }))
					}
					$i = $i + take
					$t = { ..$t, offset: $t.offset + take, buf: piece_buf }
					if take == left {
						match end_body($t, sink) {
							Ok((t2, evs)) => {
								$events = $events.concat(evs)
								$t = { ..t2, phase: if (pad == 0) Header else Pad(pad) }
							}
							Err(e) => return Err(e)
						}
					} else {
						$t = { ..$t, phase: Body({ left: left - take, pad, sink }) }
					}
				}
				Pad(left) => {
					take = U64.min(left, n - $i)
					$i = $i + take
					$t = { ..$t, offset: $t.offset + take, phase: if (take == left) Header else Pad(left - take) }
				}
				_ => {
					# Header or OneZero: the reader needs a 512-byte block.
					have = $t.pending.len()
					if have == 0 and n - $i >= block_size {
						block = chunk.sublist({ start: $i, len: block_size })
						$i = $i + block_size
						match on_block({ ..$t, at: $t.offset, offset: $t.offset + block_size }, block, choose) {
							Ok((t2, evs)) => {
								$events = $events.concat(evs)
								$t = t2
							}
							Err(e) => return Err(e)
						}
					} else {
						take = U64.min(block_size - have, n - $i)
						start = if (have == 0) List.with_capacity(block_size) else $t.pending
						pending = add_piece(start, chunk.sublist({ start: $i, len: take }))
						$i = $i + take
						if pending.len() == block_size {
							match on_block({ ..$t, pending: [], at: $t.offset - have, offset: $t.offset + take }, pending, choose) {
								Ok((t2, evs)) => {
									$events = $events.concat(evs)
									$t = t2
								}
								Err(e) => return Err(e)
							}
						} else {
							$t = { ..$t, pending, offset: $t.offset + take }
						}
					}
				}
			}
		}
		Ok(($t, $events))
	}

	## End the read: the input has no more bytes. An input that stops in a
	## header, in member data or in the padding after it is `Truncated`. A
	## pax or GNU long name header with no member after it is
	## `MetaWithoutMember`.
	finish : Tar -> Try(Tar.Summary, Tar.Error)
	finish = |tar| {
		summary = |end| Ok({ end, members: tar.members, bytes: tar.offset, total_size: tar.total_size })
		match tar.phase {
			Ended => summary(TwoZeroBlocks)
			OneZero => summary(OneZeroBlock)
			Body(_) => Err(Truncated({ offset: tar.offset, inside: Data }))
			Pad(_) => Err(Truncated({ offset: tar.offset, inside: Padding }))
			Header =>
				if tar.pending.len() > 0 {
					Err(Truncated({ offset: tar.offset, inside: Header }))
				} else if has_meta(tar.local) {
					Err(MetaWithoutMember({ offset: tar.at }))
				} else {
					summary(NoZeroBlock)
				}
		}
	}

	## `Ok({})` when the path is safe to make under a root directory: it is not
	## empty, it does not start with `/`, and no part between two `/` is `..`.
	## Other checks (duplicates, `.` parts, reserved names) are for the caller.
	check_path : Str -> Try({}, [EmptyPath, Absolute, ParentDir])
	check_path = |path| {
		if path == "" {
			Err(EmptyPath)
		} else if path.starts_with("/") {
			Err(Absolute)
		} else if path.split_on("/").any(|part| part == "..") {
			Err(ParentDir)
		} else {
			Ok({})
		}
	}

	## `Ok({})` when `roc unbundle` accepts the path on every OS: the rules of
	## `pathInvalidReason` in `src/unbundle/unbundle.zig` of roc-lang/roc
	## (commit 76258c1267204e31e58d8edcdd3ede6163ef60db), in the same order,
	## with the backslash rule of Linux and macOS. `roc bundle` applies the
	## same function to each path that it writes.
	##
	## | Order | Rule | Error |
	## | --- | --- | --- |
	## | 1 | The path is empty | `EmptyPath` |
	## | 2 | More than 255 bytes (`TAR_PATH_MAX_LENGTH`, `src/unbundle/format.zig`) | `TooLong` |
	## | 3 | The first byte is `/` or `\` | `Absolute` |
	## | 4 | The second byte is `:` (`C:x`) | `DriveLetter` |
	## | 5 | A part is `..` (parts end at `/` or `\`; empty parts are skipped) | `ParentDir` |
	## | 6 | A part is `.` | `DotPart` |
	## | 7 | The part before the first `.` of a part is a Windows device name (`CON`, `PRN`, `AUX`, `NUL`, `COM1` to `COM9`, `LPT1` to `LPT9`), in any case | `ReservedName` |
	## | 8 | A part ends with a space | `EndsWithSpace` |
	## | 9 | A part ends with `.` | `EndsWithPeriod` |
	## | 10 | A byte is NUL, `<`, `>`, `:`, `"`, `\|`, `?` or `*` (the first such byte) | `ReservedChar(byte)` |
	## | 11 | A byte is `\` (roc refuses it on each OS but Windows) | `Backslash` |
	check_portable_path : Str -> Try({}, [EmptyPath, TooLong, Absolute, DriveLetter, ParentDir, DotPart, ReservedName, EndsWithSpace, EndsWithPeriod, ReservedChar(U8), Backslash])
	check_portable_path = |path| {
		bytes = path.to_utf8()
		if bytes.is_empty() {
			return Err(EmptyPath)
		}
		if bytes.len() > 255 {
			return Err(TooLong)
		}
		first = bytes.get(0) ?? 0
		if first == '/' or first == '\\' {
			return Err(Absolute)
		}
		if bytes.get(1) == Ok(':') {
			return Err(DriveLetter)
		}
		for part in parts(bytes) {
			if part == ['.', '.'] {
				return Err(ParentDir)
			}
			if part == ['.'] {
				return Err(DotPart)
			}
			base = c_until(part, '.')
			if reserved_names.any(|name| ascii_upper(base) == name) {
				return Err(ReservedName)
			}
			last = part.last() ?? 0
			if last == ' ' {
				return Err(EndsWithSpace)
			}
			if last == '.' {
				return Err(EndsWithPeriod)
			}
		}
		for b in bytes {
			if b == 0 or b == '<' or b == '>' or b == ':' or b == '"' or b == '|' or b == '?' or b == '*' {
				return Err(ReservedChar(b))
			}
			if b == '\\' {
				return Err(Backslash)
			}
		}
		Ok({})
	}

	## `Ok({})` when `roc unbundle` accepts the member on every OS. roc-lang/roc
	## commit 76258c1267204e31e58d8edcdd3ede6163ef60db, `src/unbundle/unbundle.zig`
	## (`unbundleStream`), reads with `std.tar.Iterator` of Zig 0.17.0
	## (`lib/std/tar.zig`, `Iterator.next`), with no diagnostics. It is the rule
	## of `roc unbundle`, not a strict "file or directory only" rule: a symbolic
	## link with a safe target is `Ok`. To refuse all links, check `type_byte`.
	## The checks, in
	## this order:
	##
	## | Order | Rule | Error |
	## | --- | --- | --- |
	## | 1 | `type_byte` is not `'0'`, NUL, `'5'` or `'2'`. Zig gives `error.TarUnsupportedHeader` for each other member type (`'1'`, `'3'`, `'4'`, `'6'`, `'7'`, `'S'`, vendor types). | `UnsupportedType(byte)` |
	## | 2 | `check_portable_path(path)` fails (`pathHasUnbundleErr`, for each member) | `Path(error)` |
	## | 3 | For a symbolic link (`'2'`): the target starts with `/` or `\`, its second byte is `:`, or a part between `/` or `\` is `..` or `.` (`linkTargetUnbundleErr`, the rules of each OS together) | `Link(error)` |
	##
	## roc unbundle does not make a symbolic link that it accepts. `roc bundle`
	## writes only type `'0'`.
	roc_accepts : Tar.Entry -> Try({}, [UnsupportedType(U8), Path([EmptyPath, TooLong, Absolute, DriveLetter, ParentDir, DotPart, ReservedName, EndsWithSpace, EndsWithPeriod, ReservedChar(U8), Backslash]), Link([Absolute, DriveLetter, ParentDir, DotPart])])
	roc_accepts = |entry| {
		type = entry.type_byte
		if !(type == '0' or type == 0 or type == '5' or type == '2') {
			return Err(UnsupportedType(type))
		}
		check_portable_path(entry.path) ? |e| Path(e)
		if type == '2' {
			check_link(entry.link) ? |e| Link(e)
		}
		Ok({})
	}

	## The bytes of state that the reader keeps now: the part of a header
	## that two chunks split (at most 511), the pax and GNU values for the next
	## members, and the data buffer of the member or meta header that it reads
	## now (its full size). Between two pushes, when no member is collected,
	## this is at most 511 + `max_meta_bytes`.
	held_bytes : Tar -> U64
	held_bytes = |t| {
		body_bytes = match t.phase {
			Body({ left, sink, .. }) =>
				match sink {
					Skip => 0
					_ => t.buf.len() + left
				}

			_ => 0
		}
		t.pending.len() + meta_bytes(t.local) + meta_bytes(t.global) + body_bytes
	}

	## A text for each error, in English.
	err_to_str : Tar.Error -> Str
	err_to_str = |err| match err {
		BadChecksum({ offset }) => "tar: the header at offset ${offset.to_str()} has a bad checksum"
		BadNumber({ offset, field }) => "tar: the ${field} field of the header at offset ${offset.to_str()} is not an octal number (base-256 numbers are not supported)"
		NotUstar({ offset }) => "tar: the header at offset ${offset.to_str()} is not a ustar or GNU header (no ustar magic)"
		BadPax({ offset }) => "tar: the pax header at offset ${offset.to_str()} has a bad record"
		BadPath({ offset, problem }) => {
			why = match problem {
				Empty => "is empty"
				NotUtf8 => "is not UTF-8"
				HasNul => "has a NUL byte"
			}
			"tar: the path or link of the member at offset ${offset.to_str()} ${why}"
		}

		PathTooLong({ offset, bytes, limit }) => "tar: the path or link of the member at offset ${offset.to_str()} has ${bytes.to_str()} bytes, more than the limit ${limit.to_str()}"
		UnexpectedData({ offset, size }) => "tar: the link, directory or device at offset ${offset.to_str()} has a size of ${size.to_str()} bytes, but this type has no data"
		MetaWithoutMember({ offset }) => "tar: the pax or GNU long name header at offset ${offset.to_str()} has no member after it"
		MetaTooLarge({ offset, size, limit }) => "tar: the pax or GNU long name header at offset ${offset.to_str()} and the pax and GNU values before it have ${size.to_str()} bytes, more than the limit ${limit.to_str()}"
		TooManyMembers({ offset, limit }) => "tar: the member at offset ${offset.to_str()} is more than the limit of ${limit.to_str()} members"
		TooManyPathBytes({ offset, limit }) => "tar: at offset ${offset.to_str()} the paths and links are more than the limit of ${limit.to_str()} bytes"
		TotalSizeTooLarge({ offset, limit }) => "tar: at offset ${offset.to_str()} the sum of the member sizes is more than the limit of ${limit.to_str()} bytes"
		ContentTooLarge({ offset, size, limit }) => "tar: the member at offset ${offset.to_str()} has ${size.to_str()} bytes, more than the collect limit ${limit.to_str()}"
		CollectTooLarge({ offset, limit }) => "tar: at offset ${offset.to_str()} the collected members are more than the limit of ${limit.to_str()} bytes"
		LoneZeroBlock({ offset }) => "tar: the zero block before offset ${offset.to_str()} is not followed by a second zero block"
		DataAfterEnd({ offset }) => "tar: a byte that is not zero at offset ${offset.to_str()}, after the end of the archive"
		Truncated({ offset, inside }) => {
			where_ = match inside {
				Header => "a header"
				Data => "the data of a member"
				Padding => "the padding after a member"
			}
			"tar: the input ends at offset ${offset.to_str()}, in ${where_}"
		}
	}

	## One member to write. `Tar.file`, `Tar.dir`, `Tar.symlink` and
	## `Tar.hard_link` give a member with the fixed defaults; change a field
	## with `{ ..Tar.file(path, data), mtime: 315532800 }`. The writer reads
	## no clock, no user and no file: the archive is a function of the members.
	Member : {
		path : Str,
		kind : [File(List(U8)), Dir, Symlink(Str), HardLink(Str)],
		mode : U32,
		mtime : U64,
		uid : U64,
		gid : U64,
		uname : Str,
		gname : Str,
	}

	## The errors of the writer. Each has the path of the member.
	WriteError : [
		BadPath({ path : Str, problem : [Empty, HasNul, Absolute, EmptyPart, DotPart, ParentDir, TrailingSlash] }),
		BadLink({ path : Str, problem : [Empty, HasNul, NotEarlierFile] }),
		BadOwnerName({ path : Str }),
		BadMode({ path : Str, mode : U32 }),
		DuplicatePath({ path : Str }),
	]

	## An archive that is written one member at a time: see `Tar.writer`. It
	## keeps the paths that it wrote, never the data of a member.
	Writer :: { paths : Set(Str), files : Set(Str) }.{

		## Write one member: a pax `x` header when a field does not fit in the
		## ustar header, then the ustar header, the data and the padding to 512
		## bytes, as one chunk.
		add : Tar.Writer, Tar.Member -> Try({ writer : Tar.Writer, chunk : List(U8) }, Tar.WriteError)
		add = |w, m| {
			key = check_member(m, w.paths, w.files)?
			files = match m.kind {
				File(_) | HardLink(_) => w.files.insert(key)
				_ => w.files
			}
			Ok({ writer: { paths: w.paths.insert(key), files }, chunk: member_bytes(m) })
		}

		## The last chunk of the archive: two zero blocks.
		end : Tar.Writer -> List(U8)
		end = |_w| List.repeat(0, 2 * block_size)
	}

	## A regular file with this data. Mode 0o644, mtime 0, uid and gid 0,
	## uname and gname empty.
	file : Str, List(U8) -> Tar.Member
	file = |path, data| member_of(path, File(data), 0o644)

	## A directory. Mode 0o755. The writer writes the path as it is: give
	## `"dir/"` for the form of GNU tar and bsdtar.
	dir : Str -> Tar.Member
	dir = |path| member_of(path, Dir, 0o755)

	## A symbolic link to `target`. Mode 0o777. The target is not checked
	## (it can be absolute or have `..`), only that it is not empty and has
	## no NUL byte.
	symlink : Str, Str -> Tar.Member
	symlink = |path, target| member_of(path, Symlink(target), 0o777)

	## A hard link to `target`, the path of an earlier regular file or hard
	## link of the same archive. Mode 0o644.
	hard_link : Str, Str -> Tar.Member
	hard_link = |path, target| member_of(path, HardLink(target), 0o644)

	## Start an archive that is written one member at a time. Each
	## `Tar.Writer.add` gives the next chunk, and `Tar.Writer.end` the last
	## one. The chunks, in order, are the bytes of `Tar.create` for the same
	## members.
	writer : {} -> Tar.Writer
	writer = |{}| { paths: Set.empty(), files: Set.empty() }

	## The archive of these members, in this order, then two zero blocks.
	create : List(Tar.Member) -> Try(List(U8), Tar.WriteError)
	create = |members| {
		var $w = Tar.writer({})
		var $out = []
		for m in members {
			added = $w.add(m)?
			$w = added.writer
			$out = $out.concat(added.chunk)
		}
		Ok($out.concat($w.end()))
	}

	## A text for each writer error, in English.
	write_err_to_str : Tar.WriteError -> Str
	write_err_to_str = |err| match err {
		BadPath({ path, problem }) => {
			why = match problem {
				Empty => "is empty"
				HasNul => "has a NUL byte"
				Absolute => "starts with /"
				EmptyPart => "has an empty part (two / together)"
				DotPart => "has a part that is ."
				ParentDir => "has a part that is .."
				TrailingSlash => "ends with /, but the member is not a directory"
			}
			"tar: the path \"${path}\" ${why}"
		}

		BadLink({ path, problem }) => {
			why = match problem {
				Empty => "is empty"
				HasNul => "has a NUL byte"
				NotEarlierFile => "is not the path of an earlier regular file or hard link of the archive"
			}
			"tar: the link target of \"${path}\" ${why}"
		}

		BadOwnerName({ path }) => "tar: the uname or gname of \"${path}\" has a NUL byte"
		BadMode({ path, mode }) => "tar: the mode 0o${octal_text(mode.to_u64())} of \"${path}\" is more than 0o7777 (the type bits are not part of the mode)"
		DuplicatePath({ path }) => "tar: the path \"${path}\" is already in the archive"
	}
}

# The phases of the reader. `Body`: `left` data bytes, then `pad` padding
# bytes. `OneZero`: one zero block was read. `Ended`: two zero blocks.
Phase : [Header, Body({ left : U64, pad : U64, sink : Sink }), Pad(U64), OneZero, Ended]

# Where the data of the current body goes.
Sink : [Skip, Keep(Tar.Entry), PaxLocal, PaxGlobal, LongName, LongLink]

# A value of a pax or GNU header. `Clear`: a pax record with an empty value,
# so the field of the ustar header applies.
Value(a) : [Inherit, Clear, Set(a)]

Meta : { path : Value(List(U8)), link : Value(List(U8)), size : Value(U64), long_path : Value(List(U8)), long_link : Value(List(U8)) }

no_meta : Meta
no_meta = { path: Inherit, link: Inherit, size: Inherit, long_path: Inherit, long_link: Inherit }

# The bytes of the values of a meta record.
meta_bytes : Meta -> U64
meta_bytes = |m| {
	n = |v| match v {
		Set(x) => x.len()
		_ => 0
	}
	n(m.path) + n(m.link) + n(m.long_path) + n(m.long_link)
}

has_meta : Meta -> Bool
has_meta = |m| m != no_meta

block_size : U64
block_size = 512

# The data of a body is complete: give its events and apply a meta header.
end_body : Tar, Sink -> Try((Tar, List(Tar.Event)), Tar.Error)
end_body = |t, sink| match sink {
	Skip => Ok((t, []))
	Keep(entry) => Ok(({ ..t, buf: [] }, [Content(entry, t.buf)]))
	LongName => Ok(({ ..t, buf: [], local: { ..t.local, long_path: Set(c_str(t.buf).release_excess_capacity()) } }, []))
	LongLink => Ok(({ ..t, buf: [], local: { ..t.local, long_link: Set(c_str(t.buf).release_excess_capacity()) } }, []))
	PaxLocal => {
		m = parse_pax(t.buf, t.local) ? |_| BadPax({ offset: t.at })
		Ok(({ ..t, buf: [], local: m }, []))
	}
	PaxGlobal => {
		m = parse_pax(t.buf, t.global) ? |_| BadPax({ offset: t.at })
		Ok(({ ..t, buf: [], global: m }, []))
	}
}

# One complete 512-byte block in phase Header or OneZero. `t.at` is its
# offset and `t.offset` is after it.
on_block : Tar, List(U8), (Tar.Entry -> Tar.Action) -> Try((Tar, List(Tar.Event)), Tar.Error)
on_block = |t, block, choose| {
	if block.all(|b| b == 0) {
		match t.phase {
			OneZero => Ok(({ ..t, phase: Ended }, []))
			_ =>
				if has_meta(t.local) {
					Err(MetaWithoutMember({ offset: t.at }))
				} else {
					Ok(({ ..t, phase: OneZero }, []))
				}
		}
	} else {
		match t.phase {
			OneZero => Err(LoneZeroBlock({ offset: t.at }))
			_ => on_header(t, block, choose)
		}
	}
}

# A header block that is not all zero.
on_header : Tar, List(U8), (Tar.Entry -> Tar.Action) -> Try((Tar, List(Tar.Event)), Tar.Error)
on_header = |t, h, choose| {
	at = t.at
	stored = octal(h, 148, 8) ? |_| BadChecksum({ offset: at })
	if !(checksum_ok(h, stored)) {
		return Err(BadChecksum({ offset: at }))
	}
	format = magic(h) ? |_| NotUstar({ offset: at })
	mode = octal(h, 100, 8) ? |_| BadNumber({ offset: at, field: "mode" })
	_uid = octal(h, 108, 8) ? |_| BadNumber({ offset: at, field: "uid" })
	_gid = octal(h, 116, 8) ? |_| BadNumber({ offset: at, field: "gid" })
	header_size = octal(h, 124, 12) ? |_| BadNumber({ offset: at, field: "size" })
	_mtime = octal(h, 136, 12) ? |_| BadNumber({ offset: at, field: "mtime" })
	type = h.get(156) ?? 0
	limits = t.limits
	if type == 'x' or type == 'g' or type == 'L' or type == 'K' {
		# The new data and the values that the reader keeps now: at most max_meta_bytes.
		kept = meta_bytes(t.local) + meta_bytes(t.global)
		if header_size + kept > limits.max_meta_bytes {
			return Err(MetaTooLarge({ offset: at, size: header_size + kept, limit: limits.max_meta_bytes }))
		}
		sink = if (type == 'x') PaxLocal else if (type == 'g') PaxGlobal else if (type == 'L') LongName else LongLink
		body({ ..t, buf: List.with_capacity(header_size) }, header_size, sink, [])
	} else {
		member(t, h, format, type, mode, header_size, choose)
	}
}

# The header of a member: apply the meta values, check the limits, call
# `choose` and start the body.
member : Tar, List(U8), [Ustar, Gnu], U8, U64, U64, (Tar.Entry -> Tar.Action) -> Try((Tar, List(Tar.Event)), Tar.Error)
member = |t, h, format, type, mode, header_size, choose| {
	at = t.at
	limits = t.limits
	name = c_str(h.sublist({ start: 0, len: 100 }))
	prefix = match format {
		Ustar => c_str(h.sublist({ start: 345, len: 155 }))
		Gnu => []
	}
	ustar_path = if (prefix.is_empty()) name else prefix.concat(['/']).concat(name)
	path_bytes = resolve(t.local.path, t.local.long_path, t.global.path, ustar_path)
	link_bytes = resolve(t.local.link, t.local.long_link, t.global.link, c_str(h.sublist({ start: 157, len: 100 })))
	size = resolve(t.local.size, Inherit, t.global.size, header_size)
	if t.members + 1 > limits.max_members {
		return Err(TooManyMembers({ offset: at, limit: limits.max_members }))
	}
	path = to_text(path_bytes, at, limits.max_path_bytes)?
	if path == "" {
		return Err(BadPath({ offset: at, problem: Empty }))
	}
	link = to_text(link_bytes, at, limits.max_path_bytes)?
	all_path_bytes = t.path_bytes + path_bytes.len() + link_bytes.len()
	if all_path_bytes > limits.max_total_path_bytes {
		return Err(TooManyPathBytes({ offset: at, limit: limits.max_total_path_bytes }))
	}
	kind = kind_of(type)
	if size > 0 and type >= '1' and type <= '6' {
		return Err(UnexpectedData({ offset: at, size }))
	}
	if size > limits.max_total_size - U64.min(t.total_size, limits.max_total_size) {
		return Err(TotalSizeTooLarge({ offset: at, limit: limits.max_total_size }))
	}
	entry = { path, kind, size, mode: mode.to_u32_wrap(), link, offset: at, type_byte: type }
	t1 = {
		..t,
		members: t.members + 1,
		path_bytes: all_path_bytes,
		total_size: t.total_size + size,
		local: no_meta,
	}
	match choose(entry) {
		Skip => body(t1, size, Skip, [Entry(entry)])
		Collect(limit) => {
			if size > limit {
				return Err(ContentTooLarge({ offset: at, size, limit }))
			}
			if size > limits.max_collect_bytes - U64.min(t.collected, limits.max_collect_bytes) {
				return Err(CollectTooLarge({ offset: at, limit: limits.max_collect_bytes }))
			}
			body({ ..t1, collected: t.collected + size, buf: List.with_capacity(size) }, size, Keep(entry), [Entry(entry)])
		}
	}
}

# Start the body of `size` bytes. A body of zero bytes ends at once.
body : Tar, U64, Sink, List(Tar.Event) -> Try((Tar, List(Tar.Event)), Tar.Error)
body = |t, size, sink, events| {
	pad = (block_size - size % block_size) % block_size
	if size == 0 {
		(t2, more) = end_body(t, sink)?
		Ok(({ ..t2, phase: Header }, events.concat(more)))
	} else {
		Ok(({ ..t, phase: Body({ left: size, pad, sink }) }, events))
	}
}

# The value of one field. A pax `x` value wins, then a GNU long name, then a
# pax `g` value, then the ustar header. An empty pax `x` value (`Clear`) also
# deletes the `g` value.
resolve : Value(a), Value(a), Value(a), a -> a
resolve = |local, gnu, global, header| {
	after_pax = |fallback| match gnu {
		Set(x) => x
		_ => fallback
	}
	match local {
		Set(x) => x
		Clear => after_pax(header)
		Inherit =>
			match global {
				Set(x) => after_pax(x)
				_ => after_pax(header)
			}
	}
}

# The bytes as text, with the checks of a path or link.
to_text : List(U8), U64, U64 -> Try(Str, Tar.Error)
to_text = |bytes, at, limit| {
	if bytes.len() > limit {
		Err(PathTooLong({ offset: at, bytes: bytes.len(), limit }))
	} else if bytes.contains(0) {
		Err(BadPath({ offset: at, problem: HasNul }))
	} else {
		# A copy: `bytes` can be a slice of a chunk, and the text must not keep the chunk.
		Ok(Str.from_utf8(bytes.release_excess_capacity()) ? |_| BadPath({ offset: at, problem: NotUtf8 }))
	}
}

kind_of : U8 -> Tar.Kind
kind_of = |type| match type {
	'0' | 0 | '7' => File
	'1' => HardLink
	'2' => Symlink
	'5' => Dir
	other => Other(other)
}

# `buf` and then `piece`, in the memory of `buf`. `buf` has the capacity of
# all its bytes (List.with_capacity). A concat to an empty list gives the
# second list back, which can be a slice of a chunk and keep all of the chunk;
# so the first byte is an append.
add_piece : List(U8), List(U8) -> List(U8)
add_piece = |buf, piece| match piece {
	[] => buf
	[first, .. as rest] => if (buf.is_empty()) buf.append(first).concat(rest) else buf.concat(piece)
}

# The parts of a path between `/` and `\`, with no empty part (as
# `std.mem.tokenizeAny` of Zig).
parts : List(U8) -> List(List(U8))
parts = |bytes| {
	var $out = []
	var $cur = []
	for b in bytes {
		if b == '/' or b == '\\' {
			if !$cur.is_empty() {
				$out = $out.append($cur)
			}
			$cur = []
		} else {
			$cur = $cur.append(b)
		}
	}
	if ($cur.is_empty()) $out else $out.append($cur)
}

# The link target rules of `linkTargetUnbundleErr` (roc
# `src/unbundle/unbundle.zig`), of Unix and Windows together.
check_link : Str -> Try({}, [Absolute, DriveLetter, ParentDir, DotPart])
check_link = |target| {
	bytes = target.to_utf8()
	first = bytes.get(0) ?? 0
	if first == '/' or first == '\\' {
		return Err(Absolute)
	}
	if bytes.get(1) == Ok(':') {
		return Err(DriveLetter)
	}
	for part in parts(bytes) {
		if part == ['.', '.'] {
			return Err(ParentDir)
		}
		if part == ['.'] {
			return Err(DotPart)
		}
	}
	Ok({})
}

# The bytes before the first `stop`.
c_until : List(U8), U8 -> List(U8)
c_until = |bytes, stop| match bytes.find_first_index(|b| b == stop) {
	Ok(k) => bytes.take_first(k)
	Err(NotFound) => bytes
}

ascii_upper : List(U8) -> List(U8)
ascii_upper = |bytes| bytes.map(|b| if (b >= 'a' and b <= 'z') b - 32 else b)

# `WINDOWS_RESERVED_NAMES` of roc `src/unbundle/unbundle.zig`.
reserved_names : List(List(U8))
reserved_names = ["CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"].map(|n| n.to_utf8())

# The bytes before the first NUL.
c_str : List(U8) -> List(U8)
c_str = |bytes| match bytes.find_first_index(|b| b == 0) {
	Ok(k) => bytes.take_first(k)
	Err(NotFound) => bytes
}

# `Ustar` for the magic "ustar\0", `Gnu` for "ustar  \0" (old GNU format: no
# prefix field).
magic : List(U8) -> Try([Ustar, Gnu], [NotUstar])
magic = |h| {
	m = h.sublist({ start: 257, len: 8 })
	if m.take_first(6) == ['u', 's', 't', 'a', 'r', 0] {
		Ok(Ustar)
	} else if m == ['u', 's', 't', 'a', 'r', ' ', ' ', 0] {
		Ok(Gnu)
	} else {
		Err(NotUstar)
	}
}

# The header checksum: the sum of the 512 bytes with the 8 checksum bytes as
# spaces. Unsigned bytes (POSIX), or signed bytes (some old writers).
checksum_ok : List(U8), U64 -> Bool
checksum_ok = |h, stored| {
	var $unsigned = 0.U64
	var $signed = 0.I64
	var $k = 0.U64
	for b in h {
		v = if ($k >= 148 and $k < 156) ' ' else b
		$unsigned = $unsigned + v.to_u64()
		$signed = $signed + v.to_i8_wrap().to_i64()
		$k = $k + 1
	}
	stored == $unsigned or stored.to_i64_wrap() == $signed
}

# An octal field: spaces, then octal digits, then only NUL or space. A field
# of only NUL or space is 0. A base-256 field (first byte >= 0x80) is an error.
octal : List(U8), U64, U64 -> Try(U64, [BadNumber])
octal = |h, start, len| {
	field = h.sublist({ start, len })
	var $value = 0.U64
	var $state = Lead
	for b in field {
		match $state {
			Lead =>
				if b == ' ' {
					{}
				} else if b >= '0' and b <= '7' {
					$value = (b - '0').to_u64()
					$state = Digits
				} else if b == 0 {
					$state = Tail
				} else {
					return Err(BadNumber)
				}
			Digits =>
				if b >= '0' and b <= '7' {
					$value = $value * 8 + (b - '0').to_u64()
				} else if b == 0 or b == ' ' {
					$state = Tail
				} else {
					return Err(BadNumber)
				}
			Tail =>
				if b == 0 or b == ' ' {
					{}
				} else {
					return Err(BadNumber)
				}
		}
	}
	Ok($value)
}

# The records of a pax header: "<length> <key>=<value>\n", where <length> is
# the decimal length of the whole record. The keys `path`, `linkpath` and
# `size` change `meta`. An empty value clears the key. Other keys are ignored.
parse_pax : List(U8), Meta -> Try(Meta, [BadPax])
parse_pax = |data, meta| {
	var $m = meta
	var $pos = 0.U64
	n = data.len()
	while $pos < n {
		rest = data.drop_first($pos)
		space = rest.find_first_index(|b| b == ' ') ? |_| BadPax
		if space == 0 or space > 20 {
			return Err(BadPax)
		}
		len = decimal(rest.take_first(space)) ? |_| BadPax
		if len <= space + 1 or len > rest.len() {
			return Err(BadPax)
		}
		if rest.get(len - 1) != Ok('\n') {
			return Err(BadPax)
		}
		kv = rest.sublist({ start: space + 1, len: len - space - 2 })
		{ before: key, after: value } = kv.split_first('=') ? |_| BadPax
		if key.is_empty() {
			return Err(BadPax)
		}
		$m = if key == "path".to_utf8() {
			{ ..$m, path: if (value.is_empty()) Clear else Set(value.release_excess_capacity()) }
		} else if key == "linkpath".to_utf8() {
			{ ..$m, link: if (value.is_empty()) Clear else Set(value.release_excess_capacity()) }
		} else if key == "size".to_utf8() {
			if value.is_empty() {
				{ ..$m, size: Clear }
			} else {
				size = decimal(value) ? |_| BadPax
				{ ..$m, size: Set(size) }
			}
		} else {
			$m
		}
		$pos = $pos + len
	}
	Ok($m)
}

# Decimal digits, at least one, with no overflow.
decimal : List(U8) -> Try(U64, [BadNumber])
decimal = |digits| {
	if digits.is_empty() {
		return Err(BadNumber)
	}
	var $value = 0.U64
	for b in digits {
		if b < '0' or b > '9' {
			return Err(BadNumber)
		}
		$value = match $value.times_try(10) {
			Ok(v) =>
				match v.plus_try((b - '0').to_u64()) {
					Ok(w) => w
					Err(_) => return Err(BadNumber)
				}
			Err(_) => return Err(BadNumber)
		}
	}
	Ok($value)
}

# The writer: a member with the fixed defaults.
member_of : Str, [File(List(U8)), Dir, Symlink(Str), HardLink(Str)], U32 -> Tar.Member
member_of = |path, kind, mode| { path, kind, mode, mtime: 0, uid: 0, gid: 0, uname: "", gname: "" }

# The checks of one member. Gives the key of the path: the path with no `/`
# at the end (a directory can have one), so `a` and `a/` are the same path.
check_member : Tar.Member, Set(Str), Set(Str) -> Try(Str, Tar.WriteError)
check_member = |m, paths, files| {
	path = m.path
	is_dir = m.kind == Dir
	key = check_write_path(path, is_dir) ? |problem| BadPath({ path, problem })
	match m.kind {
		Symlink(target) => check_target(target) ? |problem| BadLink({ path, problem })
		HardLink(target) => {
			check_target(target) ? |problem| BadLink({ path, problem })
			if !files.contains(target) {
				return Err(BadLink({ path, problem: NotEarlierFile }))
			}
		}

		_ => {}
	}
	if m.uname.to_utf8().contains(0) or m.gname.to_utf8().contains(0) {
		return Err(BadOwnerName({ path: path }))
	}
	if m.mode > 0o7777 {
		return Err(BadMode({ path, mode: m.mode }))
	}
	if paths.contains(key) {
		return Err(DuplicatePath({ path: path }))
	}
	Ok(key)
}

# A path that the writer accepts: not empty, no NUL, no `/` at the start,
# and parts between single `/` that are not empty, `.` or `..`. Only a
# directory can end with one `/`.
check_write_path : Str, Bool -> Try(Str, [Empty, HasNul, Absolute, EmptyPart, DotPart, ParentDir, TrailingSlash])
check_write_path = |path, is_dir| {
	bytes = path.to_utf8()
	if bytes.is_empty() {
		return Err(Empty)
	}
	if bytes.contains(0) {
		return Err(HasNul)
	}
	if bytes.first() == Ok('/') {
		return Err(Absolute)
	}
	ends_with_slash = bytes.last() == Ok('/')
	if ends_with_slash and !is_dir {
		return Err(TrailingSlash)
	}
	key = if (ends_with_slash) bytes.drop_last(1) else bytes
	for part in key.split_on('/') {
		if part.is_empty() {
			return Err(EmptyPart)
		}
		if part == ['.'] {
			return Err(DotPart)
		}
		if part == ['.', '.'] {
			return Err(ParentDir)
		}
	}
	Ok(Str.from_utf8(key) ?? path)
}

check_target : Str -> Try({}, [Empty, HasNul])
check_target = |target| {
	bytes = target.to_utf8()
	if bytes.is_empty() {
		Err(Empty)
	} else if bytes.contains(0) {
		Err(HasNul)
	} else {
		Ok({})
	}
}

# The largest values of the octal fields: 7 digits (mode, uid, gid) and 11
# digits (size, mtime).
max_octal_7 : U64
max_octal_7 = 0o7777777

max_octal_11 : U64
max_octal_11 = 0o77777777777

# The chunk of one checked member: a pax `x` header if a field does not fit,
# the ustar header, the data, the padding.
member_bytes : Tar.Member -> List(U8)
member_bytes = |m| {
	path = m.path.to_utf8()
	(type, link, data) = match m.kind {
		File(d) => ('0', [], d)
		Dir => ('5', [], [])
		Symlink(t) => ('2', t.to_utf8(), [])
		HardLink(t) => ('1', t.to_utf8(), [])
	}
	size = data.len()
	(prefix, name, path_rec) = match ustar_split(path) {
		Ok((p, n)) => (p, n, [])
		Err(NoSplit) => ([], fit(path, 100), pax_record("path", path))
	}
	(link_field, link_rec) = if (link.len() <= 100) (link, []) else (fit(link, 100), pax_record("linkpath", link))
	(size_field, size_rec) = number(size, max_octal_11, "size")
	(uid_field, uid_rec) = number(m.uid, max_octal_7, "uid")
	(gid_field, gid_rec) = number(m.gid, max_octal_7, "gid")
	(mtime_field, mtime_rec) = number(m.mtime, max_octal_11, "mtime")
	uname = m.uname.to_utf8()
	gname = m.gname.to_utf8()
	(uname_field, uname_rec) = if (uname.len() <= 31) (uname, []) else (fit(uname, 31), pax_record("uname", uname))
	(gname_field, gname_rec) = if (gname.len() <= 31) (gname, []) else (fit(gname, 31), pax_record("gname", gname))
	# The records in the order of their keys.
	records = gid_rec.concat(gname_rec).concat(link_rec).concat(mtime_rec).concat(path_rec).concat(size_rec).concat(uid_rec).concat(uname_rec)
	pax = if records.is_empty() {
		[]
	} else {
		ustar_header({ name: "././@PaxHeader".to_utf8(), prefix: [], mode: 0o644, uid: 0, gid: 0, size: records.len(), mtime: 0, type: 'x', link: [], uname: [], gname: [] })
			.concat(records)
			.concat(List.repeat(0, pad_of(records.len())))
	}
	header = ustar_header({ name, prefix, mode: m.mode.to_u64(), uid: uid_field, gid: gid_field, size: size_field, mtime: mtime_field, type, link: link_field, uname: uname_field, gname: gname_field })
	List.with_capacity(pax.len() + block_size + size + pad_of(size))
		.concat(pax)
		.concat(header)
		.concat(data)
		.concat(List.repeat(0, pad_of(size)))
}

# A number for an octal field, or 0 and a pax record when it does not fit.
number : U64, U64, Str -> (U64, List(U8))
number = |value, max, key| if (value <= max) (value, []) else (0, pax_record(key, value.to_str().to_utf8()))

# The octal digits of a number, with no leading zero.
octal_text : U64 -> Str
octal_text = |value| {
	var $digits = []
	var $v = value
	while $digits.is_empty() or $v > 0 {
		$digits = $digits.prepend('0' + ($v % 8).to_u8_wrap())
		$v = $v // 8
	}
	Str.from_utf8($digits) ?? ""
}

pad_of : U64 -> U64
pad_of = |n| (block_size - n % block_size) % block_size

# The path in the ustar prefix and name fields: the name alone when it has
# at most 100 bytes, else split at the first `/` that leaves at most 100
# bytes after it and at most 155 bytes before it, with neither part empty
# (as GNU tar). `NoSplit` when no `/` fits.
ustar_split : List(U8) -> Try((List(U8), List(U8)), [NoSplit])
ustar_split = |path| {
	n = path.len()
	if n <= 100 {
		return Ok(([], path))
	}
	var $k = n - 101
	while $k <= 155 and $k < n - 1 {
		if path.get($k) == Ok('/') and $k > 0 {
			return Ok((path.take_first($k), path.drop_first($k + 1)))
		}
		$k = $k + 1
	}
	Err(NoSplit)
}

# The first bytes of `bytes`, at most `n`, cut at the start of a UTF-8
# character, for a field that a pax record replaces.
fit : List(U8), U64 -> List(U8)
fit = |bytes, n| {
	var $k = U64.min(n, bytes.len())
	while $k > 0 and $k < bytes.len() and (bytes.get($k) ?? 0).bitwise_and(0xC0) == 0x80 {
		$k = $k - 1
	}
	bytes.take_first($k)
}

# One pax record: "<length> <key>=<value>\n", where <length> counts its own
# digits.
pax_record : Str, List(U8) -> List(U8)
pax_record = |key, value| {
	text = [' '].concat(key.to_utf8()).append('=').concat(value).append('\n')
	var $n = text.len() + 1
	while $n != text.len() + $n.to_str().count_utf8_bytes() {
		$n = $n + 1
	}
	$n.to_str().to_utf8().concat(text)
}

UstarFields : { name : List(U8), prefix : List(U8), mode : U64, uid : U64, gid : U64, size : U64, mtime : U64, type : U8, link : List(U8), uname : List(U8), gname : List(U8) }

# A 512-byte POSIX ustar header (magic "ustar\0", version "00"). The numbers
# are octal with leading zeros and a NUL; the checksum is 6 digits, NUL and
# space (as GNU tar). The device numbers are 0.
ustar_header : UstarFields -> List(U8)
ustar_header = |f| {
	fields = field(f.name, 100)
		.concat(octal_field(f.mode, 8))
		.concat(octal_field(f.uid, 8))
		.concat(octal_field(f.gid, 8))
		.concat(octal_field(f.size, 12))
		.concat(octal_field(f.mtime, 12))
		.concat(List.repeat(' ', 8))
		.append(f.type)
		.concat(field(f.link, 100))
		.concat(['u', 's', 't', 'a', 'r', 0, '0', '0'])
		.concat(field(f.uname, 32))
		.concat(field(f.gname, 32))
		.concat(octal_field(0, 8))
		.concat(octal_field(0, 8))
		.concat(field(f.prefix, 155))
		.concat(List.repeat(0, 12))
	sum = fields.fold(0.U64, |acc, b| acc + b.to_u64())
	fields.take_first(148).concat(octal_field(sum, 7)).append(' ').concat(fields.drop_first(156))
}

# The bytes and NUL bytes to `width`.
field : List(U8), U64 -> List(U8)
field = |bytes, width| bytes.concat(List.repeat(0, width - bytes.len()))

# `width - 1` octal digits with leading zeros, then NUL.
octal_field : U64, U64 -> List(U8)
octal_field = |value, width| {
	var $digits = List.repeat('0', width - 1)
	var $v = value
	var $k = width - 1
	while $k > 0 {
		$k = $k - 1
		$digits = $digits.set($k, '0' + ($v % 8).to_u8_wrap()) ?? $digits
		$v = $v // 8
	}
	$digits.append(0)
}
