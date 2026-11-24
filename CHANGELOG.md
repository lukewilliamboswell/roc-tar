# Changelog

## 0.0.3-rc1

A release candidate, from the fork `lukewilliamboswell/roc-tar`.

| Change | Kind | What to do |
| --- | --- | --- |
| New `Tar.create : List(Tar.Member) -> Try(List(U8), Tar.WriteError)`: a ustar archive of the members, in their order, then two zero blocks. A field that does not fit in the ustar header (a long path or link target, a large size, uid, gid or mtime, a long uname or gname) goes in a pax `x` record. The bytes are a function of the members only. | New | |
| New `Tar.writer : {} -> Tar.Writer`, `Tar.Writer.add` and `Tar.Writer.end`: the same archive, one chunk for each member. | New | |
| New `Tar.Member`, and `Tar.file`, `Tar.dir`, `Tar.symlink` and `Tar.hard_link`, which make a member with fixed defaults (mode 0o644, 0o755 or 0o777, mtime 0, owner 0, empty names). | New | |
| New `Tar.WriteError` (a closed tag union) and `Tar.write_err_to_str`. The writer refuses an empty path, a NUL byte, an absolute path, an empty, `.` or `..` part, a `/` at the end of a member that is not a directory, an empty link target, a hard link to a path that is not an earlier file, a mode over 0o7777 and a repeated path. | New | |

The reader does not change. A build can take 0.0.3 in place of 0.0.2 (`roc bump` against 0.0.2: a MINOR change, "breaking changes bump X, everything else bumps Y").

`scripts/test.sh` passes on nightly-2026-10-31-f7bef6b (the pin), nightly-2026-11-18-a520eed and Roc 0.1.0_RC1. A test helper had a name that shadowed another (`tests/lib/Mk.roc`), a warning that made `roc check` fail on the two newer compilers; it has a new name.

## 0.0.2

| Change | Kind | What to do |
| --- | --- | --- |
| `Tar.Entry` has the new field `type_byte : U8`: the type byte of the ustar header of the member, as it is (after a pax `x` or GNU `L`/`K` header, the byte of the member header). `kind` does not change: `0`, NUL and `7` are still `File`. | Breaking | Code that makes an `Entry` record (for example a fake `Entry` in a test) must add `type_byte`. Code that only reads fields does not change. |
| New `Tar.roc_accepts : Tar.Entry -> Try({}, [UnsupportedType(U8), Path(...), Link(...)])`: `Ok({})` when `roc unbundle` (roc-lang/roc `76258c1`, Zig 0.17.0 `std.tar.Iterator`) accepts the member on each OS. Only types `0`, NUL, `5` and `2` are accepted; `7` is `UnsupportedType('7')`. | New | Use it in place of a read of the byte at `entry.offset + 156`. |

Note: 0.0.2 is in the series of 0.0.1 (below 1.0 the series is `0.minor`). A build can take 0.0.2 in place of 0.0.1. A dependent that makes its own `Entry` record must add `type_byte` before it uses 0.0.2.

## 0.0.1

The first release: a streaming reader for ustar, pax and GNU long names, `check_path`, `check_portable_path`, `held_bytes`.
