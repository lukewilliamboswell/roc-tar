app [main!] {
	pf: platform "https://github.com/roc-lang/basic-cli/releases/download/0.26.0/GddgvsGjiNXrHFW6au5i5dUDbTs8FinQdrgE2Gqmw53t.tar.zst",
	pkg: "../../package/main.roc",
}

import pf.Stdout
import pkg.Tar

## Writes the sample archive of `Tar.create` to standard output: each member
## kind, and each field that does not fit in the ustar header (so it goes in
## a pax record). scripts/writer.sh lists and extracts it with GNU tar and
## bsdtar, and makes tests/fixtures/written.tar. tests/write.roc has the same
## members and checks that `Tar.create` still gives the bytes of the fixture.
main! = |_args| {
	bytes = Tar.create(sample) ? |e| Tar(Tar.write_err_to_str(e))
	Stdout.write_bytes!(bytes)
}

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
