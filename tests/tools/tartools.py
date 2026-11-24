#!/usr/bin/env python3
# Lists and extracts each tar file with GNU tar and with bsdtar, and exits 1
# when the two do not agree. For each file it prints one line for each member,
# "<mode> <uid> <gid> <uname> <gname> <size> <path>[ -> <target>| link to
# <target>]" as both tools list it, then the extracted tree. The tree has
# one line for each path: the type, the permission bits (not of a symbolic
# link), the mtime (not of a symbolic link, and of a directory only when it
# is a member: tar makes a missing parent directory at the time of the
# extraction), the size and SHA-256 of a file,
# the target of a symbolic link, and the first path of each hard link group.
# Usage: python3 -I tartools.py GNU_TAR BSD_TAR FILE.tar...
import hashlib, os, stat, subprocess, sys, tempfile

GNU, BSD = sys.argv[1], sys.argv[2]
ENV = dict(os.environ, LC_ALL="C", TZ="UTC")


def run(args):
    r = subprocess.run(args, capture_output=True, env=ENV)
    if r.returncode != 0 or r.stderr:
        sys.exit(f"{' '.join(args)}: exit {r.returncode}: {r.stderr.decode(errors='replace')}")
    return r.stdout.decode("utf-8", errors="surrogateescape")


# GNU: "mode uid/gid size date time name". bsdtar: "mode links uid gid size
# month day time-or-year name". Both in the C locale, with the same escapes.
def gnu_list(f):
    out = []
    numeric = run([GNU, "--numeric-owner", "-tvf", f]).splitlines()
    named = run([GNU, "-tvf", f]).splitlines()
    for a, b in zip(numeric, named):
        mode, ids, size, _d, _t, rest = a.split(None, 5)
        names = b.split(None, 2)[1]
        uid, gid = ids.split("/")
        uname, gname = names.split("/")
        out.append((mode, uid, gid, uname, gname, size, rest))
    return out


def bsd_list(f):
    out = []
    numeric = run([BSD, "--numeric-owner", "-tvf", f]).splitlines()
    named = run([BSD, "-tvf", f]).splitlines()
    for a, b in zip(numeric, named):
        mode, _n, uid, gid, size, _m, _d, _t, rest = a.split(None, 8)
        _mode, _n2, uname, gname = b.split(None, 4)[:4]
        out.append((mode, uid, gid, uname, gname, size, rest))
    return out


def tree(root, members):
    lines, groups = [], {}
    for dirpath, dirs, files in os.walk(root):
        dirs.sort()
        for name in sorted(dirs + files):
            p = os.path.join(dirpath, name)
            rel = os.path.relpath(p, root)
            st = os.lstat(p)
            if stat.S_ISLNK(st.st_mode):
                lines.append(f"l {rel} -> {os.readlink(p)}")
            elif stat.S_ISDIR(st.st_mode):
                mtime = int(st.st_mtime) if rel in members else "-"
                lines.append(f"d {oct(st.st_mode & 0o7777)} {mtime} {rel}")
            else:
                with open(p, "rb") as fh:
                    digest = hashlib.sha256(fh.read()).hexdigest()
                first = groups.setdefault((st.st_dev, st.st_ino), rel)
                lines.append(f"f {oct(st.st_mode & 0o7777)} {int(st.st_mtime)} {st.st_size} {digest} {rel} group {first}")
    return sorted(lines)


# A pax `mtime` is after the year 2242, so GNU tar warns that it is in the
# future: only that warning is off.
def extract(tool, f, members):
    quiet = ["--warning=no-timestamp"] if tool == GNU else []
    with tempfile.TemporaryDirectory(prefix="tartools-") as d:
        run([tool] + quiet + ["-xpf", os.path.abspath(f), "-C", d])
        return tree(d, members)


fail = 0
for f in sys.argv[3:]:
    g, b = gnu_list(f), bsd_list(f)
    # The member paths, with no `/` at the end (names with escapes are not found).
    members = {line[6].rstrip("/") for line in g if line[0].startswith("d")}
    tg, tb = extract(GNU, f, members), extract(BSD, f, members)
    print(f"== {f}")
    for line in g:
        print(" ".join(line))
    for line in tg:
        print(line)
    if g != b:
        fail = 1
        print("DIFFERENT listing")
        for x, y in zip(g, b):
            if x != y:
                print(f"  gnu {x}\n  bsd {y}")
        if len(g) != len(b):
            print(f"  gnu {len(g)} members, bsd {len(b)} members")
    if tg != tb:
        fail = 1
        print("DIFFERENT tree")
        for x in sorted(set(tg) ^ set(tb)):
            print(f"  {'gnu' if x in tg else 'bsd'} {x}")
sys.exit(fail)
