# ipscrub

Find an IP address on a host, and remove it, without planting the address
anywhere new while you do it.

I wrote this after a session where my home IP kept showing up on a cloud box and
the usual `grep -rl ... | xargs sed -i` made things worse: the address ended up
in shell history, in the process table of a root shell, and in the audit log that
`sudo` writes. `ipscrub` is the version of that afternoon I wish I'd had.

## What it actually does

`ipscrub` walks a set of roots, finds every file containing the address, removes
it, and then re-scans from scratch to prove the result. Three details matter more
than the walk itself.

**The network, not just the host.** Matching `203.0.113.9` exactly leaves
`203.0.113.250` in place, and that is a different machine on the same home
connection, which is the thing you were trying to hide. By default `ipscrub`
also matches the enclosing prefix (`/24` for IPv4, `/64` for IPv6), which is what
catches the neighbours.

**Daemons lose data when you replace their files.** Rewriting `/var/log/syslog`
with the usual temp-file-and-rename leaves rsyslog holding a descriptor to an
unlinked inode; it keeps writing happily and everything after the rename is
gone. Files under `/var/log/` are rewritten in place, keeping the inode. The SSM
agent's log is truncated rather than edited, because the agent reopens it and
would otherwise duplicate the contents.

**Binary logs are not searchable, so a miss means nothing.** journald compresses
and deduplicates entries, so a plaintext scan of a `.journal` file comes back
empty even when the address is in there. Those files are deleted on the pattern
alone (journald is stopped and restarted around it), because "no match found" is
not evidence of absence. `--keep-journals` narrows it to only-on-a-match if you'd
rather trade the guarantee for the logs.

## Install

Python 3.9+, no dependencies.

```bash
git clone https://github.com/profcoconut/ipscrub
cd ipscrub
pip install -e .
```

## Use

```bash
# look, change nothing
ipscrub scan --address 203.0.113.9

# clean, then verify
sudo ipscrub clean --address 203.0.113.9

# check whether the last clean actually held
ipscrub verify --address 203.0.113.9
```

Exit codes: `0` clean, `1` matches present, `2` bad invocation. A `clean` that
leaves anything behind exits `1`, so it drops straight into a script.

Prefer to keep the address off the command line:

```bash
export IPSCRUB_ADDRESS_B64=$(printf '%s' '203.0.113.9' | base64)
sudo --preserve-env=IPSCRUB_ADDRESS_B64 ipscrub clean
```

Everything that leaves the process is a count or a marker. `describe()` reports
`203.0.113.0/24`, never the host address, so pasting a run into a chat or an issue
does not undo the cleanup.

Options worth knowing:

| flag | why |
| --- | --- |
| `--prefix-len N` | widen or narrow the network match; `0` or `--no-prefix` for the exact address only |
| `--root DIR` | repeatable; defaults to a standard Linux set (`/var/log`, `/etc`, `/home`, `/root`, `/var/lib`, `/tmp`, `/opt`, `/srv`, `/data`, `/usr/local`) |
| `--max-bytes N` | skip and report files above this (default 200 MiB) |
| `--keep-journals` | delete a journal file only when a plaintext match was found in it |
| `--no-journald` | do not stop/start journald around journal deletion |
| `--json` | machine-readable result |

## On a remote box

```bash
ipscrub remote --instance i-0123456789abcdef0 --region ap-northeast-1
ipscrub remote --instance i-0123456789abcdef0 --region ap-northeast-1 --apply
```

This needs the AWS CLI locally and the SSM agent on the target. The package is
zipped, gzipped, base64 encoded, uploaded through Run Command in sequential
chunks, checksum-verified, and only then run. The address is passed in the
environment rather than in `argv`, so a process listing on the target does not
show it.

Two things to know if you touch `remote.py`:

- Chunked uploads go in the `commands` array of **one** invocation, which runs
  them in order. Two separate invocations appending to the same file interleave
  and produce a file that looks fine and is not.
- Every remote run leaves fresh footprints: the SSM agent logs the command it
  ran, and it caches the orchestration document. That is why the plan truncates
  the agent log and removes the orchestration cache. Run `clean` twice, and the
  second run is the one that verifies the first.

## As a library

```python
from ipscrub import Matcher, Plan, run

matcher = Matcher.build(["203.0.113.9"])
outcome = run(matcher, Plan.for_roots(["/var/log"]))
for line in outcome.summary_lines():
    print(line)
```

`Plan` is a frozen dataclass; `replace(plan, roots=(...))` is how you vary it
without touching the defaults.

## What it does not do

- It does not touch a Mac or a Windows box. The path rules and the journald
  handling are Linux-shaped.
- It does not rotate logs for you, and it will not stop a daemon that keeps
  writing new lines containing the address. If something on the host prints the
  address continuously, cleaning is a rearguard action; fix the source.
- It does not search inside archives, databases, or compressed files other than
  by deleting the ones the plan names.

## Tests

```bash
pip install -e '.[dev]'
pytest
```

The suite covers the parts that broke while I was writing this: prefix matching
that must not leave dangling octets, in-place rewrites that must preserve the
inode, special rules that must not be applied twice, verification that must
actually re-read the disk, and payloads that must not contain the address. Two
tests are POSIX-only (inode and permission checks) and skip on Windows.

## Licence

MIT.
