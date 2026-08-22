# hive-system

<!-- hive-badges -->

[![Clojars Project](https://img.shields.io/clojars/v/io.github.hive-agi/hive-system.svg)](https://clojars.org/io.github.hive-agi/hive-system)
[![cljdoc](https://cljdoc.org/badge/io.github.hive-agi/hive-system)](https://cljdoc.org/d/io.github.hive-agi/hive-system/CURRENT)
[![release](https://github.com/hive-agi/hive-system/actions/workflows/release.yml/badge.svg)](https://github.com/hive-agi/hive-system/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

<!-- /hive-badges -->

The systems-programming foundation of the [hive](https://github.com/hive-agi)
ecosystem. Every host capability a Clojure program reaches for — a process, a
shell, the filesystem, crypto, secrets, a GPU, a regex — sits behind a
**protocol**, and every operation returns a **`Result`** from
[hive-dsl](https://github.com/hive-agi/hive-dsl) rather than throwing.

Two consequences, and they are the whole point:

- **Consumers depend on a port, never on a concretion.** Swap Tink for
  libsodium, `java.util.regex` for a POSIX ERE emitter, GNU pass for another
  store — the calling code does not change.
- **Tests inject a record, not a mock.** Each protocol is small enough to stub
  in a few lines, so a suite never needs the real filesystem, the real network,
  or a real `nvidia-smi`.

License: MIT.

## Installation

```clojure
;; deps.edn
io.github.hive-agi/hive-system {:mvn/version "0.3.6"}
```

## The ports

`hive-system.protocols` holds the core contracts; each subsystem adds its own
narrow ones. "Adapter" is what this repo ships for that port — everything else
is the consumer's to supply.

| Protocol | Purpose | Adapter shipped |
|---|---|---|
| `IShell` | Run a command, capture everything it printed | `shell.core/make-shell` (ProcessBuilder) |
| `IBoundedShell` | Run a command under a **line and byte budget** | same `Shell` record |
| `IProcess` | Long-lived process lifecycle: spawn / wait / signal / pipe | `process.core` |
| `IWorker` | Warm request/response worker over a long-lived process | `process.worker` |
| `IPathQuery` | Path predicates and resolution — pure queries | `fs.core/->FsPathQuery` (babashka.fs) |
| `IFilesystem` | The mutation side: watch, atomic write, lock, tmpdir, mkdirs | `fs.filesystem/make-filesystem` |
| `ICrypto` | AEAD, HPKE, hash, sign/verify, KDF, password hash | `crypto.tink`, `crypto.caesium` |
| `ISecret` / `ISecretBackend` | An opaque credential; fetching one from a store | `secrets.core`, `secrets.pass` (GNU pass) |
| `IPatternEngine` | Match / scan a named pattern against a subject | `pattern.regex` (`java.util.regex`) |
| `IConstructEmitter` | Render a regex **construct** into one dialect | `construct.regal` (`:java`, `:ecma`, `:re2`), `construct.ere` (`:posix-ere`) |
| `IGpuExecutor` / `IGpuStatus` | Submit GPU-bound work; report device state | `gpu.ollama`, `gpu.probe` (nvidia-smi) |
| `IDistroDetector` / `IPackageInstaller` / `IDependencyEnsurer` | Detect the host distro, install packages, ensure a tool exists | `deps.registry`, `deps.core` |
| `INetwork` | Connect / listen / send / recv | **contract only** — no adapter in this repo yet |
| `IHostOSRelease` / `IHostExecutableLookup` | Primitive host-identity capabilities | **contract only** — implemented by host projects |
| `IJournal` | Bitemporal execution journal | **declared, not implemented** — see [Status](#status) |

## The Result contract

Nothing here throws across a boundary. Every operation answers `(r/ok v)` or
`(r/err tag data)`, so calls compose on the railway:

```clojure
(require '[hive-dsl.result :as r]
         '[hive-system.shell.core :as shell]
         '[hive-system.fs.core :as fs])

(r/let-ok [root (fs/resolve-path "/srv" "app" "src")
           _    (fs/directory? root)
           out  (shell/exec-ok! ["git" "status" "--porcelain"] {:dir root})]
  (r/ok (:stdout out)))
```

## Shell

`exec!` captures everything the child printed. `lines!` is the segregated
sibling for callers with a budget — the memory cost of `exec!` is set by the
child, not by you.

```clojure
(require '[hive-system.shell.core :as shell])

(shell/exec! "echo hi" {:dir "/tmp" :timeout-ms 5000})
;; => (ok {:exit 0 :stdout "hi\n" :stderr "" :cmd "echo hi" :duration-ms 12})

(shell/lines! ["rg" "--files" "/srv/app"] {:max-lines 1000 :max-bytes (* 8 1024 1024)})
;; => (ok {:lines [...] :truncated? true :reason :max-lines :exit nil :stderr "" …})
```

`:truncated?` is the load-bearing key: a caller handed exactly `:max-lines`
lines cannot otherwise tell a command that printed that many from one that
printed more. `:reason` names which bound stopped it — `:eof`, `:max-lines` or
`:max-bytes`. When a cap fires the process **tree** is destroyed, so `:exit` is
nil.

`shell.tools` maps a tool key to its binary, its alternate binary names, and an
install hint per package manager, so a missing dependency reports how to get it:

```clojure
(shell/require-tool :ripgrep)
;; => (ok  {:path "/usr/bin/rg" :program "rg" :bin "rg" :tool :ripgrep
;;           :desc "Fast recursive grep"})
;; => (err :tool/missing {:tool :ripgrep :bin "rg" :tried ["rg"] :hints [...] :message "…"})
```

The `:bin` in a successful Result is the name that actually answered — spawn
**that**, not the upstream name (Debian ships `fd` as `fdfind`).
`shell.tools/require-tools`, `list-tools` and `register-tool!` cover the rest.

## Patterns and constructs

`pattern.core` is the facade: name what you are looking for, get an answer,
never mention an engine.

```clojure
(require '[hive-system.pattern.core :as pattern])

(pattern/register-pattern! #:pattern{:id :audit/probe :expr "ready\\?"})
(pattern/match?     :audit/probe "ready?")   ;; => (ok true)
(pattern/scan       :audit/probe source)     ;; => (ok [{…} {…}])
(pattern/find-first :audit/probe source)     ;; => (ok {…})
```

A **construct** is the same regex written as data, rendered per dialect. A
construct a dialect cannot express is refused, never silently approximated:

```clojure
(require '[hive-system.pattern.construct.api :as construct]
         '[hive-system.pattern.construct.ere])   ;; registers the :posix-ere emitter

(construct/->expr :java [:cat :start [:+ :digit] :end])
;; => (ok "^\\d+$")

(construct/->expr :posix-ere [:cat :start [:+ :digit] :end])
;; => (err :construct/unsupported {:dialect :posix-ere :missing [:perl-class] :provides []})

(construct/->expr :posix-ere [:cat :start [:+ [:class [\0 \9]]] :end])
;; => (ok "^[0-9]+$")

(construct/supported? :posix-ere [:lookahead "x"])   ;; => (ok false)

(construct/explain [:+ :digit])
;; => (ok {:construct {…}
;;         :requires  #{:perl-class}
;;         :dialects  {:java [] :ecma [] :re2 [] :posix-ere [:perl-class]}})

(construct/register! #:pattern{:id :audit/probe} [:cat "ready" [:? "?"]])
;; => (ok #:pattern{:id :audit/probe :expr "ready(?:\\?)?" :construct {…}})
```

`grep -E` does not refuse a `\d` — it *reinterprets* it, so a dialect that
cannot express a construct returns `:construct/unsupported` naming the missing
capabilities rather than emitting something the tool would read differently.
`explain` is the introspection surface: each dialect's entry lists what it lacks
for this construct, and `[]` means it can render it.

Dialects: `:java` (the engine behind the default `IPatternEngine`), `:ecma`,
and `:re2` (rg / sd / fd) come from `construct.regal`, which `construct.api`
already loads. `:posix-ere` (`grep -E`) lives in `construct.ere` and registers
itself when that namespace is required — directly, or transitively via
`shell.search`. `*default-dialect*` (`:java`) selects what a caller who names
none gets.

`shell.search` closes the loop: build the **argv** for a pattern-taking CLI from
a construct, so the expression is rendered in the dialect that tool actually
speaks and the `--` separator lands where its grammar requires.

```clojure
(require '[hive-system.shell.search :as search])

(search/argv :rg   [:cat [:+ :digit] "-"] {:operands ["src"]})
;; => (ok ["rg" "--regexp" "\\d+-" "--" "src"])
(search/argv :grep [:+ [:class [\0 \9]]] {:operands ["src"]})
;; => (ok ["grep" "-E" "-e" "[0-9]+" "--" "src"])
(search/argv :sd   [:+ :digit] {:operands ["N" "f.txt"]})
;; => (ok ["sd" "--" "\\d+" "N" "f.txt"])
```

Profiles shipped: `:rg`, `:grep`, `:fd`, `:sd`. `search/register!` adds your
own; `search/executable` resolves the name the tool is *installed* under and
`search/runnable?` / `search/explain` say whether this host can run it at all.

## Filesystem

Read-only queries (`IPathQuery`) are separated from mutation (`IFilesystem`), so
a consumer that only asks questions cannot be handed a writer.

```clojure
(require '[hive-system.fs.core :as fs]
         '[hive-system.fs.filesystem :as fsys])

(fs/exists? "/etc/hosts")                            ;; => (ok true)
(fs/resolve-path "/srv" "app" "src")               ;; => (ok "/srv/app/src")
(fs/find-files "/srv/app" #{"clj" "cljc"} {:max-depth 3})
;; => (ok ["/srv/app/src/a.clj" …])   — prunes heavy dirs and hidden entries

(fsys/mkdirs! "/srv/app/target")
(fsys/atomic-write! "/srv/app/state.edn" (pr-str state) {})
(fsys/lock! "/srv/app/.lock" 5000)
(fsys/watch! "/srv/app" ["*.clj"] handler)
```

`find-files` is interrupt-aware: on an interrupted thread it terminates and
leaves the interrupt flag **set**, so the caller still observes its own
cancellation.

## Processes

```clojure
(require '[hive-system.process.core :as proc]
         '[hive-system.process.liveness :as liveness]
         '[hive-system.process.tree :as tree])
```

- `process.core` — `IProcess` over `ProcessBuilder` / `ProcessHandle`.
- `process.liveness` — one definition of "is this pid alive?" for the whole
  ecosystem.
- `process.tree` — destroy a process **together with everything it spawned**.
- `process.streams` — read a child's output without blocking on its descendants.
- `process.worker` — `IWorker`: newline-delimited EDN request/response over a
  long-lived process, single-flight through a hive-weave gate, timeout-bounded
  reads.

## Crypto

`crypto.core` is a plain-fn DSL over `ICrypto`. Parameter-object style: one map,
keyed under `:crypto/*`, carrying the adapter as `:crypto/adapter`.

```clojure
(require '[hive-system.crypto.core :as crypto]
         '[hive-system.crypto.tink :as tink])

(let [c  (tink/->tink-crypto)
      k  (crypto/random-key)]                    ;; 32-byte XChaCha20 key
  (crypto/aead-seal! #:crypto{:adapter c :key k :plaintext bs :aad ctx}))
;; => (ok #:crypto{:ciphertext #bytes :iv #bytes})
```

Surface: `random-key`, `random-nonce`, `random-x25519-keypair`,
`random-ed25519-keypair`, `aead-seal!` / `aead-open!`, `hpke-seal!` /
`hpke-open!`, `sha256`, `sign!` / `verify`, `kdf-hkdf-sha256`,
`pwhash-argon2id`. `crypto.macros/let-aead` folds the sealing ceremony.

Two adapters implement the same contract — `crypto.tink` (pure Java) and
`crypto.caesium` (libsodium). `crypto.kdf` is shared between them so
`crypto-derive-key` returns byte-identical output whichever one resolves the
call. `crypto.ed25519-der` handles PKCS#8 / X.509 key encodings, and
`crypto.signer` exposes an `hive-spi.crypto.ports/ISigner` backed by whichever
`ICrypto` the host already built.

## Secrets and redaction

A `Secret` is opaque: printing, `pr-str`-ing or logging it yields a label, never
the value. Unwrapping is explicit and scoped.

```clojure
(require '[hive-dsl.result :as r]
         '[hive-system.secrets.core :as secrets]
         '[hive-system.secrets.registry :as backends]
         '[hive-system.secrets.pass :as pass])

(backends/register! (pass/make-pass-backend))

(r/let-ok [s (backends/fetch {:backend :pass :key "hive/api-key"})]
  (secrets/with-secret [k s]
    (r/ok (call-api k))))
```

A `Secret` overrides `toString` and registers `print-method`, `print-dup` and a
pprint dispatch, so it stays redacted in log lines and exception messages too:

```clojure
(pr-str (secrets/make-secret "hunter2" :literal "demo/key"))
;; => "#<Secret :literal:demo/key redacted>"
```

`backends/registered`, `backend`, `unregister!` and the pure `validate-ref`
round out the registry. `secrets.core/make-secret` wraps a value you already
hold; `secret?` tests one.

`redaction` is the surface that keeps sensitive material out of a debug dump or
an AI assistant's context:

- `redaction.tainted` — `taint` / `untaint` / `tainted?` / `token`. A tainted
  value prints as a stable per-run hash token, so its *presence and identity*
  stay observable while the value never is:

  ```clojure
  (let [t (tainted/taint "s3cr3t" :env)]
    [(pr-str t)          ;; => "<redacted src=:env h=#ab5a>"
     (tainted/token t)]) ;; => "<env:#ab5a>"
  ```
- `redaction.ssh-argv` — structural redaction of an ssh argv, flag-aware, with
  the argv's length preserved.
- `redaction.core` — the rule registry (`register-rule!`) plus the walker that
  applies every rule to arbitrarily nested data.

## Dependency ensurer

Compose `IShell` + `IDistroDetector` + `IPackageInstaller` into one `ensure!`
verb that installs what is missing and reports what it did.

```clojure
(require '[hive-system.deps.registry :as deps]
         '[hive-system.protocols :as proto])

(proto/ensure! (deps/default-ensurer)
               [{:cmd "rg" :pkg {:apt "ripgrep" :pacman "ripgrep" :dnf "ripgrep"}
                 :on-missing :auto}
                {:cmd "fd" :pkg {:apt "fd-find" :pacman "fd" :dnf "fd-find"}
                 :on-missing :ask}])
;; => (ok {:installed [...] :already-present [...] :failed [...] :distro …})
```

`:on-missing` is `:auto` (install, then re-verify), `:ask` (consult the injected
`prompt-fn`) or `:throw` (report `:deps/missing`, install nothing). The summary
is always `ok` — individual failures land in `:failed`; the wrapper is `err`
only when the whole computation could not run.

## GPU

`IGpuExecutor` / `IGpuStatus` are the DIP boundary for GPU-bound work:
`gpu.ollama/ollama-executor` speaks the ollama HTTP API, and
`gpu.probe/nvidia-smi-probe` reports device state by parsing `nvidia-smi` CSV.

## Events

`events.system` wires the system operations onto
[hive-events](https://github.com/hive-agi/hive-events) — `init!`, `shutdown!`
and `dispatch-result` — with reusable interceptors in `events.interceptors`.

## Status

Three contracts are declared without an implementation in this repo. They are
listed here so nobody discovers it at runtime:

- **`IJournal`.** `temporal/journal.clj` holds the intended Datahike schema
  (`:op/tx-time`, `:op/valid-time`, `:op/type`, `:op/input`, `:op/output`,
  `:op/duration-ms`, `:op/success?`, `:op/caller`, `:op/session`,
  `:op/causal-prev`) and a TODO where the connection, schema install and
  protocol methods go. **Nothing journals yet.**
- **`INetwork`.** The contract is stable; `src/hive_system/network/` is empty.
- **`IHostOSRelease` / `IHostExecutableLookup`.** Primitive capability contracts
  on purpose — endpoint-specific execution and policy live in the projects that
  implement them.

## Tests

```
clj -M:test
```

387 tests / 1706 assertions across 37 namespaces, driven by
[hive-test](https://github.com/hive-agi/hive-test) and
[hive-schemas](https://github.com/hive-agi/hive-schemas): conformance, golden,
property (`defprop-total`, `defprop-metamorphic`) and mutation facets, with
value-object schemas imported from `src/` rather than redeclared in the suite.

## Releasing

Versioning and publishing are delegated to
[hive-build](https://github.com/hive-agi/hive-build) — this repo carries no
`build.clj` to drift. Coordinates come from `version.edn`, the version from
`VERSION`:

```
clojure -T:build jar             # source jar + pom
clojure -T:build install         # build + install into ~/.m2
clojure -T:build kondo           # sync dependency-exported lint configs, then lint
clojure -T:build bump :level :patch
clojure -T:build deploy          # publish per version.edn :publish (:clojars)
```

`.github/workflows/release.yml` runs that flow on every push to `main` touching
`src/**`, `resources/**` or `deps.edn`: bump patch, commit
`chore(release): $VER [skip ci]`, annotated tag `v$VER`, push with
`--follow-tags`, deploy to Clojars. Docs- and test-only commits do not mint a
version, because a published pom is immutable.
