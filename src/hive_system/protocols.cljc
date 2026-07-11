(ns hive-system.protocols
  "Core protocols for hive-system.

   Layer 1: IJournal — temporal execution fabric (Datahike/Proximum)
   Layer 2: System operation protocols (IProcess, INetwork, IFilesystem, etc.)

   Every system operation returns Result (ok/err) from hive-dsl.
   Every Result is journaled with bitemporal semantics.

   SOLID-D: All consumers depend on these protocols, never concrete implementations.
   SOLID-O: New operation types = new protocol implementations, zero changes to journal.")

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: AGPL-3.0-or-later

;; =============================================================================
;; Layer 1: Temporal Execution Journal
;; =============================================================================

(defprotocol IJournal
  "Bitemporal execution journal backed by Datahike/Proximum.
   All system operations are journaled here for time-travel queries."
  (journal-id [this] "Return keyword identifying this journal backend.")
  (record! [this op-type input output duration-ms ctx]
    "Record an operation execution. Returns entry-id.")
  (query-at [this datalog-query as-of-tx]
    "Query journal state as of a specific transaction time.")
  (query-between [this datalog-query from-tx to-tx]
    "Query journal entries between two transaction times.")
  (time-travel [this entity-id as-of-tx]
    "Get entity state at a specific point in time."))

;; =============================================================================
;; Layer 2: System Operation Protocols
;; =============================================================================

(defprotocol IProcess
  "Process lifecycle management. All operations return Result."
  (process-spawn! [this cmd opts]
    "Spawn a process. Returns Result with {:pid :process :stdout :stderr}.")
  (process-wait! [this process timeout-ms]
    "Wait for process completion. Returns Result with {:exit-code :stdout :stderr}.")
  (process-signal! [this process signal]
    "Send signal to process. Returns Result.")
  (process-pipe! [this from-process to-process]
    "Pipe stdout of one process to stdin of another. Returns Result."))

(defprotocol IWorker
  "Warm request/response worker over a long-lived process (IProcess).
   All operations return Result."
  (worker-call! [this request timeout-ms]
    "Send a framed request, read one framed response. Returns Result.")
  (worker-health [this]
    "Worker process liveness. Returns Result.")
  (worker-stop! [this]
    "Stop the worker and release its process. Returns Result."))

(defprotocol INetwork
  "Network operations. All operations return Result."
  (net-connect! [this host port opts]
    "Open a connection. Returns Result with {:socket :channel}.")
  (net-listen! [this port opts]
    "Listen on port. Returns Result with {:server-socket}.")
  (net-send! [this channel data]
    "Send data on channel. Returns Result with {:bytes-sent}.")
  (net-recv! [this channel buf-size timeout-ms]
    "Receive data. Returns Result with {:data :bytes-read}."))

(defprotocol IFilesystem
  "Advanced filesystem operations beyond basic read/write."
  (fs-watch! [this path patterns handler]
    "Watch path for changes. Returns Result with {:watcher}.")
  (fs-atomic-write! [this path content opts]
    "Atomic write (write-to-tmp + rename). Returns Result.")
  (fs-lock! [this path timeout-ms]
    "Advisory file lock. Returns Result with {:lock}.")
  (fs-tmpdir! [this prefix]
    "Create temporary directory. Returns Result with {:path}."))

(defprotocol IPathQuery
  "Path predicates and resolution. Pure queries — no mutation.
   SRP: separated from IFilesystem (which handles watch/write/lock).
   All return Result for railway composition via ok->/let-ok."
  (path-exists? [this path]
    "Check path existence. Returns Result<boolean>.")
  (path-directory? [this path]
    "Check if path is directory. Returns Result<boolean>.")
  (path-file? [this path]
    "Check if path is regular file. Returns Result<boolean>.")
  (path-absolute? [this path]
    "Check if path is absolute. Returns Result<boolean> (pure, no IO).")
  (path-resolve [this base segments]
    "Join + normalize path segments. Returns Result<string>.")
  (path-children [this dir opts]
    "List immediate children. opts: {:filter :dirs|:files|:all, :skip #{names}}.
     Returns Result<vec<string>>."))

(defprotocol IShell
  "Shell execution with capture."
  (shell-exec! [this cmd opts]
    "Execute shell command. Returns Result with {:exit :stdout :stderr :duration-ms}.")
  (shell-env [this]
    "Get current environment map.")
  (shell-which [this program]
    "Resolve program path. Returns Result with {:path} or err."))


(defprotocol IHostOSRelease
  "Read host operating-system release identity.

   Primitive host capability contract. Endpoint-specific execution and policy
   live in higher-level general projects that implement this protocol."
  (host-os-release [this opts]
    "Return Result<{:id :version-id :pretty-name :raw}> from /etc/os-release or equivalent."))


(defprotocol IHostExecutableLookup
  "Resolve executable availability on a host.

   Primitive host capability contract. Batch discovery and package-manager
   interpretation compose above this protocol."
  (host-executable [this program opts]
    "Return Result<{:program :present? :path?}> for one executable."))

(defprotocol ICrypto
  "Cryptographic operations.

   Each method takes a single map (Parameter Object pattern) keyed under
   the `:crypto/*` namespace. Returns hive-dsl Result.

   Common keys:
     :crypto/algorithm   keyword       — :xchacha20-poly1305, :hpke-x25519, :sha256,
                                         :hkdf-sha256, :argon2id, ...
     :crypto/key         ^bytes        — symmetric key (32B AEAD) or signing key
     :crypto/pubkey      ^bytes        — recipient public key (HPKE seal)
     :crypto/keypair     {:public :private} — HPKE open
     :crypto/plaintext   ^bytes
     :crypto/ciphertext  ^bytes
     :crypto/iv          ^bytes        — nonce / IV (24B XChaCha20)
     :crypto/aad         ^bytes        — additional authenticated data / contextInfo
     :crypto/data        ^bytes        — hash / sign / verify input
     :crypto/signature   ^bytes        — verify input
     :crypto/ikm         ^bytes        — input keying material (KDF)
     :crypto/salt        ^bytes-or-nil — KDF salt / pwhash salt (16B for Argon2id)
     :crypto/info        ^bytes-or-nil — HKDF context/info string (RFC 5869)
     :crypto/length      pos-int       — desired output bytes (KDF / pwhash)
     :crypto/password    ^bytes        — password to hash (pwhash)
     :crypto/ops-limit   pos-int       — pwhash CPU cost (libsodium t_cost)
     :crypto/mem-limit   pos-int       — pwhash memory cost in bytes (libsodium memlimit)

   Result shapes (also `:crypto/*` namespaced):
     encrypt      → {:ok {:crypto/ciphertext ... :crypto/iv ...}}
     decrypt      → {:ok {:crypto/plaintext ...}}
     hash         → {:ok {:crypto/hash ... :crypto/algorithm ...}}
     sign         → {:ok {:crypto/signature ...}}
     verify       → {:ok {:crypto/valid? boolean}}
     derive-key   → {:ok {:crypto/key ^bytes :crypto/algorithm ...}}
     password-hash → {:ok {:crypto/hash ^bytes :crypto/algorithm ...}}"
  (crypto-hash [this op-map]
    "Hash :crypto/data with :crypto/algorithm.")
  (crypto-sign! [this op-map]
    "Sign :crypto/data with :crypto/key.")
  (crypto-verify [this op-map]
    "Verify :crypto/signature against :crypto/data with :crypto/key.")
  (crypto-encrypt! [this op-map]
    "Encrypt :crypto/plaintext under :crypto/key (or :crypto/pubkey for HPKE).")
  (crypto-decrypt! [this op-map]
    "Decrypt :crypto/ciphertext under :crypto/key (or :crypto/keypair for HPKE).")
  (crypto-derive-key [this op-map]
    "Derive a key from :crypto/ikm with :crypto/algorithm (e.g. :hkdf-sha256).
     Inputs: :crypto/ikm :crypto/salt :crypto/info :crypto/length.
     Returns Result<{:crypto/key ^bytes :crypto/algorithm ...}>.")
  (crypto-password-hash [this op-map]
    "Password-hash :crypto/password with :crypto/algorithm (e.g. :argon2id).
     Inputs: :crypto/password :crypto/salt :crypto/ops-limit :crypto/mem-limit
     :crypto/length. Returns Result<{:crypto/hash ^bytes :crypto/algorithm ...}>."))
