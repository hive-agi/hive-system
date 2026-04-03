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

(defprotocol IShell
  "Shell execution with capture."
  (shell-exec! [this cmd opts]
    "Execute shell command. Returns Result with {:exit :stdout :stderr :duration-ms}.")
  (shell-env [this]
    "Get current environment map.")
  (shell-which [this program]
    "Resolve program path. Returns Result with {:path} or err."))

(defprotocol ICrypto
  "Cryptographic operations."
  (crypto-hash [this algorithm data]
    "Hash data. Returns Result with {:hash :algorithm}.")
  (crypto-sign! [this key data]
    "Sign data. Returns Result with {:signature}.")
  (crypto-verify [this key data signature]
    "Verify signature. Returns Result with {:valid?}.")
  (crypto-encrypt! [this key plaintext opts]
    "Encrypt. Returns Result with {:ciphertext :iv}.")
  (crypto-decrypt! [this key ciphertext opts]
    "Decrypt. Returns Result with {:plaintext}."))
