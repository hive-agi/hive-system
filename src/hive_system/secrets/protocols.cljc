(ns hive-system.secrets.protocols
  "Protocols for the secrets subsystem.

   ## ISP boundary

   `ISecretBackend` is the DIP seam between consumers (probe, hive-mcp,
   etc.) and concrete secret stores (GNU pass, Bitwarden CLI, 1Password,
   Vault, age-encrypted files, etc.).

   New backends implement this protocol; consumers depend only on the
   protocol. No call site needs to change to swap or add backends.

   ## Backend contract

   A backend MUST:
   - Return `Result<Secret>` from `fetch` — never raw values, never
     plaintext bound in a map outside the Secret type.
   - Surface `:line-only?` and `:timeout-ms` opts (may ignore others).
   - Report `available?` cheaply (no network round-trip if avoidable).
   - Use a stable, namespaced `backend-id` keyword (e.g. `:pass`,
     `:bw`, `:op`, `:vault`, `:age`)."
  )

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: AGPL-3.0-or-later

(defprotocol ISecretBackend
  "A pluggable secret store. Implementations might wrap GNU pass,
   Bitwarden, 1Password, Vault, age-encrypted files, etc."
  (backend-id [this]
    "Keyword identifying this backend (e.g. :pass, :bw, :op, :vault, :age).
     MUST be stable and unique within a process.")
  (fetch [this key opts]
    "Resolve `key` to a Secret. Returns Result<Secret>.

     opts (all optional):
       :line-only?  — if true, return only the first non-empty line
       :timeout-ms  — resolution timeout (default backend-specific)

     Errors are namespaced under the backend (e.g. :pass/not-found,
     :bw/locked, :vault/permission-denied) — never leak the resolved
     value into the error payload.")
  (available? [this]
    "Returns Result<bool> indicating whether the backend is usable
     right now. Should be cheap (no remote calls if possible)."))
