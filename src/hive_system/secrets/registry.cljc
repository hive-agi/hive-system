(ns hive-system.secrets.registry
  "Backend registry + uniform resolution for ISecretBackend implementations.

   Consumers depend on this ns + protocols.clj. They never need to know
   which concrete backend (`pass`, `bw`, `op`, `vault`, `age`) is in use.

   ## Workflow

   1. At process boot, register the backends you need:
        (registry/register! (pass/make-pass-backend))
        (registry/register! (bw/make-bw-backend {:session ...}))

   2. At call sites, resolve via a SecretRef map:
        (registry/fetch {:backend :pass :key \"vps/r1/root\"})
        (registry/fetch {:backend :pass :key \"vps/r1/ip\" :opts {:line-only? true}})

      Returns Result<Secret>.

   ## SecretRef shape

   {:backend  <keyword>     ;; backend-id (e.g. :pass, :bw)
    :key      <string>      ;; opaque key passed to the backend
    :opts     <map?>}       ;; optional per-fetch opts

   ## Validation

   `validate-ref` checks structure WITHOUT touching the backend — pure,
   safe to run during config loading."
  (:require [hive-dsl.result :as r :refer [let-ok]]
            [hive-system.secrets.protocols :as proto]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: AGPL-3.0-or-later

(defonce ^:private backends (atom {}))

(defn register!
  "Register a backend instance under its backend-id.
   Returns the backend (for fluent registration chains).
   Overwrites any existing registration with the same id."
  [backend]
  (let [id (proto/backend-id backend)]
    (swap! backends assoc id backend)
    backend))

(defn unregister!
  "Remove a backend by id. Returns the previously-registered backend
   or nil. Useful for tests."
  [id]
  (let [prev (get @backends id)]
    (swap! backends dissoc id)
    prev))

(defn registered
  "Return a map of {backend-id → backend} for all currently registered
   backends. Snapshot — safe to inspect."
  []
  @backends)

(defn backend
  "Look up a registered backend by id. Returns Result<ISecretBackend>."
  [id]
  (if-let [b (get @backends id)]
    (r/ok b)
    (r/err :secrets/unknown-backend
           {:id id :known (vec (keys @backends))})))

;; =============================================================================
;; SecretRef validation
;; =============================================================================

(defn validate-ref
  "Pure: validate a SecretRef map without resolving anything.
   Returns (ok ref) or (err :secrets/invalid-ref ...)."
  [{:keys [backend key opts] :as ref}]
  (cond
    (not (keyword? backend))
    (r/err :secrets/invalid-ref
           {:reason "missing or non-keyword :backend" :ref ref})

    (not (string? key))
    (r/err :secrets/invalid-ref
           {:reason "missing or non-string :key" :ref ref})

    (and opts (not (map? opts)))
    (r/err :secrets/invalid-ref
           {:reason "non-map :opts" :ref ref})

    :else (r/ok ref)))

;; =============================================================================
;; Fetch
;; =============================================================================

(defn fetch
  "Resolve a SecretRef to a Secret. Returns Result<Secret>.

   Validates the ref structure, looks up the backend, and dispatches.
   Any of these stages can short-circuit with an err result."
  [ref]
  (let-ok [valid (validate-ref ref)
           b     (backend (:backend valid))]
    (proto/fetch b (:key valid) (or (:opts valid) {}))))
