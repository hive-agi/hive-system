(ns hive-system.secrets.core
  "Opaque secret container for credentials, keys, and other sensitive values.

   ## Purpose

   Carry sensitive values through the system without leaking them via
   logs, REPL output, exception traces, pretty-printers, or accidental
   stdout. Unwrapping requires an explicit `expose` call — auditable,
   greppable, intentional.

   ## Type

   `Secret` is a deftype (not defrecord) — it is intentionally NOT a map.
   Keyword lookup (`(:value s)`), `get`, and map destructuring all return
   nil. The underlying field is reachable only via Java interop
   (`(.value s)`), which is greppable and easy to ban via lint.

   ## Audit surface

   - `expose` — the ONE blessed unwrap. Every call site is a leak risk.
   - `(.value <Secret>)` — interop escape hatch; ban in lint.

   ## Print safety

   Registered for `print-method`, `print-dup`, and `clojure.pprint/simple-dispatch`.
   `toString` overrides Object — covers exception messages, log lines.
   Hash is constant (0); equality is constant-time. Never serializable.

   ## Non-goals (v1)

   - Secure memory wiping. JVM strings cannot be reliably zeroed; this
     would be theater for SSH-pass / API-token use cases. Use char[]
     wrappers if you need defense against heap dumps.
   - Encryption at rest. This wraps live values in memory, not storage."
  (:refer-clojure :exclude [expose])
  (:import [java.security MessageDigest]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: AGPL-3.0-or-later

;; =============================================================================
;; Protocol
;; =============================================================================

(defprotocol ISecret
  "Opaque carrier for sensitive values."
  (expose [s]
    "Unwrap the secret value. AUDIT: every call site is a leak risk.
     Prefer scoping unwrap to the smallest possible block.")
  (secret-source [s]
    "Return the source label (e.g. :pass, :env, :keyfile, :literal).
     Non-sensitive — safe to log.")
  (secret-key [s]
    "Return the lookup key (e.g. \"vps/r1/root\"). Non-sensitive —
     safe to log. May be nil for unkeyed secrets."))

;; =============================================================================
;; Secret type
;; =============================================================================

(deftype Secret [value source key]
  ISecret
  (expose [_] value)
  (secret-source [_] source)
  (secret-key [_] key)

  Object
  (toString [_]
    (str "#<Secret " source
         (when key (str ":" key))
         " redacted>"))

  (hashCode [_]
    ;; Constant hash — never leak content via hashCode probe, never
    ;; allow accidental cache-key partitioning by value.
    0)

  (equals [_ other]
    (and (satisfies? ISecret other)
         (let [a (.getBytes ^String value "UTF-8")
               b (.getBytes ^String (expose other) "UTF-8")]
           (and (= (alength a) (alength b))
                (MessageDigest/isEqual a b))))))

;; =============================================================================
;; Print method registration — every printer must redact
;; =============================================================================

(defmethod print-method Secret [^Secret s ^java.io.Writer w]
  (.write w (.toString s)))

(defmethod print-dup Secret [^Secret s ^java.io.Writer w]
  ;; print-dup intentionally rejects round-trip; you cannot reconstruct
  ;; a Secret from its printed form.
  (.write w (.toString s)))

;; pprint dispatch — register lazily so we don't pull in clojure.pprint
;; for callers that never use it.
(defn- install-pprint-dispatch! []
  (when-let [pp (try (require 'clojure.pprint) true (catch Exception _ nil))]
    (let [simple-dispatch (resolve 'clojure.pprint/simple-dispatch)
          add-method      (resolve 'clojure.pprint/use-method)]
      (when (and simple-dispatch add-method)
        ((deref add-method) (deref simple-dispatch) Secret
         (fn [^Secret s] (print (.toString s))))))
    pp))

(install-pprint-dispatch!)

;; =============================================================================
;; Constructors / predicates
;; =============================================================================

(defn make-secret
  "Wrap a raw value in a Secret.

   value  — the sensitive value (typically a String)
   source — label for the source (:pass, :env, :keyfile, :literal, etc.)
   key    — the lookup key used to retrieve it (e.g. \"vps/r1/root\"),
            or nil if not applicable.

   Returns a Secret instance."
  ([value source]
   (make-secret value source nil))
  ([value source key]
   (Secret. value source key)))

(defn secret?
  "Truthy if x is an ISecret instance."
  [x]
  (satisfies? ISecret x))

;; =============================================================================
;; Macro: with-secret — scoped unwrap
;; =============================================================================

(defmacro with-secret
  "Bind the unwrapped value of `secret` to `binding` for the duration of
   `body`. Encourages narrow unwrap scope.

   (with-secret [pwd my-secret]
     (do-something-with pwd))"
  [[binding secret] & body]
  `(let [~binding (expose ~secret)]
     ~@body))
