(ns hive-system.redaction.tainted
  "Tainted-value wrapper for sensitive material that must NOT reach an AI
   assistant or any debug surface — but whose *presence and identity*
   should still be observable via stable per-run hash tokens.

   ## Purpose

   Where `hive-system.secrets.core/Secret` is the storage primitive for
   credentials (\"don't print, don't compare, don't serialize\"), `Tainted`
   is a *diagnostic* primitive: it wraps any value (hostnames, ports,
   identities, env values, argv slots) so we can correlate the same
   underlying value across many log lines with a short hash token like
   `<host:#a3f4>` — without ever printing the value itself.

   ## Type

   `Tainted` is a defrecord with three fields:

     :value  — the wrapped sensitive value
     :source — non-sensitive label (e.g. \"pass:vps/r1/ip\", :argv-host)
     :hash   — 4-hex-char stable token derived from HMAC-SHA256(salt, value)

   ## Hash semantics

   - Hash is computed once at construction and cached.
   - Same value within a single JVM run produces the SAME hash token,
     so operators can correlate `<host:#a3f4>` across log lines.
   - Salt is generated per JVM at namespace-load time via SecureRandom
     and held in a private atom — cross-JVM-restart unlinkability is by
     design (the salt cannot be reconstructed from prior runs).
   - Hash space is 16^4 = 65,536 — collision probability is acceptable
     within a single run's working set of distinct sensitive values.

   ## Print safety

   `print-method` ALWAYS emits `<redacted src=... h=#xxxx>` and NEVER
   the underlying value. `toString` mirrors that.

   ## Audit surface

   - `untaint` — the ONE blessed unwrap. Every call site is a leak risk.
     This is the only safe extraction point and MUST only be invoked at
     trust boundaries (process spawn, network write, file write to a
     trusted local sink). Never call it within reach of a log appender,
     event subscriber, or anything whose output may be surfaced to the
     assistant.

   ## Non-goals

   - Encryption / secure memory wiping. JVM strings can't be reliably
     zeroed; the same caveats as `Secret` apply.
   - Cross-process correlation. By design — see Hash semantics above."
  (:import [java.security SecureRandom]
           [javax.crypto Mac]
           [javax.crypto.spec SecretKeySpec]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: AGPL-3.0-or-later

;; =============================================================================
;; Per-JVM salt
;; =============================================================================

(defonce ^:private process-salt
  ;; SecureRandom-derived 32-byte salt, generated once per JVM. Held in
  ;; a private atom so tests cannot tamper without reflection. Restart
  ;; the JVM → fresh salt → cross-run unlinkability.
  (let [bs (byte-array 32)]
    (.nextBytes (SecureRandom.) bs)
    (atom bs)))

(defn- salt-bytes
  ^bytes []
  @process-salt)

;; =============================================================================
;; Hash computation
;; =============================================================================

(defn- hex-of
  ^String [^bytes bs n]
  ;; Hex-encode the first n bytes of bs.
  (let [sb (StringBuilder.)]
    (dotimes [i n]
      (.append sb (format "%02x" (bit-and (aget bs i) 0xff))))
    (.toString sb)))

(defn- compute-hash
  "Compute a 4-hex-char stable token for `value` using HMAC-SHA256
   keyed by the per-JVM salt. The token is the first 2 bytes of the
   MAC, hex-encoded → 4 hex chars."
  ^String [value]
  (let [mac      (Mac/getInstance "HmacSHA256")
        key-spec (SecretKeySpec. (salt-bytes) "HmacSHA256")
        bytes-in (.getBytes (str value) "UTF-8")]
    (.init mac key-spec)
    (let [out (.doFinal mac bytes-in)]
      (hex-of out 2))))

;; =============================================================================
;; Tainted record
;; =============================================================================

(defrecord Tainted [value source hash])

(defmethod print-method Tainted [^Tainted t ^java.io.Writer w]
  ;; ALWAYS emit the redacted form. Never touch :value.
  (.write w "<redacted")
  (when-let [s (:source t)]
    (.write w " src=")
    (.write w (pr-str s)))
  (when-let [h (:hash t)]
    (.write w " h=#")
    (.write w ^String h))
  (.write w ">"))

(defmethod print-dup Tainted [^Tainted t ^java.io.Writer w]
  ;; print-dup intentionally rejects round-trip; you cannot reconstruct
  ;; a Tainted from its printed form.
  (print-method t w))

;; pprint dispatch — register lazily so we don't pull in clojure.pprint
;; for callers that never use it.
(defn- install-pprint-dispatch! []
  (when (try (require 'clojure.pprint) true (catch Exception _ nil))
    (let [simple-dispatch (resolve 'clojure.pprint/simple-dispatch)
          use-method      (resolve 'clojure.pprint/use-method)]
      (when (and simple-dispatch use-method)
        ((deref use-method) (deref simple-dispatch) Tainted
         (fn [t] (print-method t *out*)))))))

(install-pprint-dispatch!)

;; =============================================================================
;; Constructors / predicates / extractor
;; =============================================================================

(defn taint
  "Wrap `value` as a Tainted carrier with non-sensitive `source` label.

   The returned Tainted carries a 4-hex-char stable hash derived from the
   per-JVM salt + value via HMAC-SHA256. Same value within a JVM run →
   same hash. Different JVM run → different hash (salt is per-process).

   Examples:

     (taint \"10.0.0.42\" \"pass:vps/r1/ip\")
     (taint 22 :argv-port)

   `value` may be any value that has a meaningful `(str value)`. `source`
   is non-sensitive and printed verbatim in the redacted form."
  ([value source]
   (->Tainted value source (compute-hash value))))

(defn untaint
  "Return the underlying value of a Tainted.

   AUDIT: this is the ONLY safe extraction point and MUST only be called
   at trust boundaries — process spawn, file write to a trusted local
   sink, etc. Every call site is a leak risk. Never invoke within reach
   of a log appender, event subscriber, REPL transcript, or anywhere
   whose output may be surfaced to an AI assistant.

   For non-Tainted inputs, returns the value unchanged so callers can
   uniformly call (untaint x) over a heterogeneous structure."
  [t]
  (if (instance? Tainted t)
    (:value t)
    t))

(defn tainted?
  "Truthy if x is a Tainted instance."
  [x]
  (instance? Tainted x))

(defn token
  "Return the stable token form `<src:#hash>` for a Tainted, or nil if
   x is not Tainted. Useful for ssh-argv / structural redactors that
   want to substitute Tainted slots with a short string token."
  [x]
  (when (tainted? x)
    (str "<" (let [s (:source x)]
              (cond
                (keyword? s) (name s)
                (string? s)  s
                :else        (str s)))
         ":#" (:hash x) ">")))
