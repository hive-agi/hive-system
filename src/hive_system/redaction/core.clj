(ns hive-system.redaction.core
  "Redaction registry + walker for safely surfacing structured data
   (compiled plans, event payloads, env maps, log lines) to an AI
   assistant or any debug surface.

   ## Model

   A *rule* is a map:

     {:select  <selector>     ; path-vector OR predicate fn (key,val)→bool
      :replace <fn>           ; (fn [val] -> replacement)
      :id      <keyword>      ; assigned by register-rule!
      :doc     <string?>}

   Rules are stored in a global atom registry. `redact` walks input via
   `clojure.walk/postwalk`, applying matching rules and auto-replacing
   any `Tainted` it encounters with its print-method form.

   ## Selector forms

   - Vector path  — `[:env \"SSHPASS\"]` matches the value at that path
                    inside any nested map.
   - Predicate fn — `(fn [k v] ...)` invoked for every map entry; truthy
                    return → replace the value.

   ## Default rules

   Registered at namespace load time:

     :env/sshpass         → [:env \"SSHPASS\"]        → \"<redacted>\"
     :env/ssh-auth-sock   → [:env \"SSH_AUTH_SOCK\"]  → \"<redacted>\"
     :env/ssh-askpass     → [:env \"SSH_ASKPASS\"]    → \"<redacted>\"
     :env/ssh-private-key → [:env \"SSH_PRIVATE_KEY\"] → \"<redacted>\"

   ## Tainted handling

   Any `Tainted` encountered during the walk is replaced with its
   `pr-str` form (the redacted print-method output) — no rule needed.

   ## Privacy contract

   `redact` never invokes `untaint` and never reads `:value` directly.
   It is safe to compose into a logger appender."
  (:require [hive-system.redaction.tainted :as tainted]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: AGPL-3.0-or-later

;; =============================================================================
;; Registry
;; =============================================================================

(defonce ^:private rules (atom {}))

(defn register-rule!
  "Register a redaction rule under `id`. Overwrites any existing rule
   with the same id. Returns the rule.

   rule shape: {:select <vector-or-fn> :replace <fn> :doc <string?>}"
  [id rule]
  (when-not (keyword? id)
    (throw (ex-info "rule id must be a keyword" {:id id})))
  (when-not (and (map? rule)
                 (contains? rule :select)
                 (fn? (:replace rule)))
    (throw (ex-info "rule must be {:select ... :replace fn}"
                    {:id id :rule rule})))
  (let [stored (assoc rule :id id)]
    (swap! rules assoc id stored)
    stored))

(defn unregister-rule!
  "Remove the rule with the given id. Returns the removed rule or nil."
  [id]
  (let [prev (get @rules id)]
    (swap! rules dissoc id)
    prev))

(defn reset-rules!
  "Clear ALL registered rules (including defaults). Mainly useful for
   tests; production callers should prefer targeted unregister-rule!.
   Returns the previous rule map."
  []
  (let [prev @rules]
    (reset! rules {})
    prev))

(defn registered-rules
  "Snapshot of currently registered rules: {id → rule}."
  []
  @rules)

;; =============================================================================
;; Path-based selector matching
;; =============================================================================

(defn- path-matches?
  "Does the path-vector `select` match the trailing portion of `current-path`?
   Path keys are compared with `=` (handles strings, keywords, ints).
   The selector is matched as a SUFFIX of the current path so rules don't
   need to know the depth at which a target key appears."
  [select current-path]
  (let [n (count select)
        m (count current-path)]
    (and (>= m n)
         (= (vec select) (subvec (vec current-path) (- m n))))))

(defn- apply-rules-at-entry
  "For a single map-entry [k v] at `path`, run every registered rule and
   return the (possibly-replaced) value. The first matching rule wins;
   stable order via the rule registry's iteration order is not
   guaranteed across JVM versions, so callers should design rules to be
   non-overlapping."
  [path k v rule-coll]
  (loop [[r & more] rule-coll
         current     v]
    (if (nil? r)
      current
      (let [sel    (:select r)
            match? (cond
                     (vector? sel)
                     (path-matches? sel (conj (vec path) k))

                     (fn? sel)
                     (sel k current)

                     :else false)]
        (if match?
          ((:replace r) current)
          (recur more current))))))

;; =============================================================================
;; Walk
;; =============================================================================

(defn- redact-value
  "If x is a Tainted, replace with its printed (redacted) form.
   Otherwise return x unchanged."
  [x]
  (if (tainted/tainted? x)
    (pr-str x)
    x))

(defn- walk-with-rules
  "Walk `data` applying `rule-coll` at each map entry, plus auto-replacing
   any Tainted via redact-value. Path-tracking is done by descending
   manually through maps; non-map collections are walked via postwalk
   for Tainted replacement only.

   Tainted is checked FIRST at every node so we never descend into its
   fields (defrecords are maps under the hood — descending would expose
   :value, and `empty` on a record is unsupported anyway)."
  [rule-coll data]
  (letfn [(descend [path node]
            (cond
              ;; Replace Tainted before any structural inspection so we
              ;; never read :value via map traversal.
              (tainted/tainted? node)
              (redact-value node)

              ;; Plain hash-maps (NOT records) — descend with path.
              (and (map? node) (not (record? node)))
              (reduce-kv
                (fn [acc k v]
                  (let [child-path (conj path k)
                        v'         (descend child-path v)
                        v''        (apply-rules-at-entry path k v' rule-coll)]
                    (assoc acc k (redact-value v''))))
                (empty node)
                node)

              (vector? node)
              (mapv #(redact-value (descend path %)) node)

              (set? node)
              (into (empty node)
                    (map #(redact-value (descend path %)))
                    node)

              (seq? node)
              (doall (map #(redact-value (descend path %)) node))

              :else
              (redact-value node)))]
    (descend [] data)))

(defn redact
  "Walk `data` and return a redacted structure.

   - Every `Tainted` is replaced with its print-method form (a string
     like `<redacted src=... h=#xxxx>`).
   - Every registered rule whose `:select` matches has its `:replace`
     applied to the matched value.

   Pure: never mutates input, never invokes untaint."
  [data]
  (walk-with-rules (vals @rules) data))

;; =============================================================================
;; Default rules
;; =============================================================================

(def ^:private default-redacted-string "<redacted>")

(defn- env-rule [env-key]
  {:select  [:env env-key]
   :replace (constantly default-redacted-string)
   :doc     (str "Redact env var " env-key)})

(register-rule! :env/sshpass         (env-rule "SSHPASS"))
(register-rule! :env/ssh-auth-sock   (env-rule "SSH_AUTH_SOCK"))
(register-rule! :env/ssh-askpass     (env-rule "SSH_ASKPASS"))
(register-rule! :env/ssh-private-key (env-rule "SSH_PRIVATE_KEY"))

;; =============================================================================
;; Convenience: re-install defaults (for tests after reset-rules!)
;; =============================================================================

(defn install-default-rules!
  "Re-register the default env/* rules. Call after `reset-rules!` in tests
   that want the default surface back."
  []
  (register-rule! :env/sshpass         (env-rule "SSHPASS"))
  (register-rule! :env/ssh-auth-sock   (env-rule "SSH_AUTH_SOCK"))
  (register-rule! :env/ssh-askpass     (env-rule "SSH_ASKPASS"))
  (register-rule! :env/ssh-private-key (env-rule "SSH_PRIVATE_KEY"))
  nil)
