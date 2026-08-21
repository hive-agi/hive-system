(ns hive-system.pattern.registry
  "Engine and named-pattern registries — the DIP swap points.

   Two open sets, two registries:

     engines   id -> IPatternEngine   ;; how to match
     patterns  id -> Pattern          ;; what to look for

   A consumer names a pattern (`:audit/readiness-probe`) instead of carrying a
   literal expression, so one definition serves every call site and a fix lands
   in one place. `resolve-pattern` is PURE — the index is an argument, which is
   what makes it testable and what lets a caller run against a private index."
  (:require [hive-dsl.result :as r]
            [hive-system.pattern.protocols :as proto]
            [hive-system.pattern.schema :as ps]
            [malli.core :as m]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(defonce ^:private engines* (atom {}))

(defonce ^:private patterns* (atom {}))

;;; =============================================================================
;;; Engines
;;; =============================================================================

(defn register-engine!
  "Register ENGINE under its engine-id, replacing any prior one. Returns it."
  [engine]
  (swap! engines* assoc (proto/engine-id engine) engine)
  engine)

(defn unregister-engine!
  "Drop the engine registered under ID. Returns it, or nil."
  [id]
  (let [prev (get @engines* id)]
    (swap! engines* dissoc id)
    prev))

(defn registered-engines
  "Snapshot of {engine-id -> IPatternEngine}."
  []
  @engines*)

(defn engine
  "Result<IPatternEngine> for ID."
  [id]
  (if-let [e (get @engines* id)]
    (r/ok e)
    (r/err :pattern/unknown-engine {:id id :known (vec (keys @engines*))})))

;;; =============================================================================
;;; Named patterns
;;; =============================================================================

(defn register-pattern!
  "Validate PATTERN and register it under its :pattern/id.
   Returns Result<Pattern>. An invalid pattern is refused, never stored."
  [pattern]
  (cond
    (not (m/validate ps/Pattern pattern))
    (r/err :pattern/invalid {:pattern pattern
                             :explain (m/explain ps/Pattern pattern)})

    (nil? (:pattern/id pattern))
    (r/err :pattern/unnamed {:pattern pattern})

    :else
    (do (swap! patterns* assoc (:pattern/id pattern) pattern)
        (r/ok pattern))))

(defn unregister-pattern!
  "Drop the pattern registered under ID. Returns it, or nil."
  [id]
  (let [prev (get @patterns* id)]
    (swap! patterns* dissoc id)
    prev))

(defn registered-patterns
  "Snapshot of {pattern-id -> Pattern}."
  []
  @patterns*)

(defn resolve-pattern
  "PURE. Result<Pattern> for REF against INDEX: an inline Pattern resolves to
   itself, a keyword to its registration."
  [index ref]
  (cond
    (map? ref)     (r/ok ref)
    (keyword? ref) (if-let [p (get index ref)]
                     (r/ok p)
                     (r/err :pattern/unknown {:id ref :known (vec (keys index))}))
    :else          (r/err :pattern/bad-ref {:ref ref})))

(m/=> resolve-pattern [:=> [:cat ps/PatternIndex ps/PatternRef] :any])

(defn pattern
  "Result<Pattern> for REF against the live index."
  [ref]
  (resolve-pattern @patterns* ref))
