(ns hive-system.pattern.construct.dialect
  "The DIP swap point: a regex target language as data, plus the one gate every
   emitter passes through.

   ## The substitutability contract

   For a Construct a dialect cannot express, `emit` returns
   `(r/err :construct/unsupported …)`. It NEVER emits an approximation and never
   drops a node. A `:lookahead` quietly discarded for RE2 produces a DIFFERENT
   LANGUAGE that still compiles and still returns hits — the worst outcome
   available, because nothing reports it.

   ## Why the gate is here and not in the emitter

   `emit` is a plain function that checks capabilities and THEN calls
   `-render`. An implementation supplies rendering only; it cannot skip,
   weaken or forget the check, because it never sees it. One definition, N
   implementations.

   The dialect profile is an ARGUMENT throughout — resolved from the registry
   at call time, never captured at wiring time."
  (:require [hive-dsl.result :as r]
            [hive-system.pattern.construct.core :as cc]
            [hive-system.pattern.construct.schema :as cs]
            [malli.core :as m]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(defprotocol IConstructEmitter
  "Renders a Construct the caller has already been cleared to emit.

   Implementations do NOT gate — `emit` does that before calling here."
  (dialect [this]
    "The Dialect this emitter renders for.")
  (-render [this construct]
    "Result<String>: CONSTRUCT as a regex source string in this dialect."))

;;; =============================================================================
;;; Registry
;;; =============================================================================

(defonce ^:private emitters* (atom {}))

(defn register-emitter!
  "Register EMITTER under its dialect id, replacing any prior one. Returns it.
   A profile that does not conform to the Dialect schema is refused."
  [emitter]
  (let [d (dialect emitter)]
    (if (m/validate cs/Dialect d)
      (do (swap! emitters* assoc (:dialect/id d) emitter)
          (r/ok emitter))
      (r/err :dialect/invalid {:dialect d :explain (m/explain cs/Dialect d)}))))

(defn unregister-emitter!
  "Drop the emitter registered under ID. Returns it, or nil."
  [id]
  (let [prev (get @emitters* id)]
    (swap! emitters* dissoc id)
    prev))

(defn registered-emitters
  "Snapshot of {dialect-id -> IConstructEmitter}."
  []
  @emitters*)

(defn emitter
  "Result<IConstructEmitter> for ID."
  [id]
  (if-let [e (get @emitters* id)]
    (r/ok e)
    (r/err :dialect/unknown {:id id :known (vec (keys @emitters*))})))

;;; =============================================================================
;;; The gate — pure, and the only place support is decided
;;; =============================================================================

(defn missing-capabilities
  "What CONSTRUCT needs that DIALECT does not provide. Empty = emittable."
  [dialect construct]
  (into (sorted-set)
        (remove (:dialect/capabilities dialect))
        (cc/required-capabilities construct)))

(m/=> missing-capabilities [:=> [:cat cs/Dialect cs/Construct] cs/Capabilities])

(defn supports?
  "Can DIALECT express CONSTRUCT? Decided from the shape — no compile."
  [dialect construct]
  (empty? (missing-capabilities dialect construct)))

(m/=> supports? [:=> [:cat cs/Dialect cs/Construct] :boolean])

;;; =============================================================================
;;; Emission
;;; =============================================================================

(defn emit
  "Result<String> for CONSTRUCT under EMITTER's dialect.

   Refuses — with the missing capabilities named — rather than approximating."
  [emitter construct]
  (let [d       (dialect emitter)
        missing (missing-capabilities d construct)]
    (if (seq missing)
      (r/err :construct/unsupported
             {:dialect  (:dialect/id d)
              :missing  (vec missing)
              :provides (vec (sort (:dialect/capabilities d)))})
      (-render emitter construct))))

(defn emit-as
  "Result<String> for CONSTRUCT under the dialect registered as DIALECT-ID."
  [dialect-id construct]
  (r/let-ok [e (emitter dialect-id)]
            (emit e construct)))
