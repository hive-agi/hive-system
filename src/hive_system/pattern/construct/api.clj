(ns hive-system.pattern.construct.api
  "BOUNDARY: write a regex as data, get a Pattern the existing subsystem
   already knows how to run.

     (api/->expr :java [:cat :start [:+ :digit] :end])
     ;; => {:ok \"^\\\\d+$\"}

     (api/register! #:pattern{:id :audit/probe} [:cat \"ready\" [:? \"?\"]])
     (pattern/match? :audit/probe \"ready?\")

   A Construct projects INTO the existing `Pattern` value object rather than
   replacing it: `:pattern/expr` is filled from the construct, `:pattern/construct`
   records what it was built from, and everything downstream — the registry's
   validation, `IPatternEngine`, `match?`, `scan` — is untouched. A pattern
   written as a literal string keeps working exactly as before.

   `register!` goes through `pattern.registry/register-pattern!` so a construct
   that projects to an invalid Pattern is refused at the same gate as every
   other pattern."
  (:require [hive-dsl.result :as r]
            [hive-system.pattern.construct.core :as cc]
            [hive-system.pattern.construct.dialect :as dial]
            [hive-system.pattern.construct.regal]
            [hive-system.pattern.registry :as registry]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(def ^:dynamic *default-dialect*
  "Dialect used when a caller names none. The JVM runs the default engine."
  :java)

(defn ->expr
  "Result<String>: FORM as a regex source string in DIALECT-ID.

   FORM is regal's authored syntax or a normalized Construct. A construct the
   dialect cannot express is refused, never approximated."
  ([form] (->expr *default-dialect* form))
  ([dialect-id form]
   (r/let-ok [construct (cc/normalize form)]
             (dial/emit-as dialect-id construct))))

(defn ->pattern
  "Result<Pattern>: BASE (a Pattern map without `:pattern/expr`) completed from
   FORM. `:pattern/construct` records the normalized construct, so the source of
   an expression survives into the registry."
  ([base form] (->pattern *default-dialect* base form))
  ([dialect-id base form]
   (r/let-ok [construct (cc/normalize form)
              expr      (dial/emit-as dialect-id construct)]
             (r/ok (assoc base
                          :pattern/expr expr
                          :pattern/construct construct)))))

(defn register!
  "Build a Pattern from BASE + FORM and register it. Result<Pattern>.

   Refused — and not stored — if the construct will not normalize, the dialect
   cannot express it, or the projected Pattern fails the Pattern schema."
  ([base form] (register! *default-dialect* base form))
  ([dialect-id base form]
   (r/let-ok [pattern (->pattern dialect-id base form)]
             (registry/register-pattern! pattern))))

(defn supported?
  "Can DIALECT-ID express FORM? Result<boolean> — an unnormalizable form is an
   error, not a false."
  [dialect-id form]
  (r/let-ok [construct (cc/normalize form)
             emitter   (dial/emitter dialect-id)]
            (r/ok (dial/supports? (dial/dialect emitter) construct))))

(defn explain
  "Result<map>: what FORM needs, and which registered dialects can express it.
   The introspection surface — use it before shelling a pattern to `rg`."
  [form]
  (r/let-ok [construct (cc/normalize form)]
            (let [needs (cc/required-capabilities construct)]
              (r/ok {:construct construct
                     :requires  (into (sorted-set) needs)
                     :dialects  (into (sorted-map)
                                      (map (fn [[id e]]
                                             [id (vec (dial/missing-capabilities
                                                       (dial/dialect e) construct))]))
                                      (dial/registered-emitters))}))))
