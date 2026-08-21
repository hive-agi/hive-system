(ns hive-system.pattern.regex
  "java.util.regex adapter for IPatternEngine.

   The default engine. Pure promoters (`flags->bitmask`, `->matches`) carry the
   logic; the record is a thin Result-returning shell over them."
  (:require [hive-dsl.result :as r]
            [hive-system.pattern.protocols :as proto]
            [hive-system.pattern.schema :as ps]
            [malli.core :as m])
  (:import (java.util.regex Matcher Pattern)))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(def ^:private flag->bit
  {:case-insensitive Pattern/CASE_INSENSITIVE
   :multiline        Pattern/MULTILINE
   :dotall           Pattern/DOTALL
   :extended         Pattern/COMMENTS})

(def supported-flags
  "Every Flag this engine honours."
  (set (keys flag->bit)))

(defn flags->bitmask
  "The java.util.regex bitmask for FLAGS. Monotone: adding a flag only ever
   turns bits on."
  [flags]
  (reduce (fn [acc f] (bit-or acc (long (get flag->bit f 0)))) 0 flags))

(m/=> flags->bitmask [:=> [:cat [:set ps/Flag]] [:int {:min 0}]])

(defn ->matches
  "Every occurrence of compiled REGEX in SUBJECT, subject-ordered and
   non-overlapping, as Match maps."
  [^Pattern regex ^String subject]
  (let [^Matcher matcher (.matcher regex subject)]
    (loop [acc (transient [])]
      (if (.find matcher)
        (recur (conj! acc {:match/text   (.group matcher)
                           :match/start  (.start matcher)
                           :match/end    (.end matcher)
                           :match/groups (mapv (fn [i] (.group matcher (int i)))
                                               (range 1 (inc (.groupCount matcher))))}))
        (persistent! acc)))))

(m/=> ->matches [:=> [:cat :any :string] ps/Matches])

(defn compile-pattern
  "Result<java.util.regex.Pattern> for PATTERN. A flag this engine cannot
   honour is an error, never a silent drop."
  [{:pattern/keys [expr flags] :as pattern}]
  (if-let [unsupported (seq (remove supported-flags (or flags #{})))]
    (r/err :pattern/unsupported-flag
           {:engine :regex :flags (vec unsupported) :pattern pattern})
    (r/try-effect* :pattern/bad-expression
                   (Pattern/compile expr (int (flags->bitmask (or flags #{})))))))

(defrecord RegexEngine []
  proto/IPatternEngine
  (engine-id [_] :regex)
  (match? [_ pattern subject]
    (r/let-ok [regex (compile-pattern pattern)]
              (r/ok (.find (.matcher ^Pattern regex ^String subject)))))
  (scan [_ pattern subject]
    (r/let-ok [regex (compile-pattern pattern)]
              (r/ok (->matches regex subject)))))

(defn make-engine
  "A stateless regex engine."
  []
  (->RegexEngine))
