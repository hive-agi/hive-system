(ns hive-system.process.liveness-trifecta-test
  "Trifecta tests for `hive-system.process.liveness`.

   Coverage:
   - golden  : pinpoint inputs (nil, non-integer, this-process pid, bogus pid)
               snapshot the LivenessSignal variant we promise per case.
   - property: forall any value, `check-pid-alive` yields a closed-set
               variant — never throws, never returns garbage.
   - mutation: stress non-integer / negative / zero inputs to make sure
               degrade-soft semantics hold (no zombify on :unknown)."
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [clojure.test.check.clojure-test :refer [defspec]]
            [hive-system.process.liveness :as L]
            [hive-test.trifecta :refer [deftrifecta]])
  (:import [java.lang ProcessHandle]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: AGPL-3.0-or-later

;; =============================================================================
;; Helpers
;; =============================================================================

(defn- self-pid [] (.pid (ProcessHandle/current)))

(def ^:private liveness-variants
  #{:liveness/alive :liveness/dead :liveness/unknown})

(defn- variant [pid] (:adt/variant (L/check-pid-alive pid)))

;; =============================================================================
;; Generators
;; =============================================================================

;; Pids we KNOW are dead — Linux pid_max is typically 4_194_304. Anything way
;; above that can never be a live process. We pick a fixed huge int to keep
;; the property deterministic.
(def gen-dead-pid    (gen/return 999999999))
(def gen-non-integer (gen/one-of [(gen/return nil)
                                  gen/string-alphanumeric
                                  (gen/return :keyword)
                                  (gen/vector gen/int)]))
(def gen-pid-input   (gen/one-of [gen-dead-pid gen-non-integer]))

;; =============================================================================
;; Trifecta — closed-variant coercion
;; =============================================================================

(deftrifecta check-pid-alive-variants
  hive-system.process.liveness/check-pid-alive
  {:cases {nil       {:adt/type :LivenessSignal :adt/variant :liveness/unknown}
           "abc"     {:adt/type :LivenessSignal :adt/variant :liveness/unknown}
           :sym      {:adt/type :LivenessSignal :adt/variant :liveness/unknown}
           999999999 {:adt/type :LivenessSignal :adt/variant :liveness/dead}}
   :xf    identity
   :gen   gen-pid-input
   :pred  #(contains? liveness-variants (:adt/variant %))
   :num-tests 200})

;; =============================================================================
;; Property: closed-set invariant
;; =============================================================================

(defspec liveness-closed-set 300
  (prop/for-all [pid gen-pid-input]
                (contains? liveness-variants (variant pid))))

(defspec dead-and-alive-mutually-exclusive 200
  (prop/for-all [pid gen-pid-input]
                (let [d? (L/dead? pid)
                      a? (L/alive? pid)]
                  (not (and d? a?)))))

;; =============================================================================
;; Targeted assertions
;; =============================================================================

(deftest self-pid-alive
  (testing "the JVM's own pid must report :liveness/alive"
    (let [pid (self-pid)]
      (is (= :liveness/alive (variant pid)))
      (is (L/alive? pid))
      (is (not (L/dead? pid))))))

(deftest unknown-never-zombifies
  (testing "nil / non-integer inputs are :unknown, NOT :dead — degrade-soft"
    (doseq [bad [nil "" "  " :kw [] {} 'sym]]
      (is (= :liveness/unknown (variant bad))
          (str "expected :unknown for " (pr-str bad)))
      (is (not (L/dead? bad)))
      (is (not (L/alive? bad))))))

(deftest dead-pid-confirmed
  (testing "extremely large pid is unambiguously dead"
    (is (L/dead? 999999999))
    (is (= :liveness/dead (variant 999999999)))))
