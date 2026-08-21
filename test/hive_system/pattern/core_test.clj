(ns hive-system.pattern.core-test
  "Contracts for the pattern subsystem.

   Schema-derived coverage for the pure promoters; hand-written tests for what
   a schema cannot state — the engine's offset invariant, flag refusal, and the
   DIP swap (a stub engine, never a with-redefs)."
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [clojure.test.check :as tc]
            [hive-dsl.result :as r]
            [hive-schemas.test :as hst]
            [hive-system.pattern.core :as pattern]
            [hive-system.pattern.protocols :as proto]
            [hive-system.pattern.regex :as regex]
            [hive-system.pattern.registry :as registry]
            [hive-system.pattern.schema :as ps]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

;;; =============================================================================
;;; Isolation — the registries are process-global
;;; =============================================================================

(defn- restore-registries
  [f]
  (let [patterns (registry/registered-patterns)
        engines  (registry/registered-engines)]
    (try
      (f)
      (finally
        (doseq [id (remove (set (keys patterns)) (keys (registry/registered-patterns)))]
          (registry/unregister-pattern! id))
        (doseq [id (remove (set (keys engines)) (keys (registry/registered-engines)))]
          (registry/unregister-engine! id))))))

(use-fixtures :each restore-registries)

;;; =============================================================================
;;; Free coverage — property + mutation synthesized from the schemas
;;; =============================================================================

(hst/deftrifecta-from-schema flags->bitmask
  hive-system.pattern.regex/flags->bitmask
  {:in        [:cat [:set ps/Flag]]
   :out       [:int {:min 0}]
   :rel       (fn [[flags] bitmask] (= (zero? bitmask) (empty? flags)))
   :mutation  false
   :num-tests 100})

(hst/deftrifecta-from-schema resolve-pattern
  hive-system.pattern.registry/resolve-pattern
  {:in        [:cat ps/PatternIndex ps/PatternRef]
   :out       :any
   :rel       (fn [[index ref] result]
                (= (r/ok? result)
                   (boolean (or (map? ref) (contains? index ref)))))
   :mutation  false
   :num-tests 100})

;;; =============================================================================
;;; Engine contract — what the schema cannot state
;;; =============================================================================

(def ^:private literal-pattern
  #:pattern{:id :test/ab :expr "ab+"})

(deftest matches-locate-themselves-in-the-subject
  (testing "every Match's offsets carve its own text out of the subject"
    (let [property
          (prop/for-all [subject (gen/fmap #(apply str %)
                                           (gen/vector (gen/elements "abc ") 0 40))]
            (let [result (pattern/scan literal-pattern subject)
                  matches (:ok result)]
              (and (r/ok? result)
                   (every? (fn [{:match/keys [text start end]}]
                             (and (<= 0 start) (<= start end) (<= end (count subject))
                                  (= text (subs subject start end))))
                           matches)
                   ;; subject order, non-overlapping
                   (->> matches
                        (partition 2 1)
                        (every? (fn [[a b]] (<= (:match/end a) (:match/start b))))))))]
      (is (:result (tc/quick-check 200 property))))))

(deftest scan-actually-finds-occurrences
  (testing "non-vacuity: the offset property above is satisfied by an empty
            result set, so pin real matches with real coordinates"
    (is (= [#:match{:text "abb" :start 2 :end 5 :groups []}
            #:match{:text "ab" :start 8 :end 10 :groups []}]
           (:ok (pattern/scan literal-pattern "xxabbxx ab"))))
    (is (= ["b"]
           (-> (pattern/scan #:pattern{:expr "a(b)" :id :test/grouped} "zab")
               :ok first :match/groups)))
    (is (false? (:ok (pattern/match? literal-pattern "no match here"))))))

(deftest an-unhonourable-flag-is-refused-not-dropped
  (let [engine (regex/make-engine)
        result (proto/match? engine
                             #:pattern{:expr "a" :flags #{:no-such-flag}}
                             "aaa")]
    (is (r/err? result))
    (is (= :pattern/unsupported-flag (:error result)))))

(deftest a-bad-expression-is-an-error-not-a-throw
  (is (r/err? (pattern/match? #:pattern{:expr "a["} "aaa"))))

;;; =============================================================================
;;; Registry contracts
;;; =============================================================================

(deftest a-named-pattern-serves-every-call-site
  (is (r/ok? (pattern/register-pattern! literal-pattern)))
  (is (= (:ok (pattern/match? :test/ab "xxabbxx"))
         (:ok (pattern/match? literal-pattern "xxabbxx"))
         true)))

(deftest an-unknown-id-is-an-error
  (let [result (pattern/match? :test/never-registered "abc")]
    (is (r/err? result))
    (is (= :pattern/unknown (:error result)))))

(deftest an-invalid-pattern-is-refused-and-not-stored
  (let [result (registry/register-pattern! #:pattern{:id :test/bad :expr 42})]
    (is (r/err? result))
    (is (= :pattern/invalid (:error result)))
    (is (not (contains? (registry/registered-patterns) :test/bad)))))

(deftest an-unnamed-pattern-cannot-be-registered
  (is (= :pattern/unnamed (:error (registry/register-pattern! #:pattern{:expr "a"})))))

;;; =============================================================================
;;; DIP — a stub engine serves the same call sites (LSP)
;;; =============================================================================

(defrecord AlwaysEngine [answer calls]
  proto/IPatternEngine
  (engine-id [_] :test/always)
  (match? [_ pattern subject]
    (swap! calls conj [(:pattern/expr pattern) subject])
    (r/ok answer))
  (scan [_ _ _] (r/ok [])))

(deftest an-engine-swap-changes-no-call-site
  (let [calls (atom [])]
    (pattern/register-engine! (->AlwaysEngine true calls))
    (is (r/ok? (pattern/register-pattern!
                #:pattern{:id :test/stubbed :engine :test/always :expr "zzz"})))
    (testing "the call site is identical; only the engine id differs"
      (is (true? (:ok (pattern/match? :test/stubbed "no zzz here at all"))))
      (is (= [["zzz" "no zzz here at all"]] @calls)))))

(deftest an-unknown-engine-is-an-error
  (is (= :pattern/unknown-engine
         (:error (pattern/match? #:pattern{:expr "a" :engine :test/nope} "a")))))
