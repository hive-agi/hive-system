(ns hive-system.shell.detect-test
  "Tests for package manager detection and binary resolution.
   Golden tests lock down detection behavior on this host.
   Property tests verify which always returns valid Results."
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.test.check.generators :as gen]
            [hive-test.golden :refer [deftest-golden]]
            [hive-test.properties :refer [defprop-total defprop-complement]]
            [hive-dsl.result :as r]
            [hive-system.shell.detect :as detect]))

;; =============================================================================
;; Golden: Lock down detected package managers on this host
;; =============================================================================

(deftest-golden detected-pkg-managers
  "test/golden/detect/pkg-managers.edn"
  (set (keys (detect/detect-pkg-managers))))

;; =============================================================================
;; Unit: which returns correct Result shape
;; =============================================================================

(deftest which-found-returns-ok
  (testing "which for a known binary returns ok with path"
    (let [result (detect/which "sh")]
      (is (r/ok? result))
      (is (string? (get-in result [:ok :path])))
      (is (= "sh" (get-in result [:ok :program]))))))

(deftest which-missing-returns-err
  (testing "which for a nonexistent binary returns err"
    (let [result (detect/which "nonexistent-binary-xyz-123")]
      (is (r/err? result))
      (is (= :shell/not-found (:error result))))))

(deftest which-result-shape
  (testing "ok result always has :path and :program"
    (let [result (detect/which "ls")]
      (when (r/ok? result)
        (is (contains? (:ok result) :path))
        (is (contains? (:ok result) :program))
        (is (.startsWith ^String (get-in result [:ok :path]) "/"))))))

;; =============================================================================
;; Property: which is total — never throws for any string input
;; =============================================================================

(defprop-total which-total
  detect/which
  gen/string-alphanumeric
  {:num-tests 100
   :pred (fn [r] (or (r/ok? r) (r/err? r)))})

;; =============================================================================
;; Property: ok? and err? are exact complements for which results
;; =============================================================================

(defprop-complement which-ok-err-complement
  r/ok? r/err?
  (gen/fmap detect/which
            (gen/one-of [gen/string-alphanumeric
                         (gen/elements ["ls" "sh" "nonexistent-xyz"])]))
  {:num-tests 50})

;; =============================================================================
;; Unit: detect-pkg-managers returns valid map
;; =============================================================================

(deftest detect-pkg-managers-shape
  (testing "returns a map with keyword keys and string paths"
    (let [mgrs (detect/detect-pkg-managers)]
      (is (map? mgrs))
      (doseq [[k v] mgrs]
        (is (keyword? k))
        (is (string? v))
        (is (.startsWith ^String v "/"))))))
