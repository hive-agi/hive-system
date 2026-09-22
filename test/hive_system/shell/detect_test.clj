(ns hive-system.shell.detect-test
  "Tests for package manager detection and binary resolution.

   Detection is asserted as a RULE, not as an inventory: a manager is reported
   exactly when its binary resolves on PATH. Property tests verify which
   always returns valid Results."
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.test.check.generators :as gen]
            [hive-test.properties :refer [defprop-total defprop-complement]]
            [hive-dsl.result :as r]
            [hive-system.shell.detect :as detect]))

;; =============================================================================
;; Detection agrees with PATH, on any host
;; =============================================================================

(deftest detection-reports-only-managers-it-knows
  ;; This was a golden over `(set (keys (detect-pkg-managers)))`, which froze
  ;; the inventory of ONE developer's laptop: #{:cargo :apt :conda :pip :brew
  ;; :npm}. No CI runner has brew, so the test could not pass anywhere else,
  ;; and it was the last thing standing between this library and a release.
  ;;
  ;; A golden can only lock something that does not depend on the host. What
  ;; does not depend on the host here is the RULE: detection reports a manager
  ;; exactly when its binary resolves on PATH, and never reports one it does
  ;; not declare. That holds on the laptop, on the runner, and in a container
  ;; with nothing installed at all.
  (let [known @#'detect/pkg-manager-binaries
        found (detect/detect-pkg-managers)]
    (testing "every reported manager is declared, resolves, and agrees on its path"
      (doseq [[mgr path] found]
        (is (contains? known mgr)
            (str mgr " was reported but this namespace does not declare it"))
        (let [res (detect/which (get known mgr))]
          (is (r/ok? res)
              (str mgr " was reported but " (get known mgr) " does not resolve"))
          (is (= path (get-in res [:ok :path]))
              (str mgr " was reported at a path `which` does not agree with")))))
    (testing "every manager left out really is absent"
      (doseq [[mgr bin] (apply dissoc known (keys found))]
        (is (r/err? (detect/which bin))
            (str mgr " resolves on PATH but detection did not report it"))))))

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
