(ns hive-system.redaction.tainted-test
  "Tests for hive-system.redaction.tainted.

   Critical invariants under test:
   - print-method NEVER emits the wrapped value (sentinel canary check)
   - Same value within a JVM run → same hash
   - Different values → different hash (with high probability)
   - tainted? predicate, untaint extractor, token helper.

   Cross-JVM-restart unlinkability is documented but not testable in a
   single JVM run (the salt is process-local by design)."
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.string :as str]
            [clojure.pprint :as pp]
            [hive-system.redaction.tainted :as tainted :refer [taint untaint tainted? token]]))

;; The canary string MUST never appear in any printed output.
(def ^:private canary "TAINTED-CANARY-12345")

;; =============================================================================
;; Construction
;; =============================================================================

(deftest taint-constructs
  (testing "taint wraps a value with source and hash"
    (let [t (taint canary "pass:vps/r1/ip")]
      (is (tainted? t))
      (is (= canary (:value t)))
      (is (= "pass:vps/r1/ip" (:source t)))
      (is (string? (:hash t)))
      (is (= 4 (count (:hash t)))))))

(deftest taint-keyword-source
  (testing "source can be a keyword"
    (let [t (taint canary :argv-host)]
      (is (= :argv-host (:source t))))))

;; =============================================================================
;; print-method NEVER leaks the value
;; =============================================================================

(deftest print-method-never-leaks
  (testing "pr-str never reveals the canary"
    (let [t (taint canary "pass:vps/r1/ip")]
      (is (not (str/includes? (pr-str t) canary)))
      (is (str/includes? (pr-str t) "redacted"))
      (is (str/includes? (pr-str t) "h=#")))))

(deftest println-never-leaks
  (testing "println / prn never reveal the canary"
    (let [t (taint canary :argv-host)]
      (is (not (str/includes? (with-out-str (println t)) canary)))
      (is (not (str/includes? (with-out-str (prn t)) canary))))))

(deftest print-dup-never-leaks
  (testing "print-dup never reveals the canary"
    (let [t   (taint canary :argv-host)
          out (binding [*print-dup* true] (pr-str t))]
      (is (not (str/includes? out canary))))))

(deftest pprint-never-leaks
  (testing "clojure.pprint never reveals the canary"
    (let [t   (taint canary :argv-host)
          out (with-out-str (pp/pprint t))]
      (is (not (str/includes? out canary))))))

(deftest pprint-in-collection-never-leaks
  (testing "pprint of a Tainted inside a map still redacts"
    (let [t   (taint canary :argv-host)
          out (with-out-str (pp/pprint {:host t :other "fine"}))]
      (is (not (str/includes? out canary)))
      (is (str/includes? out "fine")))))

(deftest exception-message-redacts
  (testing "throwing with a Tainted in the message uses print-method → no leak"
    (let [t   (taint canary "src")
          ex  (ex-info (str "ssh failed for " (pr-str t)) {})
          msg (.getMessage ex)]
      (is (not (str/includes? msg canary))))))

(deftest source-appears-in-print-output
  (testing "the (non-sensitive) source label appears in printed form"
    (let [t (taint canary "pass:vps/r1/ip")]
      (is (str/includes? (pr-str t) "pass:vps/r1/ip")))))

;; =============================================================================
;; Hash stability
;; =============================================================================

(deftest same-value-same-hash
  (testing "two Tainteds wrapping the same value produce the same hash"
    (let [a (taint canary "src-a")
          b (taint canary "src-b")]
      (is (= (:hash a) (:hash b))))))

(deftest different-values-different-hash
  (testing "different values produce different hashes (probabilistically)"
    ;; 16^4 = 65536 space; 100 distinct values should collide rarely.
    (let [hashes (->> (range 100)
                      (map #(taint (str "value-" %) "src"))
                      (map :hash)
                      set)]
      ;; allow up to a few collisions
      (is (> (count hashes) 90)))))

(deftest hash-is-4-hex-chars
  (testing "hash is exactly 4 lowercase hex characters"
    (let [t (taint "anything" "src")]
      (is (re-matches #"[0-9a-f]{4}" (:hash t))))))

;; =============================================================================
;; untaint
;; =============================================================================

(deftest untaint-extracts-value
  (testing "untaint returns the original value"
    (let [t (taint canary "src")]
      (is (= canary (untaint t))))))

(deftest untaint-passthrough-non-tainted
  (testing "untaint of a non-Tainted returns the value unchanged"
    (is (= "plain" (untaint "plain")))
    (is (= 42 (untaint 42)))
    (is (nil? (untaint nil)))))

;; =============================================================================
;; Predicate
;; =============================================================================

(deftest tainted?-predicate
  (is (tainted? (taint "x" "src")))
  (is (not (tainted? "x")))
  (is (not (tainted? nil)))
  (is (not (tainted? {:value "x" :source "s" :hash "abcd"}))))

;; =============================================================================
;; token helper
;; =============================================================================

(deftest token-format
  (testing "token returns <src:#hash> for Tainted"
    (let [t (taint canary :argv-host)]
      (is (= (str "<argv-host:#" (:hash t) ">") (token t))))))

(deftest token-string-source
  (testing "token uses the string source verbatim"
    (let [t (taint canary "host")]
      (is (= (str "<host:#" (:hash t) ">") (token t))))))

(deftest token-nil-for-non-tainted
  (testing "token returns nil for non-Tainted inputs"
    (is (nil? (token "plain")))
    (is (nil? (token nil)))))

;; =============================================================================
;; Cross-JVM-restart unlinkability — DOCUMENTED, NOT TESTABLE HERE
;; =============================================================================

(deftest cross-jvm-unlinkability-is-documented
  ;; This is a spec-level invariant: a fresh JVM regenerates the salt
  ;; via SecureRandom, so hash tokens emitted by run #1 cannot be
  ;; correlated with tokens from run #2. Single-JVM-test cannot prove
  ;; this; we assert via the docstring + design instead.
  (let [doc (-> #'hive-system.redaction.tainted/taint meta :doc)]
    (is (string? doc))))
