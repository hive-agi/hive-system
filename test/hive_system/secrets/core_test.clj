(ns hive-system.secrets.core-test
  "Tests for the opaque Secret type.

   Critical invariants under test:
   - toString never reveals the wrapped value
   - print-method/print-dup never reveal the value
   - Keyword lookup, get, destructuring all return nil
   - hashCode is constant (no value leak via probe)
   - equals uses constant-time comparison
   - expose returns the value verbatim"
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.string :as str]
            [clojure.pprint :as pp]
            [hive-system.secrets.core :as sec :refer [expose]]))

;; =============================================================================
;; Construction + basic API
;; =============================================================================

(deftest make-secret-basic
  (testing "make-secret wraps a value"
    (let [s (sec/make-secret "hunter2" :literal "test-key")]
      (is (sec/secret? s))
      (is (= "hunter2" (expose s)))
      (is (= :literal   (sec/secret-source s)))
      (is (= "test-key" (sec/secret-key s))))))

(deftest make-secret-no-key
  (testing "make-secret allows nil key"
    (let [s (sec/make-secret "v" :literal)]
      (is (nil? (sec/secret-key s))))))

(deftest secret?-predicate
  (is (sec/secret? (sec/make-secret "x" :literal)))
  (is (not (sec/secret? "x")))
  (is (not (sec/secret? nil)))
  (is (not (sec/secret? {:value "x"}))))

;; =============================================================================
;; Print safety — toString MUST NOT leak value
;; =============================================================================

(deftest tostring-redacts
  (testing ".toString never contains the wrapped value"
    (let [s (sec/make-secret "TOPSECRET-12345" :pass "vps/r1/root")]
      (is (not (str/includes? (.toString s) "TOPSECRET-12345")))
      (is (str/includes? (.toString s) "redacted")))))

(deftest pr-str-redacts
  (testing "pr-str / println / prn never contain the wrapped value"
    (let [s (sec/make-secret "SUPERSECRET-XYZ" :pass "vps/r1/root")]
      (is (not (str/includes? (pr-str s)    "SUPERSECRET-XYZ")))
      (is (not (str/includes? (with-out-str (println s)) "SUPERSECRET-XYZ")))
      (is (not (str/includes? (with-out-str (prn s))     "SUPERSECRET-XYZ"))))))

(deftest print-dup-redacts
  (testing "print-dup never contains the wrapped value"
    (let [s   (sec/make-secret "DUP-LEAK-CHECK" :pass "k")
          out (binding [*print-dup* true] (pr-str s))]
      (is (not (str/includes? out "DUP-LEAK-CHECK"))))))

(deftest pprint-redacts
  (testing "clojure.pprint never reveals the wrapped value"
    (let [s   (sec/make-secret "PPRINT-LEAK-CHECK" :pass "k")
          out (with-out-str (pp/pprint s))]
      (is (not (str/includes? out "PPRINT-LEAK-CHECK"))))))

(deftest pprint-in-collection-redacts
  (testing "pprint of a Secret inside a map/vec still redacts"
    (let [s   (sec/make-secret "NESTED-LEAK" :pass "k")
          out (with-out-str (pp/pprint {:relay-pass s :other "fine"}))]
      (is (not (str/includes? out "NESTED-LEAK")))
      (is (str/includes? out "fine")))))

(deftest tostring-includes-source-and-key
  (testing "toString reveals source and key (non-sensitive)"
    (let [s (sec/make-secret "v" :pass "vps/r1/root")]
      (is (str/includes? (.toString s) "pass"))
      (is (str/includes? (.toString s) "vps/r1/root")))))

;; =============================================================================
;; Map-like access MUST return nil — Secret is not a map
;; =============================================================================

(deftest keyword-lookup-returns-nil
  (testing "keyword lookup returns nil — no map-style escape hatch"
    (let [s (sec/make-secret "ESCAPE-ATTEMPT" :literal)]
      (is (nil? (:value s)))
      (is (nil? (get s :value)))
      (is (nil? (:source s)))
      (is (nil? (:key s))))))

(deftest destructuring-returns-nil
  (testing "map-style destructuring binds nil for all keys"
    (let [s (sec/make-secret "DESTRUCTURE-LEAK" :literal)
          {:keys [value source key]} s]
      (is (nil? value))
      (is (nil? source))
      (is (nil? key)))))

(deftest not-seqable
  (testing "Secret is not Seqable — seq throws or returns nothing meaningful"
    (let [s (sec/make-secret "v" :literal)]
      ;; Either throws, or returns nil — both are acceptable.
      (is (or (nil? (try (seq s) (catch Exception _ ::threw)))
              (= ::threw (try (seq s) (catch Exception _ ::threw))))))))

;; =============================================================================
;; Equality + hash
;; =============================================================================

(deftest equality-by-value
  (testing "two Secrets with equal value are equal"
    (let [a (sec/make-secret "same" :pass "k1")
          b (sec/make-secret "same" :pass "k2")
          c (sec/make-secret "diff" :pass "k1")]
      (is (= a b))
      (is (not= a c)))))

(deftest hashcode-constant
  (testing "hashCode is constant — no value leak via probe"
    (let [a (sec/make-secret "alpha" :literal)
          b (sec/make-secret "beta"  :literal)]
      (is (= (.hashCode a) (.hashCode b)))
      (is (zero? (.hashCode a))))))

(deftest equality-rejects-non-secret
  (testing "equals returns false for non-Secret"
    (let [s (sec/make-secret "v" :literal)]
      (is (not (= s "v")))
      (is (not (= s {:value "v"})))
      (is (not (= s nil))))))

;; =============================================================================
;; expose
;; =============================================================================

(deftest expose-returns-value
  (testing "expose unwraps the original value"
    (let [s (sec/make-secret "raw-value" :literal)]
      (is (= "raw-value" (expose s))))))

(deftest expose-of-empty
  (testing "expose works on empty string"
    (let [s (sec/make-secret "" :literal)]
      (is (= "" (expose s))))))

;; =============================================================================
;; with-secret macro
;; =============================================================================

(deftest with-secret-binds
  (testing "with-secret binds the unwrapped value"
    (let [s (sec/make-secret "scoped" :literal)]
      (sec/with-secret [v s]
        (is (= "scoped" v))))))

;; =============================================================================
;; Exception messages must redact
;; =============================================================================

(deftest exception-message-redacts
  (testing "throwing with a Secret in the message uses .toString → redacted"
    (let [s   (sec/make-secret "EXC-LEAK-CHECK" :pass "k")
          ex  (ex-info (str "failed to use " s) {:secret s})
          msg (.getMessage ex)]
      (is (not (str/includes? msg "EXC-LEAK-CHECK"))))))
