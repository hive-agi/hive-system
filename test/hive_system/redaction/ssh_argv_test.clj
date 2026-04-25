(ns hive-system.redaction.ssh-argv-test
  "Tests for hive-system.redaction.ssh-argv.

   Critical invariants:
   - structure preserved: output count == input count
   - flag positions unchanged
   - Tainted slots → token strings of the form `<src:#hash>`
   - repeated Tainted with the same value → the SAME token (correlatable)
   - plain strings pass through unchanged (we never guess)"
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.string :as str]
            [hive-system.redaction.ssh-argv :as ssh-argv]
            [hive-system.redaction.tainted :as tainted :refer [taint]]))

(def ^:private canary "TAINTED-CANARY-12345")

;; =============================================================================
;; Plain-string passthrough
;; =============================================================================

(deftest plain-argv-passes-through
  (testing "argv with no Tainted slots is returned unchanged"
    (let [argv ["ssh" "-o" "ExitOnForwardFailure=yes"
                "-l" "root" "-p" "22" "host.example"]]
      (is (= argv (ssh-argv/redact-ssh-argv argv))))))

(deftest empty-argv
  (testing "empty argv passes through"
    (is (= [] (ssh-argv/redact-ssh-argv [])))))

;; =============================================================================
;; Structure preservation
;; =============================================================================

(deftest count-preserved
  (testing "output count matches input count"
    (let [argv ["ssh" "-o" "Foo=bar" "-l" (taint "root" :id)
                "-p" (taint 22 :port) (taint "host.example" :host)]]
      (is (= (count argv) (count (ssh-argv/redact-ssh-argv argv)))))))

(deftest flag-positions-preserved
  (testing "every flag occupies its original position"
    (let [argv ["ssh" "-o" "ExitOnForwardFailure=yes"
                "-l" (taint "root" :id)
                "-p" (taint 22 :port)
                (taint "host.example" :host)]
          out  (ssh-argv/redact-ssh-argv argv)]
      (is (= "ssh"  (nth out 0)))
      (is (= "-o"   (nth out 1)))
      (is (= "ExitOnForwardFailure=yes" (nth out 2)))
      (is (= "-l"   (nth out 3)))
      (is (= "-p"   (nth out 5))))))

(deftest flag-count-unchanged
  (testing "number of flag tokens (those starting with '-') is unchanged"
    (let [argv ["ssh" "-A" "-o" "K=V" "-l" (taint "root" :id)
                "-p" "22" (taint "host" :host)]
          out  (ssh-argv/redact-ssh-argv argv)
          flag-count (fn [xs] (count (filter #(and (string? %)
                                                   (str/starts-with? % "-"))
                                             xs)))]
      (is (= (flag-count argv) (flag-count out))))))

;; =============================================================================
;; Tainted slot → token
;; =============================================================================

(deftest tainted-host-becomes-token
  (testing "Tainted host slot is replaced with a <host:#hash> token"
    (let [t    (taint canary :host)
          argv ["ssh" t]
          out  (ssh-argv/redact-ssh-argv argv)
          slot (nth out 1)]
      (is (string? slot))
      (is (str/starts-with? slot "<host:#"))
      (is (str/ends-with? slot ">"))
      (is (not (str/includes? (pr-str out) canary))))))

(deftest tainted-without-explicit-source-uses-flag-default
  (testing "bare Tainted after -l gets the 'id' default source"
    (let [t    (taint "root-user" nil)
          argv ["ssh" "-l" t "host"]
          out  (ssh-argv/redact-ssh-argv argv)]
      (is (str/starts-with? (nth out 2) "<id:#")))))

(deftest tainted-port-flag
  (testing "bare Tainted after -p gets the 'port' default source"
    (let [t    (taint 22 nil)
          argv ["ssh" "-p" t "host"]
          out  (ssh-argv/redact-ssh-argv argv)]
      (is (str/starts-with? (nth out 2) "<port:#")))))

(deftest tainted-explicit-source-wins
  (testing "an explicit :source on Tainted overrides the flag default"
    (let [t    (taint "myhost" :argv-host)
          argv ["ssh" "-l" t "host"]
          out  (ssh-argv/redact-ssh-argv argv)]
      (is (str/starts-with? (nth out 2) "<argv-host:#")))))

;; =============================================================================
;; Plain-string slots are NEVER hashed
;; =============================================================================

(deftest plain-string-host-passes-through
  (testing "plain (non-Tainted) host string is preserved verbatim"
    (let [argv ["ssh" "-l" "root" "host.example"]
          out  (ssh-argv/redact-ssh-argv argv)]
      (is (= "host.example" (last out)))
      (is (= "root" (nth out 2))))))

(deftest mixed-tainted-and-plain
  (testing "only Tainted slots get tokens; plain strings pass through"
    (let [t    (taint canary :host)
          argv ["ssh" "-l" "root" "-p" "22" t]
          out  (ssh-argv/redact-ssh-argv argv)]
      (is (= "root" (nth out 2)))
      (is (= "22"   (nth out 4)))
      (is (str/starts-with? (nth out 5) "<host:#"))
      (is (not (str/includes? (pr-str out) canary))))))

;; =============================================================================
;; Repeated Tainted with same underlying value → same hash token
;; =============================================================================

(deftest same-value-same-token-within-argv
  (testing "two Tainteds wrapping the same value yield the same token"
    (let [a    (taint "host.example" :host)
          b    (taint "host.example" :host)
          argv ["ssh" "-J" a a "-W" b]
          out  (ssh-argv/redact-ssh-argv argv)]
      ;; positions 2, 3, 5 all hold a Tainted of the same value
      (is (= (nth out 2) (nth out 3)))
      (is (= (nth out 2) (nth out 5))))))

(deftest different-values-different-tokens
  (testing "two distinct Tainted values within one argv yield distinct tokens"
    (let [a    (taint "alpha.example" :host)
          b    (taint "beta.example"  :host)
          argv ["ssh" a b]
          out  (ssh-argv/redact-ssh-argv argv)]
      (is (not= (nth out 1) (nth out 2))))))

;; =============================================================================
;; Boolean flags must not consume the next slot
;; =============================================================================

(deftest boolean-flag-does-not-consume-value
  (testing "boolean flags like -A do not steal the following slot"
    (let [t    (taint "host" :host)
          argv ["ssh" "-A" t]
          out  (ssh-argv/redact-ssh-argv argv)]
      (is (= "-A" (nth out 1)))
      (is (str/starts-with? (nth out 2) "<host:#")))))

;; =============================================================================
;; Trailing value-flag (no value) — should not crash
;; =============================================================================

(deftest trailing-value-flag-survives
  (testing "argv ending in a value-flag with no value is preserved as-is"
    (let [argv ["ssh" "-l"]
          out  (ssh-argv/redact-ssh-argv argv)]
      (is (= argv out)))))

;; =============================================================================
;; Input-validation
;; =============================================================================

(deftest non-sequential-input-throws
  (testing "non-sequential input is rejected"
    (is (thrown? Exception (ssh-argv/redact-ssh-argv "not a vec")))
    (is (thrown? Exception (ssh-argv/redact-ssh-argv {:argv "x"})))))
