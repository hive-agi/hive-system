(ns hive-system.redaction.core-test
  "Tests for hive-system.redaction.core.

   Critical invariants:
   - Walker auto-replaces every Tainted with its print-form.
   - Path-vector :select rules match nested map entries.
   - Predicate :select rules match per-entry.
   - Non-matching data passes through unchanged.
   - register-rule! / unregister-rule! / reset-rules! manage the registry.
   - Default env/* rules are registered at load time and redact env keys."
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [clojure.string :as str]
            [hive-system.redaction.core :as red]
            [hive-system.redaction.tainted :as tainted :refer [taint]]))

(def ^:private canary "TAINTED-CANARY-12345")

;; =============================================================================
;; Fixture: snapshot + restore registry per test so user rules don't leak
;; =============================================================================

(defn ^:private with-clean-rules [f]
  (let [snapshot (red/registered-rules)]
    (try
      (red/reset-rules!)
      (red/install-default-rules!)
      (f)
      (finally
        (red/reset-rules!)
        (doseq [[id r] snapshot]
          (red/register-rule! id (dissoc r :id)))))))

(use-fixtures :each with-clean-rules)

;; =============================================================================
;; Tainted auto-replacement (no rule needed)
;; =============================================================================

(deftest walker-replaces-tainted-at-top-level
  (testing "redact replaces a top-level Tainted with its print form"
    (let [t   (taint canary "src")
          out (red/redact t)]
      (is (string? out))
      (is (not (str/includes? out canary)))
      (is (str/includes? out "redacted")))))

(deftest walker-replaces-tainted-in-map
  (testing "redact replaces Tainted nested inside a map"
    (let [t   (taint canary :host)
          out (red/redact {:host t :ok "fine"})]
      (is (string? (:host out)))
      (is (not (str/includes? (pr-str out) canary)))
      (is (= "fine" (:ok out))))))

(deftest walker-replaces-tainted-in-vector
  (testing "redact replaces Tainted inside a vector"
    (let [t   (taint canary :host)
          out (red/redact ["a" t "c"])]
      (is (vector? out))
      (is (= 3 (count out)))
      (is (= "a" (first out)))
      (is (string? (second out)))
      (is (not (str/includes? (pr-str out) canary))))))

(deftest walker-replaces-deeply-nested-tainted
  (testing "redact descends through nested maps/vectors"
    (let [t    (taint canary "deep")
          data {:a {:b {:c [t {:d t}]}}}
          out  (red/redact data)]
      (is (not (str/includes? (pr-str out) canary))))))

(deftest non-matching-data-passes-through
  (testing "data without Tainteds and without rule matches is unchanged"
    (let [data {:plain "ok" :nested {:x 1 :y [1 2 3]} :s "hello"}]
      (is (= data (red/redact data))))))

;; =============================================================================
;; Path-based :select rules
;; =============================================================================

(deftest rule-matches-path
  (testing "vector :select matches a nested map entry"
    (red/register-rule! :test/api-key
                        {:select  [:headers "Authorization"]
                         :replace (constantly "<redacted>")})
    (let [data {:headers {"Authorization" "Bearer abc123"
                          "Content-Type"  "application/json"}}
          out  (red/redact data)]
      (is (= "<redacted>" (get-in out [:headers "Authorization"])))
      (is (= "application/json" (get-in out [:headers "Content-Type"]))))))

(deftest rule-matches-path-suffix
  (testing "vector :select matches by suffix at any depth"
    (red/register-rule! :test/secret
                        {:select  [:secret]
                         :replace (constantly "<R>")})
    (let [data {:a {:b {:secret "leak1"}} :c {:secret "leak2"} :secret "leak3"}
          out  (red/redact data)]
      (is (= "<R>" (get-in out [:a :b :secret])))
      (is (= "<R>" (get-in out [:c :secret])))
      (is (= "<R>" (:secret out))))))

(deftest rule-replace-receives-value
  (testing ":replace fn receives the original value"
    (red/register-rule! :test/upcase
                        {:select  [:tag]
                         :replace #(str/upper-case %)})
    (let [out (red/redact {:tag "hello"})]
      (is (= "HELLO" (:tag out))))))

;; =============================================================================
;; Predicate :select rules
;; =============================================================================

(deftest rule-matches-predicate
  (testing "fn :select is invoked per map entry"
    (red/register-rule! :test/big
                        {:select  (fn [_k v] (and (number? v) (> v 100)))
                         :replace (constantly :BIG)})
    (let [out (red/redact {:a 5 :b 200 :c 50 :d 1000})]
      (is (= 5 (:a out)))
      (is (= :BIG (:b out)))
      (is (= 50 (:c out)))
      (is (= :BIG (:d out))))))

;; =============================================================================
;; Registry management
;; =============================================================================

(deftest register-validates-shape
  (testing "register-rule! rejects malformed rules"
    (is (thrown? Exception
                 (red/register-rule! "not-a-keyword"
                                     {:select [:x] :replace identity})))
    (is (thrown? Exception
                 (red/register-rule! :ok {:replace identity})))
    (is (thrown? Exception
                 (red/register-rule! :ok {:select [:x]})))))

(deftest unregister-removes-rule
  (testing "unregister-rule! removes a rule and stops it firing"
    (red/register-rule! :test/x
                        {:select [:x] :replace (constantly :REDACTED)})
    (is (= :REDACTED (:x (red/redact {:x "v"}))))
    (red/unregister-rule! :test/x)
    (is (= "v" (:x (red/redact {:x "v"}))))))

(deftest reset-clears-all
  (testing "reset-rules! drops every rule including defaults"
    (red/reset-rules!)
    (is (empty? (red/registered-rules)))
    ;; even default env rule no longer fires
    (is (= "leak" (get-in (red/redact {:env {"SSHPASS" "leak"}})
                          [:env "SSHPASS"])))))

;; =============================================================================
;; Default env rules
;; =============================================================================

(deftest default-env-rules-fire
  (testing "default rules redact common ssh-related env vars"
    (let [data {:env {"SSHPASS"      "TOPSECRET"
                      "SSH_AUTH_SOCK" "/tmp/ssh-XXXX/agent.123"
                      "PATH"         "/usr/bin"}}
          out  (red/redact data)]
      (is (= "<redacted>" (get-in out [:env "SSHPASS"])))
      (is (= "<redacted>" (get-in out [:env "SSH_AUTH_SOCK"])))
      (is (= "/usr/bin"   (get-in out [:env "PATH"]))))))

(deftest tainted-and-rule-coexist
  (testing "Tainted replacement and rule replacement both run on a single doc"
    (red/register-rule! :test/host
                        {:select  [:host]
                         :replace (fn [v] (str "host-tag:" v))})
    (let [t   (taint canary :pwd)
          out (red/redact {:host "h.example" :pwd t})]
      (is (= "host-tag:h.example" (:host out)))
      (is (string? (:pwd out)))
      (is (not (str/includes? (pr-str out) canary))))))
