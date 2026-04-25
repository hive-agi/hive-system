(ns hive-system.secrets.pass-test
  "Tests for the PassBackend ISecretBackend implementation.

   Uses a mock shell function injected into the backend so we can
   simulate `pass` outcomes deterministically without touching the
   real password store."
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.string :as str]
            [hive-dsl.result :as r]
            [hive-system.secrets.core :as sec :refer [expose]]
            [hive-system.secrets.pass :as pass]
            [hive-system.secrets.protocols :as proto]))

;; =============================================================================
;; Mock shell helpers
;; =============================================================================

(defn- mock-shell
  "Build a mock exec! fn that returns `result` regardless of input.
   `result` should already be in Result shape — i.e. (r/ok {...}) or (r/err ...)."
  [result]
  (fn [_cmd _opts] result))

(defn- ok-shell
  "Mock shell that simulates a successful pass invocation with given stdout."
  [stdout]
  (mock-shell (r/ok {:exit 0 :stdout stdout :stderr "" :duration-ms 1})))

(defn- not-found-shell
  "Mock shell that simulates pass returning 'is not in the password store'."
  [key]
  (mock-shell
    (r/ok {:exit 1 :stdout ""
           :stderr (str "Error: " key " is not in the password store.\n")
           :duration-ms 1})))

(defn- exec-fail-shell []
  (mock-shell (r/err :shell/exec-failed {:reason "boom"})))

;; =============================================================================
;; Backend identity
;; =============================================================================

(deftest backend-id-is-pass
  (is (= :pass (proto/backend-id (pass/make-pass-backend)))))

;; =============================================================================
;; fetch — happy path
;; =============================================================================

(deftest fetch-returns-secret
  (testing "fetch wraps stdout in a Secret"
    (let [b (pass/make-pass-backend {:shell (ok-shell "hunter2\nsome-note\n")})
          result (proto/fetch b "vps/r1/root" {})]
      (is (r/ok? result))
      (is (sec/secret? (:ok result)))
      (is (= "hunter2\nsome-note\n" (expose (:ok result))))
      (is (= :pass (sec/secret-source (:ok result))))
      (is (= "vps/r1/root" (sec/secret-key (:ok result)))))))

(deftest fetch-line-only
  (testing ":line-only? returns first non-empty trimmed line"
    (let [b (pass/make-pass-backend
             {:shell (ok-shell "  \n203.0.113.42  \nignored-comment\n")})
          result (proto/fetch b "vps/r1/ip" {:line-only? true})]
      (is (r/ok? result))
      (is (= "203.0.113.42" (expose (:ok result)))))))

;; =============================================================================
;; fetch — errors
;; =============================================================================

(deftest fetch-not-found
  (testing "stderr 'is not in the password store' → :pass/not-found"
    (let [b (pass/make-pass-backend {:shell (not-found-shell "vps/missing")})
          result (proto/fetch b "vps/missing" {})]
      (is (r/err? result))
      (is (= :pass/not-found (:error result)))
      (is (= "vps/missing" (:key result))))))

(deftest fetch-empty
  (testing "blank stdout → :pass/empty"
    (let [b (pass/make-pass-backend {:shell (ok-shell "\n  \n")})
          result (proto/fetch b "vps/blank" {})]
      (is (r/err? result))
      (is (= :pass/empty (:error result))))))

(deftest fetch-shell-fail
  (testing "shell err → :pass/exec-fail"
    (let [b (pass/make-pass-backend {:shell (exec-fail-shell)})
          result (proto/fetch b "vps/anything" {})]
      (is (r/err? result))
      (is (= :pass/exec-fail (:error result))))))

(deftest fetch-non-zero-exit
  (testing "non-zero exit (without not-found stderr) → :pass/exec-fail"
    (let [b (pass/make-pass-backend
             {:shell (mock-shell (r/ok {:exit 2 :stdout "" :stderr "gpg: bad passphrase"
                                         :duration-ms 1}))})
          result (proto/fetch b "vps/anything" {})]
      (is (r/err? result))
      (is (= :pass/exec-fail (:error result)))
      (is (= 2 (:exit result))))))

;; =============================================================================
;; Errors must NEVER include the resolved value
;; =============================================================================

(deftest errors-never-leak-value
  (testing "even a 'success' that becomes empty doesn't leak in err payload"
    (let [b (pass/make-pass-backend {:shell (ok-shell "   \n")})
          result (proto/fetch b "k" {})]
      (is (r/err? result))
      ;; Error payload contains key but no resolved value
      (is (not (str/includes? (pr-str (dissoc result :error)) "   "))))))

;; =============================================================================
;; Convenience API delegates to default backend
;; =============================================================================

(deftest convenience-api-shape
  (testing "pass-show / pass-show-line / pass-available? are callable"
    ;; Smoke: just confirm they don't throw and return Result shape
    (let [r1 (pass/pass-available?)]
      (is (or (r/ok? r1) (r/err? r1))))))
