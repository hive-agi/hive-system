(ns hive-system.shell.core-test
  "Tests for IShell implementation — exec!, exec-ok!, which, env.
   Golden tests snapshot exec behavior. Property tests verify Result
   railway semantics. Mutation tests catch blind spots in error handling."
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.test.check.generators :as gen]
            [hive-test.golden :refer [deftest-golden]]
            [hive-test.mutation :refer [deftest-mutation-witness]]
            [hive-test.properties :refer [defprop-total defprop-complement]]
            [hive-dsl.result :as r]
            [hive-system.shell.core :as sh]
            [hive-system.protocols :as proto]))

;; =============================================================================
;; Golden: exec! output shape (deterministic command)
;; =============================================================================

(deftest-golden exec-echo-shape
  "test/golden/shell/exec-echo.edn"
  (let [result (sh/exec! "echo deterministic")]
    ;; Strip duration (non-deterministic) for golden
    (update result :ok dissoc :duration-ms)))

;; =============================================================================
;; Unit: exec! returns proper Result on success
;; =============================================================================

(deftest exec-success
  (testing "exec! captures stdout, stderr, exit code"
    (let [result (sh/exec! "echo hello")]
      (is (r/ok? result))
      (is (zero? (get-in result [:ok :exit])))
      (is (= "hello\n" (get-in result [:ok :stdout])))
      (is (= "" (get-in result [:ok :stderr])))
      (is (number? (get-in result [:ok :duration-ms]))))))

(deftest exec-failure
  (testing "exec! returns ok even on non-zero exit (exit code in value)"
    (let [result (sh/exec! "exit 42")]
      (is (r/ok? result))
      (is (= 42 (get-in result [:ok :exit]))))))

(deftest exec-stderr-capture
  (testing "exec! captures stderr separately"
    (let [result (sh/exec! "echo err >&2")]
      (is (r/ok? result))
      (is (= "err\n" (get-in result [:ok :stderr]))))))

;; =============================================================================
;; Unit: exec-ok! enforces zero exit
;; =============================================================================

(deftest exec-ok-success
  (testing "exec-ok! returns ok for zero exit"
    (let [result (sh/exec-ok! "true")]
      (is (r/ok? result)))))

(deftest exec-ok-failure
  (testing "exec-ok! returns err for non-zero exit"
    (let [result (sh/exec-ok! "false")]
      (is (r/err? result))
      (is (= :shell/non-zero-exit (:error result))))))

;; =============================================================================
;; Unit: exec! with options
;; =============================================================================

(deftest exec-with-dir
  (testing "exec! respects :dir option"
    (let [result (sh/exec! "pwd" {:dir "/tmp"})]
      (is (r/ok? result))
      (is (= "/tmp\n" (get-in result [:ok :stdout]))))))

(deftest exec-with-env
  (testing "exec! injects :env vars"
    (let [result (sh/exec! "echo $MY_VAR" {:env {"MY_VAR" "hello-hive"}})]
      (is (r/ok? result))
      (is (= "hello-hive\n" (get-in result [:ok :stdout]))))))

(deftest exec-with-timeout
  (testing "exec! returns :shell/timeout on deadline exceeded"
    (let [result (sh/exec! "sleep 10" {:timeout-ms 100})]
      ;; The try-effect wraps the timeout err into an ok of err, need to check
      (is (or (r/err? result)
              (and (r/ok? result)
                   (= :shell/timeout (:error (:ok result)))))))))

;; =============================================================================
;; Unit: exec! with vector command (no shell interpretation)
;; =============================================================================

(deftest exec-vector-command
  (testing "exec! accepts a vector of args (no shell expansion)"
    (let [result (sh/exec! ["echo" "hello" "world"])]
      (is (r/ok? result))
      (is (= "hello world\n" (get-in result [:ok :stdout]))))))

;; =============================================================================
;; Unit: env returns map
;; =============================================================================

(deftest env-returns-map
  (testing "env returns a map with PATH"
    (let [e (sh/env)]
      (is (map? e))
      (is (contains? e "PATH"))
      (is (string? (get e "PATH"))))))

;; =============================================================================
;; Unit: which delegates to detect
;; =============================================================================

(deftest which-delegates
  (testing "sh/which resolves known binaries"
    (is (r/ok? (sh/which "sh")))
    (is (r/err? (sh/which "nonexistent-xyz")))))

;; =============================================================================
;; Unit: IShell protocol satisfied
;; =============================================================================

(deftest shell-satisfies-protocol
  (testing "Shell record satisfies IShell"
    (let [s (sh/make-shell)]
      (is (satisfies? proto/IShell s)))))

;; =============================================================================
;; Mutation: exec! error path — broken ProcessBuilder must be caught
;; =============================================================================

(deftest-mutation-witness exec-error-caught
  hive-system.shell.core/exec!
  ;; Mutant: always return ok with fake data
  (fn
    ([_] (r/ok {:exit 0 :stdout "fake" :stderr "" :duration-ms 0 :cmd "fake"}))
    ([_ _] (r/ok {:exit 0 :stdout "fake" :stderr "" :duration-ms 0 :cmd "fake"})))
  (fn []
    (let [result (sh/exec! "echo real-output")]
      (is (r/ok? result))
      (is (= "real-output\n" (get-in result [:ok :stdout]))))))

;; =============================================================================
;; Property: exec! is total for safe commands
;; =============================================================================

(defprop-total exec-total
  (fn [s] (sh/exec! (str "echo " s) {:timeout-ms 5000}))
  gen/string-alphanumeric
  {:num-tests 30
   :pred (fn [r] (or (r/ok? r) (r/err? r)))})

;; =============================================================================
;; Property: exec-ok! ok? and err? are complements
;; =============================================================================

(defprop-complement exec-ok-complement
  r/ok? r/err?
  (gen/fmap (fn [exit-code]
              (sh/exec-ok! (str "exit " exit-code)))
            (gen/choose 0 2))
  {:num-tests 20})
