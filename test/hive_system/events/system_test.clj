(ns hive-system.events.system-test
  "Tests for the event-driven system layer.
   Verifies event dispatch, interceptor chain, journal recording,
   and tool-check short-circuiting."
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [clojure.test.check.generators :as gen]
            [hive-test.golden :refer [deftest-golden]]
            [hive-test.properties :refer [defprop-total]]
            [hive-dsl.result :as r]
            [hive-system.events.system :as sys]
            [hive.events :as ev]))

;; =============================================================================
;; Fixture: init/shutdown per test
;; =============================================================================

(def ^:private journal-log (atom []))

(defn- test-journal-fn [op-map]
  (swap! journal-log conj op-map))

(use-fixtures :each
  (fn [f]
    (reset! journal-log [])
    (sys/init! {:journal-fn test-journal-fn})
    (try (f)
         (finally (sys/shutdown!)))))

;; =============================================================================
;; Golden: dispatch-result shape for echo
;; =============================================================================

(deftest-golden event-exec-echo
  "test/golden/events/exec-echo.edn"
  (let [result (sys/dispatch-result [:sys/exec "echo event-driven"])]
    (update result :ok dissoc :duration-ms)))

;; =============================================================================
;; Unit: :sys/exec dispatches and returns Result
;; =============================================================================

(deftest exec-event-success
  (testing "dispatch :sys/exec returns ok Result"
    (let [result (sys/dispatch-result [:sys/exec "echo hello"])]
      (is (r/ok? result))
      (is (= "hello\n" (get-in result [:ok :stdout])))
      (is (zero? (get-in result [:ok :exit]))))))

(deftest exec-event-failure
  (testing "dispatch :sys/exec with failing command still returns ok (non-zero exit)"
    (let [result (sys/dispatch-result [:sys/exec "exit 1"])]
      (is (r/ok? result))
      (is (= 1 (get-in result [:ok :exit]))))))

;; =============================================================================
;; Unit: :sys/exec-ok enforces zero exit via events
;; =============================================================================

(deftest exec-ok-event-success
  (testing ":sys/exec-ok returns ok for zero exit"
    (let [result (sys/dispatch-result [:sys/exec-ok "true"])]
      (is (r/ok? result)))))

(deftest exec-ok-event-failure
  (testing ":sys/exec-ok returns err for non-zero exit"
    (let [result (sys/dispatch-result [:sys/exec-ok "false"])]
      (is (r/err? result))
      (is (= :shell/non-zero-exit (:error result))))))

;; =============================================================================
;; Unit: :sys/exec with options
;; =============================================================================

(deftest exec-event-with-dir
  (testing ":sys/exec respects dir option"
    (let [result (sys/dispatch-result [:sys/exec "pwd" {:dir "/tmp"}])]
      (is (r/ok? result))
      (is (= "/tmp\n" (get-in result [:ok :stdout]))))))

(deftest exec-event-with-env
  (testing ":sys/exec injects env vars"
    (let [result (sys/dispatch-result [:sys/exec "echo $FOO" {:env {"FOO" "bar"}}])]
      (is (r/ok? result))
      (is (= "bar\n" (get-in result [:ok :stdout]))))))

;; =============================================================================
;; Unit: :sys/which
;; =============================================================================

(deftest which-event
  (testing ":sys/which resolves binaries"
    (let [ok-result (sys/dispatch-result [:sys/which "sh"])
          err-result (sys/dispatch-result [:sys/which "nonexistent-xyz"])]
      (is (r/ok? ok-result))
      (is (r/err? err-result)))))

;; =============================================================================
;; Unit: :sys/require-tool
;; =============================================================================

(deftest require-tool-event
  (testing ":sys/require-tool returns tool info or install hints"
    (let [result (sys/dispatch-result [:sys/require-tool :git])]
      (is (r/ok? result))
      (is (= :git (get-in result [:ok :tool]))))))

;; =============================================================================
;; Unit: :sys/require-tools batch
;; =============================================================================

(deftest require-tools-event
  (testing ":sys/require-tools returns partitioned map"
    (let [result (sys/dispatch-result [:sys/require-tools [:git :ls]])]
      (is (r/ok? result))
      (is (contains? (:ok result) :available)))))

;; =============================================================================
;; Unit: :sys/env
;; =============================================================================

(deftest env-event
  (testing ":sys/env returns environment map"
    (let [result (sys/dispatch-result [:sys/env])]
      (is (r/ok? result))
      (is (contains? (:ok result) "PATH")))))

;; =============================================================================
;; Journal: operations are recorded
;; =============================================================================

(deftest journal-records-exec
  (testing "journal-fn receives operation records"
    (sys/dispatch-result [:sys/exec "echo journal-test"])
    (is (= 1 (count @journal-log)))
    (let [entry (first @journal-log)]
      (is (= :sys/exec (:op-type entry)))
      (is (true? (:success? entry)))
      (is (number? (:duration-ms entry))))))

(deftest journal-records-failure
  (testing "journal records failed operations"
    (sys/dispatch-result [:sys/which "nonexistent-xyz"])
    (let [entry (last @journal-log)]
      (is (= :sys/which (:op-type entry)))
      (is (false? (:success? entry))))))

(deftest journal-records-multiple
  (testing "journal accumulates across dispatches"
    (sys/dispatch-result [:sys/exec "echo one"])
    (sys/dispatch-result [:sys/exec "echo two"])
    (sys/dispatch-result [:sys/which "sh"])
    (is (= 3 (count @journal-log)))))

;; =============================================================================
;; Property: all sys events are total (never throw)
;; =============================================================================

(defprop-total sys-exec-total
  (fn [s] (sys/dispatch-result [:sys/exec (str "echo " s)]))
  gen/string-alphanumeric
  {:num-tests 20
   :pred (fn [r] (or (r/ok? r) (r/err? r) (nil? r)))})
