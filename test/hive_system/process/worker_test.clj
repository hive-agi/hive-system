(ns hive-system.process.worker-test
  "Tests for IWorker — warm request/response over a long-lived process.
   Isolation: spawns only an ephemeral awk line-echo worker it creates and
   reaps; never a live/shared system."
  (:require [clojure.test :refer [deftest is testing]]
            [hive-dsl.result :as r]
            [hive-system.process.worker :as w]
            [hive-system.protocols :as proto]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: AGPL-3.0-or-later

;; awk echoes each stdin line to stdout and flushes -> a warm line-echo worker
;; speaking the newline-delimited EDN protocol (echoes the request, which
;; carries the injected :id, back as the response).
(def ^:private echo-worker ["awk" "{ print; fflush() }"])

(deftest spawn-warm-returns-worker
  (testing "spawn-warm! returns ok with an IWorker"
    (let [res (w/spawn-warm! echo-worker)]
      (is (r/ok? res))
      (is (satisfies? proto/IWorker (:ok res)))
      (w/stop! (:ok res)))))

(deftest warm-call-roundtrip
  (testing "worker-call! frames a request and reads the echoed response"
    (let [worker (:ok (w/spawn-warm! echo-worker))
          resp (w/call! worker {:op :ping} 5000)]
      (is (r/ok? resp))
      (is (= :ping (:op (:ok resp))))
      (is (= 1 (:id (:ok resp))))
      (w/stop! worker))))

(deftest warm-worker-stays-warm
  (testing "successive calls reuse the same process; id increments monotonically"
    (let [worker (:ok (w/spawn-warm! echo-worker))
          r1 (w/call! worker {:op :a} 5000)
          r2 (w/call! worker {:op :b} 5000)]
      (is (= 1 (:id (:ok r1))))
      (is (= 2 (:id (:ok r2))))
      (is (:alive? (:ok (w/health worker))))
      (w/stop! worker))))

(deftest warm-worker-stop-terminates
  (testing "worker-stop! terminates the underlying process"
    (let [worker (:ok (w/spawn-warm! echo-worker))]
      (w/call! worker {:op :ping} 5000)
      (w/stop! worker)
      (Thread/sleep 200)
      (is (false? (:alive? (:ok (w/health worker))))))))

(deftest worker-satisfies-protocol
  (testing "Worker record satisfies IWorker"
    (let [worker (:ok (w/spawn-warm! echo-worker))]
      (is (satisfies? proto/IWorker worker))
      (w/stop! worker))))
