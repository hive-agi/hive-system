(ns hive-system.remote.ssh-test
  "The ssh IRemoteHost over stub IShell / IProcess ports, and with-host's
   release-on-every-path guarantee over a stub IHostProvider. No real host."
  (:require [clojure.test :refer [deftest is testing]]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [hive-system.remote.ports :as ports]
            [hive-system.remote.ssh :as ssh]
            [hive-system.remote.target :as t]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(defn- recording-shell
  "IShell stub: records [argv opts] and answers (respond argv)."
  [calls respond]
  (reify proto/IShell
    (shell-exec! [_ cmd opts] (swap! calls conj [cmd opts]) (respond cmd))
    (shell-env [_] {})
    (shell-which [_ program] (r/ok {:path (str "/usr/bin/" program)}))))

(defn- exit [n] (fn [_] (r/ok {:exit n :stdout "" :stderr (if (zero? n) "" "boom") :duration-ms 1.0})))

(defn- recording-process
  "IProcess stub: spawn answers a fake handle, signal records it."
  [spawned signalled]
  (reify proto/IProcess
    (process-spawn! [_ cmd _opts]
      (let [h {:pid (+ 100 (count @spawned)) :cmd cmd}]
        (swap! spawned conj h)
        (r/ok h)))
    (process-wait! [_ _ _] (r/ok {:exit-code 0}))
    (process-signal! [_ handle signal] (swap! signalled conj [(:pid handle) signal]) (r/ok {:delivered? true}))
    (process-pipe! [_ _ _] (r/ok {}))))

(def ^:private target {:host "pod" :user "root" :port 2222})

(defn- host
  ([respond] (host respond (atom []) (atom []) (atom [])))
  ([respond calls spawned signalled]
   (ssh/ssh-host target (recording-shell calls respond) (recording-process spawned signalled))))

(deftest exec-runs-the-target-argv-and-keeps-a-nonzero-exit-as-data
  (let [calls (atom [])
        h     (host (exit 3) calls (atom []) (atom []))
        res   (ports/remote-exec! h ["cat" "/etc/os-release"] {:in "secret" :timeout-ms 5})]
    (is (r/ok? res))
    (is (= 3 (:exit (:ok res))))
    (is (= [[(t/exec-argv target ["cat" "/etc/os-release"]) {:timeout-ms 5 :in "secret"}]] @calls))))

(deftest copies-fail-loudly-on-nonzero-exit
  (testing "ok on exit 0"
    (let [calls (atom [])
          res   (ports/remote-put! (host (exit 0) calls (atom []) (atom [])) "/l/w.jar" "/r/w.jar" {})]
      (is (= (r/ok {:local-path "/l/w.jar" :remote-path "/r/w.jar"}) res))
      (is (= (t/put-argv target "/l/w.jar" "/r/w.jar") (ffirst @calls)))))
  (testing "err on exit 1, carrying exit and stderr"
    (let [res (ports/remote-get! (host (exit 1)) "/r/log" "/l/log" {})]
      (is (r/err? res))
      (is (= :remote/get-failed (:error res)))
      (is (= 1 (:exit res)))
      (is (= "boom" (:stderr res)))))
  (testing "a shell err passes through unchanged"
    (let [e (r/err :shell/timeout {:timeout-ms 5})]
      (is (= e (ports/remote-put! (host (constantly e)) "/a" "/b" {}))))))

(deftest health-is-data-on-every-outcome
  (is (= (r/ok {:reachable? true}) (ports/remote-health (host (exit 0)))))
  (is (= false (:reachable? (:ok (ports/remote-health (host (exit 255)))))))
  (is (= {:reachable? false :reason :shell/timeout}
         (:ok (ports/remote-health (host (constantly (r/err :shell/timeout {}))))))))

(deftest forwards-are-held-then-released-once
  (let [spawned   (atom [])
        signalled (atom [])
        h         (host (exit 0) (atom []) spawned signalled)
        f1        (ports/remote-forward! h 17888 7888 {})
        f2        (ports/remote-forward! h 19530 19530 {:remote-host "10.0.0.5"})]
    (is (r/ok? f1))
    (is (= "forward-19530-10.0.0.5-19530" (:forward-id (:ok f2))))
    (is (= [(t/forward-argv target 17888 7888 "127.0.0.1")
            (t/forward-argv target 19530 19530 "10.0.0.5")]
           (mapv :cmd @spawned)))
    (is (= (r/ok {:closed 2}) (ports/remote-release! h)))
    (is (= #{[100 :term] [101 :term]} (set @signalled)))
    (testing "release is idempotent"
      (is (= (r/ok {:closed 0}) (ports/remote-release! h)))
      (is (= 2 (count @signalled))))))

;; =============================================================================
;; with-host
;; =============================================================================

(defn- stub-provider
  "IHostProvider stub over `h`; records terminations. `provision-result`
   overrides the provision answer."
  ([h terminated] (stub-provider h terminated nil))
  ([h terminated provision-result]
   (reify ports/IHostProvider
     (provision! [_ _spec] (or provision-result (r/ok {:id "pod-1" :host h})))
     (terminate! [_ id] (swap! terminated conj id) (r/ok {:id id})))))

(deftest with-host-releases-and-terminates-on-every-path
  (doseq [[label body] [[:ok    (fn [h] (ports/remote-forward! h 1 2 {}) (r/ok :done))]
                        [:err   (fn [h] (ports/remote-forward! h 1 2 {}) (r/err :job/failed {}))]
                        [:throw (fn [h] (ports/remote-forward! h 1 2 {}) (throw (ex-info "job blew up" {})))]]]
    (testing (name label)
      (let [signalled  (atom [])
            terminated (atom [])
            h          (host (exit 0) (atom []) (atom []) signalled)
            res        (try (ports/with-host (stub-provider h terminated) {:gpu "A40"} body)
                            (catch clojure.lang.ExceptionInfo e (ex-message e)))]
        (case label
          :ok    (is (= (r/ok :done) res))
          :err   (is (= :job/failed (:error res)))
          :throw (is (= "job blew up" res)))
        (is (= [[100 :term]] @signalled) "forward released")
        (is (= ["pod-1"] @terminated) "host terminated")))))

(deftest with-host-skips-body-and-terminate-when-provision-fails
  (let [terminated (atom [])
        called     (atom false)
        e          (r/err :provider/no-capacity {})
        res        (ports/with-host (stub-provider nil terminated e) {} (fn [_] (reset! called true)))]
    (is (= e res))
    (is (false? @called))
    (is (empty? @terminated))))
