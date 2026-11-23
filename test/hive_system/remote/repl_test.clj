(ns hive-system.remote.repl-test
  "IReplEndpoint over a scripted IRemoteHost stub. No real host."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [hive-dsl.result :as r]
            [hive-system.remote.ports :as ports]
            [hive-system.remote.repl :as repl]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(defn- host
  "IRemoteHost stub. `probe-exits` is the seq of exit codes the readiness
   probe answers, in order; every other exec answers `launch-exit`."
  [execs forwards {:keys [probe-exits launch-exit] :or {probe-exits [1 0] launch-exit 0}}]
  (let [probes (atom probe-exits)]
    (reify ports/IRemoteHost
      (remote-exec! [_ cmd _]
        (swap! execs conj cmd)
        (let [code (if (str/includes? cmd "kill -0")
                     (let [c (first @probes)] (when (next @probes) (swap! probes rest)) c)
                     launch-exit)]
          (r/ok {:exit code :stdout "" :stderr "" :duration-ms 1.0})))
      (remote-put! [_ _ _ _] (r/ok {}))
      (remote-get! [_ _ _ _] (r/ok {}))
      (remote-forward! [_ l rp _] (swap! forwards conj [l rp]) (r/ok {:forward-id (str "f-" l) :local-port l :remote-port rp}))
      (remote-health [_] (r/ok {:reachable? true}))
      (remote-release! [_] (r/ok {:closed 0})))))

(def ^:private spec {:runtime :bb :remote-port 7888 :local-port 17888 :poll-ms 10 :ready-timeout-ms 100})

(defn- ep [h] (repl/nrepl-endpoint h {:sleep! (fn [_] nil)}))

(deftest server-argv-is-open-by-runtime
  (is (= ["bb" "nrepl-server" "127.0.0.1:7888"] (repl/server-argv spec)))
  (is (= ["clojure" "-Sdeps" "{:deps {nrepl/nrepl {:mvn/version \"1.3.1\"}}}" "-M:dev:test"
          "-m" "nrepl.cmdline" "--bind" "127.0.0.1" "--port" "7888"]
         (repl/server-argv {:runtime :clojure-cli :remote-port 7888 :aliases [:dev :test]})))
  (is (= ["nc" "-l"] (repl/server-argv {:runtime :shell :argv ["nc" "-l"]}))))

(deftest launch-command-detaches-and-records-the-pid
  (is (= (str "cd /srv/app && if command -v setsid >/dev/null 2>&1; then nohup setsid bb nrepl-server 127.0.0.1:7888"
              "; else nohup bb nrepl-server 127.0.0.1:7888; fi"
              " >/tmp/hive-repl-7888.log 2>&1 </dev/null & echo $! >/tmp/hive-repl-7888.pid")
         (repl/launch-command (assoc spec :dir "/srv/app")))))

(deftest open-launches-waits-forwards-then-close-stops
  (let [execs (atom []) fwds (atom [])
        e     (ep (host execs fwds {:probe-exits [1 1 0]}))
        res   (repl/repl-open! e spec)]
    (is (= (r/ok {:host "127.0.0.1" :port 17888 :remote-port 7888 :forward-id "f-17888"
                  :pid-file "/tmp/hive-repl-7888.pid"})
           res))
    (is (= [(repl/launch-command spec) (repl/probe-command spec) (repl/probe-command spec) (repl/probe-command spec)] @execs))
    (is (= [[17888 7888]] @fwds) "forwarded only once listening")
    (is (r/ok? (repl/repl-close! e)))
    (is (= (repl/stop-command spec) (last @execs)))
    (testing "close is idempotent"
      (is (= :not-open (:reason (:ok (repl/repl-close! e))))))))

(deftest open-errs-are-data-and-never-forward
  (testing "server died"
    (let [fwds (atom [])]
      (is (= :remote/repl-died (:error (repl/repl-open! (ep (host (atom []) fwds {:probe-exits [3]})) spec))))
      (is (empty? @fwds))))
  (testing "never listens"
    (is (= :remote/repl-not-listening (:error (repl/repl-open! (ep (host (atom []) (atom []) {:probe-exits [1]})) spec)))))
  (testing "launch failed"
    (is (= :remote/repl-launch-failed (:error (repl/repl-open! (ep (host (atom []) (atom []) {:launch-exit 127})) spec)))))
  (testing "unknown runtime and bad spec"
    (is (= :remote/unknown-runtime (:error (repl/repl-open! (ep (host (atom []) (atom []) {})) (assoc spec :runtime :cobol)))))
    (is (= :remote/invalid-spec (:error (repl/repl-open! (ep (host (atom []) (atom []) {})) {:runtime :bb}))))))

(deftest with-repl-stops-the-server-on-every-path
  (doseq [f [(fn [_] (r/ok :ran)) (fn [_] (throw (ex-info "boom" {})))]]
    (let [execs (atom [])]
      (try (repl/with-repl (host execs (atom []) {:probe-exits [0]}) spec f) (catch Exception _ nil))
      (is (= (repl/stop-command spec) (last @execs))))))
