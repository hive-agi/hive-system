(ns hive-system.remote.k8s-test
  "The k8s IRemoteHost / IHostProvider over stub IShell / IProcess ports.
   No cluster."
  (:require [clojure.test :refer [deftest is testing]]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [hive-system.remote.k8s :as k8s]
            [hive-system.remote.ports :as ports]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(defn- shell [calls respond]
  (reify proto/IShell
    (shell-exec! [_ cmd opts] (swap! calls conj [cmd opts]) (respond cmd))
    (shell-env [_] {})
    (shell-which [_ p] (r/ok {:path p}))))

(defn- exit [n] (fn [_] (r/ok {:exit n :stdout "" :stderr (if (zero? n) "" "boom") :duration-ms 1.0})))

(defn- process [spawned signalled]
  (reify proto/IProcess
    (process-spawn! [_ cmd _] (let [h {:pid (+ 100 (count @spawned)) :cmd cmd}] (swap! spawned conj h) (r/ok h)))
    (process-wait! [_ _ _] (r/ok {:exit-code 0}))
    (process-signal! [_ h sig] (swap! signalled conj [(:pid h) sig]) (r/ok {:delivered? true}))
    (process-pipe! [_ _ _] (r/ok {}))))

(def ^:private t {:namespace "hive-docs" :pod "web-0" :container "nginx" :context "admin@blw"})

(deftest argv-shapes
  (is (= ["kubectl" "--context" "admin@blw" "-n" "hive-docs" "exec" "-i" "web-0" "-c" "nginx" "--" "uname" "-a"]
         (k8s/exec-argv t ["uname" "-a"])))
  (is (= ["kubectl" "-n" "ns" "exec" "-i" "p" "--" "sh" "-c" "echo $HOME"]
         (k8s/exec-argv {:namespace "ns" :pod "p"} "echo $HOME")))
  (is (= ["kubectl" "--context" "admin@blw" "-n" "hive-docs" "cp" "-c" "nginx" "/l/a" "hive-docs/web-0:/r/a"]
         (k8s/put-argv t "/l/a" "/r/a")))
  (is (= ["kubectl" "-n" "ns" "cp" "ns/p:/r/a" "/l/a"] (k8s/get-argv {:namespace "ns" :pod "p"} "/r/a" "/l/a")))
  (is (= ["kubectl" "-n" "ns" "port-forward" "--address" "127.0.0.1" "pod/p" "17888:7888"]
         (k8s/forward-argv {:namespace "ns" :pod "p"} 17888 7888))))

(deftest first-running-skips-other-phases
  (is (= "b" (k8s/first-running "a Pending\nb Running\nc Running\n")))
  (is (nil? (k8s/first-running "a Terminating\n")))
  (is (nil? (k8s/first-running nil))))

(deftest host-exec-copy-health
  (let [calls (atom [])
        h     (k8s/k8s-host t (shell calls (exit 3)) (process (atom []) (atom [])))]
    (is (= 3 (:exit (:ok (ports/remote-exec! h ["ls"] {:in "x" :timeout-ms 5})))))
    (is (= [(k8s/exec-argv t ["ls"]) {:timeout-ms 5 :in "x"}] (first @calls)))
    (is (= :remote/put-failed (:error (ports/remote-put! h "/l" "/r" {}))))
    (is (= {:reachable? false :exit 3 :stderr "boom"} (:ok (ports/remote-health h)))))
  (let [h (k8s/k8s-host t (shell (atom []) (exit 0)) (process (atom []) (atom [])))]
    (is (= (r/ok {:remote-path "/r" :local-path "/l"}) (ports/remote-get! h "/r" "/l" {})))
    (is (= (r/ok {:reachable? true}) (ports/remote-health h)))))

(deftest forwards-held-then-released-and-off-pod-refused
  (let [spawned (atom []) signalled (atom [])
        h       (k8s/k8s-host t (shell (atom []) (exit 0)) (process spawned signalled))]
    (is (r/ok? (ports/remote-forward! h 17888 7888 {})))
    (is (= :remote/forward-unsupported (:error (ports/remote-forward! h 1 2 {:remote-host "10.0.0.5"}))))
    (is (= [(k8s/forward-argv t 17888 7888)] (mapv :cmd @spawned)))
    (is (= (r/ok {:closed 1}) (ports/remote-release! h)))
    (is (= (r/ok {:closed 0}) (ports/remote-release! h)))
    (is (= [[100 :term]] @signalled))))

(deftest provider-attaches-by-name-or-selector
  (let [calls (atom [])
        sh    (shell calls (fn [cmd] (if (some #{"get"} cmd)
                                       (r/ok {:exit 0 :stdout "x-1 Pending\nx-2 Running\n" :stderr "" :duration-ms 1.0})
                                       (r/ok {:exit 0 :stdout "" :stderr "" :duration-ms 1.0}))))
        prov  (:ok (ports/host-provider {:kind :k8s :shell sh :process (process (atom []) (atom []))}))]
    (is (= "ns/x-2" (:id (:ok (ports/provision! prov {:namespace "ns" :selector "app=x"})))))
    (is (= "ns/named" (:id (:ok (ports/provision! prov {:namespace "ns" :pod "named"})))))
    (is (= 1 (count @calls)) "a named pod needs no lookup")
    (testing "spec must name exactly one of :pod / :selector"
      (is (= :remote/invalid-spec (:error (ports/provision! prov {:namespace "ns"}))))
      (is (= :remote/invalid-spec (:error (ports/provision! prov {:namespace "ns" :pod "a" :selector "b"})))))
    (is (= false (:terminated? (:ok (ports/terminate! prov "ns/x-2")))))))

(deftest provider-lookup-errs-are-data
  (let [none (k8s/k8s-provider (shell (atom []) (fn [_] (r/ok {:exit 0 :stdout "a Pending\n" :stderr "" :duration-ms 1.0})))
                               (process (atom []) (atom [])))
        fail (k8s/k8s-provider (shell (atom []) (exit 1)) (process (atom []) (atom [])))]
    (is (= :remote/no-running-pod (:error (ports/provision! none {:namespace "ns" :selector "app=x"}))))
    (is (= :remote/pod-lookup-failed (:error (ports/provision! fail {:namespace "ns" :selector "app=x"}))))))
