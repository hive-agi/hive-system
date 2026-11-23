(ns hive-system.remote.tailnet-test
  "The tailnet IHostProvider over a stub IShell answering a canned
   `tailscale status --json`. No real tailnet."
  (:require [clojure.data.json :as json]
            [clojure.test :refer [deftest is testing]]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [hive-system.remote.ports :as ports]
            [hive-system.remote.tailnet :as tailnet]
            [hive-system.remote.target :as t]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(def ^:private status
  {"Self" {"HostName" "alpha" "DNSName" "alpha.tailnet.example." "TailscaleIPs" ["100.64.0.1"] "Online" false}
   "Peer" {"k1" {"HostName" "beta" "DNSName" "beta.tailnet.example."
                 "TailscaleIPs" ["100.64.0.2" "fd7a:115c:a1e0::2"] "Online" true}
           "k2" {"HostName" "gamma" "DNSName" "gamma.tailnet.example."
                 "TailscaleIPs" ["100.64.0.3"] "Online" false}}})

(defn- shell
  "IShell stub: `tailscale status --json` answers `answer`; records every argv."
  [calls answer]
  (reify proto/IShell
    (shell-exec! [_ cmd _opts] (swap! calls conj cmd) answer)
    (shell-env [_] {})
    (shell-which [_ p] (r/ok {:path p}))))

(def ^:private ok-status (r/ok {:exit 0 :stdout (json/write-str status) :stderr "" :duration-ms 1.0}))

(def ^:private process
  (reify proto/IProcess
    (process-spawn! [_ cmd _] (r/ok {:pid 1 :cmd cmd}))
    (process-wait! [_ _ _] (r/ok {:exit-code 0}))
    (process-signal! [_ _ _] (r/ok {:delivered? true}))
    (process-pipe! [_ _ _] (r/ok {}))))

(deftest peers-reads-self-and-peers
  (let [ps (tailnet/peers status)]
    (is (= 3 (count ps)))
    (is (= {:hostname "alpha" :dns-name "alpha.tailnet.example" :ips ["100.64.0.1"] :online? true :self? true}
           (first ps)) "self counts as online and the trailing dot is dropped")))

(deftest find-peer-matches-hostname-and-dns-label
  (let [ps (tailnet/peers status)]
    (is (= "beta" (:hostname (:ok (tailnet/find-peer ps "BeTa")))))
    (is (= "beta" (:hostname (:ok (tailnet/find-peer ps "beta.tailnet.example")))))
    (is (= :remote/peer-not-found (:error (tailnet/find-peer ps "nope"))))))

(deftest peer-target-addresses-and-refuses-offline
  (let [ps (tailnet/peers status)
        wh (:ok (tailnet/find-peer ps "beta"))
        di (:ok (tailnet/find-peer ps "gamma"))]
    (is (= (r/ok {:host "beta.tailnet.example" :user "root" :port 2222})
           (tailnet/peer-target wh {:peer "beta" :user "root" :port 2222 :identity-file nil})))
    (is (= "100.64.0.2" (:host (:ok (tailnet/peer-target wh {:peer "beta" :address :ipv4})))))
    (is (= :remote/peer-offline (:error (tailnet/peer-target di {:peer "gamma"}))))
    (is (r/ok? (tailnet/peer-target di {:peer "gamma" :allow-offline? true})))))

(deftest provision-answers-an-ssh-host-aimed-at-the-peer
  (let [calls (atom [])
        prov  (:ok (ports/host-provider {:kind :tailnet :shell (shell calls ok-status) :process process}))
        res   (ports/provision! prov {:peer "beta" :user "root"})
        host  (:host (:ok res))]
    (is (= "beta" (:id (:ok res))))
    (ports/remote-exec! host ["uname" "-a"] {})
    (is (= [["tailscale" "status" "--json"]
            (t/exec-argv {:host "beta.tailnet.example" :user "root"} ["uname" "-a"])]
           @calls))
    (testing "terminate never destroys a tailnet host"
      (is (= false (:terminated? (:ok (ports/terminate! prov "beta"))))))))

(deftest provision-errs-are-data
  (let [prov (tailnet/tailnet-provider (shell (atom []) ok-status) process)]
    (is (= :remote/invalid-spec (:error (ports/provision! prov {}))))
    (is (= :remote/peer-offline (:error (ports/provision! prov {:peer "gamma"})))))
  (let [failing (tailnet/tailnet-provider
                 (shell (atom []) (r/ok {:exit 1 :stdout "" :stderr "not logged in" :duration-ms 1.0})) process)]
    (is (= :remote/tailnet-status-failed (:error (ports/provision! failing {:peer "beta"})))))
  (let [garbled (tailnet/tailnet-provider
                 (shell (atom []) (r/ok {:exit 0 :stdout "{nope" :stderr "" :duration-ms 1.0})) process)]
    (is (r/err? (ports/provision! garbled {:peer "beta"})))))

(deftest registry-is-open-and-unknown-kinds-are-errs
  (is (= :remote/unknown-provider (:error (ports/host-provider {:kind :mars}))))
  (is (= :remote/invalid-config (:error (ports/host-provider {:kind :tailnet})))))
