(ns hive-system.remote.tailnet
  "IHostProvider over a Tailscale tailnet. A tailnet host already exists and
   is not ours to create or destroy: provision! RESOLVES a named peer from
   `tailscale status --json` (read through IShell), refuses it when offline,
   and answers an ssh IRemoteHost aimed at its MagicDNS name (or first
   tailnet IPv4). terminate! is a no-op that says so.

   Parsing is pure (peers, find-peer, peer-target); only provision! touches
   the shell."
  (:require [clojure.data.json :as json]
            [clojure.string :as str]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [hive-system.remote.ports :as ports]
            [hive-system.remote.ssh :as ssh]
            [malli.core :as m]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(def Peer
  "One tailnet node, reduced from tailscale's JSON."
  [:map
   [:hostname :string]
   [:dns-name [:maybe :string]]
   [:ips [:vector :string]]
   [:online? :boolean]
   [:self? :boolean]])

(def TailnetSpec
  "provision! spec: the peer to reach and how to log in. :peer matches a
   HostName or the MagicDNS name (whole or first label), case-insensitively.
   :address :dns (default) or :ipv4."
  [:map
   [:peer [:string {:min 1}]]
   [:user {:optional true} [:maybe [:string {:min 1}]]]
   [:port {:optional true} [:maybe [:int {:min 1 :max 65535}]]]
   [:identity-file {:optional true} [:maybe [:string {:min 1}]]]
   [:connect-timeout-s {:optional true} [:maybe [:int {:min 1}]]]
   [:address {:optional true} [:enum :dns :ipv4]]
   [:allow-offline? {:optional true} :boolean]])

(defn- ->peer
  [node self?]
  {:hostname (or (get node "HostName") "")
   :dns-name (some-> (get node "DNSName") (str/replace #"\.$" "") not-empty)
   :ips      (vec (get node "TailscaleIPs"))
   :online?  (boolean (or self? (get node "Online")))
   :self?    (boolean self?)})

(defn peers
  "Every node in a parsed `tailscale status --json` body, self first."
  [status]
  (into (if-let [s (get status "Self")] [(->peer s true)] [])
        (map #(->peer % false))
        (vals (get status "Peer"))))

(m/=> peers [:=> [:cat :map] [:vector Peer]])

(defn- matches?
  [wanted {:keys [hostname dns-name]}]
  (let [w (str/lower-case wanted)]
    (or (= w (str/lower-case hostname))
        (and dns-name (= w (str/lower-case dns-name)))
        (and dns-name (= w (str/lower-case (first (str/split dns-name #"\."))))))))

(defn find-peer
  "Result<Peer> named `wanted` in `ps`; err :remote/peer-not-found otherwise."
  [ps wanted]
  (if-let [p (first (filter #(matches? wanted %) ps))]
    (r/ok p)
    (r/err :remote/peer-not-found {:peer wanted :known (mapv :hostname ps)})))

(m/=> find-peer [:=> [:cat [:vector Peer] :string] :any])

(defn- ipv4 [ips] (first (filter #(re-matches #"\d+\.\d+\.\d+\.\d+" %) ips)))

(defn peer-target
  "Result<HostTarget> reaching `peer` as `spec` asks. An offline peer is
   err :remote/peer-offline unless :allow-offline?."
  [peer spec]
  (let [addr (if (= :ipv4 (:address spec))
               (ipv4 (:ips peer))
               (or (:dns-name peer) (ipv4 (:ips peer))))]
    (cond
      (and (not (:online? peer)) (not (:allow-offline? spec)))
      (r/err :remote/peer-offline {:peer (:hostname peer)})

      (str/blank? addr)
      (r/err :remote/peer-unaddressable {:peer (:hostname peer) :address (:address spec :dns)})

      :else
      (r/ok (into {:host addr}
                  (filter (comp some? val))
                  (select-keys spec [:user :port :identity-file :connect-timeout-s]))))))

(m/=> peer-target [:=> [:cat Peer TailnetSpec] :any])

(defn- status!
  [shell]
  (r/let-ok [res (proto/shell-exec! shell ["tailscale" "status" "--json"] {:timeout-ms 15000})]
    (let [{:keys [exit stdout stderr]} res]
      (if (zero? exit)
        (r/try-effect* :remote/tailnet-status-unparsable (json/read-str stdout))
        (r/err :remote/tailnet-status-failed {:exit exit :stderr stderr})))))

(defrecord TailnetProvider [shell process]
  ports/IHostProvider
  (provision! [_ spec]
    (if-not (m/validate TailnetSpec spec)
      (r/err :remote/invalid-spec {:explain (m/explain TailnetSpec spec)})
      (r/let-ok [status (status! shell)
                 peer   (find-peer (peers status) (:peer spec))
                 tgt    (peer-target peer spec)]
        (r/ok {:id   (:hostname peer)
               :peer peer
               :host (ssh/ssh-host tgt shell process)}))))
  (terminate! [_ id]
    (r/ok {:id id :terminated? false :reason :remote/not-owned})))

(defn tailnet-provider
  "An IHostProvider resolving tailnet peers through `shell` (IShell) and
   reaching them with ssh over `shell` and `process` (IProcess)."
  [shell process]
  (->TailnetProvider shell process))

(defmethod ports/host-provider :tailnet [{:keys [shell process]}]
  (if (and shell process)
    (r/ok (tailnet-provider shell process))
    (r/err :remote/invalid-config {:kind :tailnet :needs [:shell :process]})))
