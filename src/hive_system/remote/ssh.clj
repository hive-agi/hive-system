(ns hive-system.remote.ssh
  "IRemoteHost over the OpenSSH client, driven through the local IShell
   (exec, scp, health) and IProcess (held forwards) ports. Boundary only:
   argv comes from hive-system.remote.target."
  (:require [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [hive-system.remote.ports :as ports]
            [hive-system.remote.target :as target]
            [malli.core :as m]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(def ^:private default-timeout-ms 60000)

(def ^:private health-timeout-ms 15000)

(defn- shell-opts
  [opts]
  (cond-> {:timeout-ms (or (:timeout-ms opts) default-timeout-ms)}
    (some? (:in opts)) (assoc :in (:in opts))))

(defn- copy!
  "Run an scp argv; a non-zero exit becomes `err-key`."
  [shell argv opts err-key ok-value]
  (let [res (proto/shell-exec! shell argv (shell-opts opts))]
    (cond
      (r/err? res) res
      (zero? (:exit (:ok res))) (r/ok ok-value)
      :else (r/err err-key (merge ok-value (select-keys (:ok res) [:exit :stderr]))))))

(defrecord SshHost [target shell process forwards]
  ports/IRemoteHost
  (remote-exec! [_ cmd opts]
    (proto/shell-exec! shell (target/exec-argv target cmd) (shell-opts opts)))

  (remote-put! [_ local-path remote-path opts]
    (copy! shell (target/put-argv target local-path remote-path) opts
           :remote/put-failed {:local-path local-path :remote-path remote-path}))

  (remote-get! [_ remote-path local-path opts]
    (copy! shell (target/get-argv target remote-path local-path) opts
           :remote/get-failed {:remote-path remote-path :local-path local-path}))

  (remote-forward! [_ local-port remote-port opts]
    (let [remote-host (or (:remote-host opts) "127.0.0.1")
          argv        (target/forward-argv target local-port remote-port remote-host)
          spawned     (proto/process-spawn! process argv {:redirect-err? true})]
      (if (r/err? spawned)
        spawned
        (let [id (str "forward-" local-port "-" remote-host "-" remote-port)]
          (swap! forwards assoc id (:ok spawned))
          (r/ok {:forward-id id :local-port local-port :remote-port remote-port})))))

  (remote-health [_]
    (let [res (proto/shell-exec! shell (target/exec-argv target ["true"]) {:timeout-ms health-timeout-ms})]
      (cond
        (r/err? res) (r/ok {:reachable? false :reason (:error res)})
        (zero? (:exit (:ok res))) (r/ok {:reachable? true})
        :else (r/ok {:reachable? false :exit (:exit (:ok res)) :stderr (:stderr (:ok res))}))))

  (remote-release! [_]
    (let [[held _] (reset-vals! forwards {})
          signals  (mapv (fn [[id handle]] [id (proto/process-signal! process handle :term)]) held)
          failed   (into {} (filter (comp r/err? second)) signals)]
      (if (seq failed)
        (r/err :remote/release-failed {:closed (- (count signals) (count failed))
                                       :failed (vec (keys failed))})
        (r/ok {:closed (count signals)})))))

(defn ssh-host
  "An IRemoteHost reaching `target` (a HostTarget) through `shell` (IShell)
   and `process` (IProcess)."
  [target shell process]
  (->SshHost target shell process (atom {})))

(m/=> ssh-host [:=> [:cat target/HostTarget :any :any] :any])
