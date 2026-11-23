(ns hive-system.remote.ports
  "Ports for running work on a remote host. Every method returns a hive-dsl
   Result.

     IRemoteHost    exec, file transfer, port forward, health, release
     IHostProvider  provision and terminate a host
     with-host      provision, run, release and terminate on every path"
  (:require [hive-dsl.result :as r]
            [taoensso.timbre :as log]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(defprotocol IRemoteHost
  "One reachable host."
  (remote-exec! [this cmd opts]
    "Run `cmd` (argv vector or a shell string) on the host. opts: :timeout-ms,
     :in (string or bytes fed to the remote stdin). Returns Result
     {:exit :stdout :stderr :duration-ms}; a non-zero exit is ok data.")
  (remote-put! [this local-path remote-path opts]
    "Copy a local file to the host. opts: :timeout-ms. Returns Result
     {:local-path :remote-path}; a failed copy is an err.")
  (remote-get! [this remote-path local-path opts]
    "Copy a host file to local disk. opts: :timeout-ms. Returns Result
     {:remote-path :local-path}; a failed copy is an err.")
  (remote-forward! [this local-port remote-port opts]
    "Forward 127.0.0.1:local-port to remote-port on the host (opts :remote-host,
     default 127.0.0.1). Returns Result {:forward-id :local-port :remote-port}.
     The forward lives until remote-release!.")
  (remote-health [this]
    "Returns Result {:reachable? bool}; an unreachable host is ok data.")
  (remote-release! [this]
    "Close every forward this host opened. Idempotent. Returns Result {:closed n}."))

(defprotocol IHostProvider
  "Creates and destroys hosts. Spend cap and TTL ride on the spec as data."
  (provision! [this spec]
    "Create a host from `spec`. Returns Result {:id <provider id> :host <IRemoteHost>}.")
  (terminate! [this id]
    "Destroy the host `id`. Idempotent. Returns Result."))

(defn with-host
  "Provision a host from `provider` with `spec`, call (f host), then release
   the host and terminate it, on every path: f returning ok, f returning err,
   and f throwing. Returns f's value, or the provision err when no host was
   created. A failed release or terminate is logged at error, never swallowed
   into f's value."
  [provider spec f]
  (let [p (provision! provider spec)]
    (if (r/err? p)
      p
      (let [{:keys [id host]} (:ok p)]
        (try
          (f host)
          (finally
            (try (let [rel (remote-release! host)]
                   (when (r/err? rel)
                     (log/error "with-host: release failed" {:id id :result rel})))
                 (catch Throwable t
                   (log/error t "with-host: release threw" {:id id})))
            (try (let [term (terminate! provider id)]
                   (when (r/err? term)
                     (log/error "with-host: terminate failed; the host may still bill" {:id id :result term})))
                 (catch Throwable t
                   (log/error t "with-host: terminate threw; the host may still bill" {:id id})))))))))

(defmulti host-provider
  "The IHostProvider `cfg` names by :kind (:tailnet, :k8s, :runpod, ...), as a
   Result. An OPEN set: an adapter namespace registers its kind with a
   defmethod; loading that namespace is what makes the kind available."
  (fn [cfg] (:kind cfg)))

(defmethod host-provider :default [cfg]
  (r/err :remote/unknown-provider
         {:kind    (:kind cfg)
          :message (str "No host provider registered for " (pr-str (:kind cfg))
                        "; require the adapter namespace that registers it")}))
