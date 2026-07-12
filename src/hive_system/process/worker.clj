(ns hive-system.process.worker
  "IWorker implementation — a warm request/response worker over a long-lived
   process (hive-system.process IProcess). Requests/responses are newline-
   delimited EDN; a monotonic :id correlates each response. Calls are single-
   flight via a hive-weave gate (1 permit); reads are timeout-bounded."
  (:require [hive-system.protocols :as proto]
            [hive-system.process.core :as proc]
            [hive-system.process.liveness :as liveness]
            [hive-dsl.result :as r]
            [hive-weave.safe :as safe]
            [hive-weave.gate :as gate]
            [clojure.java.io :as io]
            [clojure.edn :as edn]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(defn- send-frame! [^java.io.Writer w msg]
  (.write w (pr-str msg))
  (.write w "\n")
  (.flush w))

(defn- read-frame [^java.io.BufferedReader r]
  (when-let [line (.readLine r)]
    (edn/read-string line)))

(defrecord Worker [handle writer reader id-counter call-gate]
  proto/IWorker
  (worker-call! [_ request timeout-ms]
    (let [task (fn []
                 (let [id (swap! id-counter inc)]
                   (send-frame! writer (assoc request :id id))
                   (safe/safe-future-call {:timeout-ms timeout-ms :name "worker-read"}
                                          (fn [] (read-frame reader)))))
          gated (gate/gate-run call-gate task)]
      (if (r/err? gated)
        gated
        (let [read-res (:ok gated)]
          (cond
            (r/err? read-res)     read-res
            (nil? (:ok read-res)) (r/err :worker/eof {:pid (:pid handle)})
            :else                 (r/ok (:ok read-res)))))))

  (worker-health [_]
    (r/ok {:pid (:pid handle) :alive? (liveness/alive? (:pid handle))}))

  (worker-stop! [_]
    (proc/signal! handle :tree)))

(defn spawn-warm!
  "Spawn a warm worker over cmd (string or arg vector). The process reads
   newline-delimited EDN requests on stdin and writes one EDN response line per
   request. Returns Result with an IWorker. Opts: :dir, :env."
  ([cmd] (spawn-warm! cmd {}))
  ([cmd opts]
   (let [spawned (proc/spawn! cmd opts)]
     (if (r/err? spawned)
       spawned
       (let [handle (:ok spawned)]
         (r/ok (->Worker handle
                         (io/writer (:stdin handle))
                         (io/reader (:stdout handle))
                         (atom 0)
                         (gate/gate {:name (str "warm-worker-" (:pid handle))
                                     :permits 1
                                     :timeout-ms 60000}))))))))

;; --- Convenience API ---

(defn call!
  "Send request (a map) to worker, read one framed response. Returns Result."
  [worker request timeout-ms]
  (proto/worker-call! worker request timeout-ms))

(defn health
  "Worker process liveness. Returns Result."
  [worker]
  (proto/worker-health worker))

(defn stop!
  "Stop the worker and release its process. Returns Result."
  [worker]
  (proto/worker-stop! worker))
