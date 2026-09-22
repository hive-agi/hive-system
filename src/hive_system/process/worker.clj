(ns hive-system.process.worker
  "IWorker implementation — a warm request/response worker over a long-lived
   process (hive-system.process IProcess). Requests/responses are newline-
   delimited EDN; a monotonic :id correlates each response. Calls are single-
   flight via a hive-weave gate (1 permit); reads are timeout-bounded."
  (:require [hive-system.protocols :as proto]
            [hive-system.process.core :as proc]
            [hive-system.process.liveness :as liveness]
            [hive-dsl.result :as r]
            [hive-weave.gate :as gate]
            [clojure.java.io :as io]
            [clojure.edn :as edn]
            [hive-weave.pool :as wp]))

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

(defn- stale?
  "True when `frame` answers an earlier call than `id`. A frame without :id is
   from a worker that does not echo the correlation key, so it can only be read
   as the reply to the call in flight."
  [frame id]
  (and (map? frame)
       (contains? frame :id)
       (not= id (:id frame))))

(defn- pending-read!
  "The worker's outstanding read, starting one on its single read thread when
   none is in flight.

   A read the caller abandoned on timeout stays here rather than being replaced:
   the reader thread is still parked in readLine, and a second reader would take
   the NEXT frame, so the abandoned call's reply would be delivered to the
   following call. One reader, one pending future, per worker."
  [{:keys [read-pool pending reader]}]
  (or @pending
      (let [fut (wp/submit! read-pool (fn [] (read-frame reader)))]
        (reset! pending fut)
        fut)))

(defn- await-frame
  "Collect frames until the reply for `id` arrives or `deadline` passes.

   A frame carrying a different :id answers a call that already timed out, so it
   is discarded rather than returned: that correlation is the whole point of
   stamping :id on the request."
  [{:keys [pending handle] :as worker} id deadline]
  (loop []
    (let [remaining (- deadline (System/currentTimeMillis))]
      (if-not (pos? remaining)
        (r/err :worker/timeout {:id id :pid (:pid handle)})
        (let [frame (deref (pending-read! worker) remaining ::pending)]
          (cond
            (= ::pending frame) (r/err :worker/timeout {:id id :pid (:pid handle)})
            :else (do (reset! pending nil)
                      (cond
                        (nil? frame) (r/err :worker/eof {:pid (:pid handle)})
                        (stale? frame id) (recur)
                        :else (r/ok frame)))))))))

(defrecord Worker [handle writer reader id-counter call-gate read-pool pending]
  proto/IWorker
  (worker-call! [this request timeout-ms]
    (let [task (fn []
                 (let [id (swap! id-counter inc)]
                   (send-frame! writer (assoc request :id id))
                   (await-frame this id (+ (System/currentTimeMillis) timeout-ms))))
          gated (gate/gate-run call-gate task)]
      (if (r/err? gated) gated (:ok gated))))

  (worker-health [_]
    (r/ok {:pid (:pid handle) :alive? (liveness/alive? (:pid handle))}))

  (worker-stop! [_]
    (let [stopped (proc/signal! handle :tree)]
      (wp/shutdown! read-pool {:await-ms 100})
      stopped)))

(defn spawn-warm!
  "Spawn a warm worker over cmd (string or arg vector). The process reads
   newline-delimited EDN requests on stdin and writes one EDN response line per
   request, echoing the injected :id. Returns Result with an IWorker.
   Opts: :dir, :env."
  ([cmd] (spawn-warm! cmd {}))
  ([cmd opts]
   (let [spawned (proc/spawn! cmd opts)]
     (if (r/err? spawned)
       spawned
       (let [handle (:ok spawned)
             pid    (:pid handle)]
         (r/ok (->Worker handle
                         (io/writer (:stdin handle))
                         (io/reader (:stdout handle))
                         (atom 0)
                         (gate/gate {:name (str "warm-worker-" pid)
                                     :permits 1
                                     :timeout-ms 60000})
                         ;; one reader thread per worker: reads are serialized by
                         ;; the call gate, and a second thread would race the
                         ;; abandoned one for the next frame
                         (wp/make-pool {:name (str "warm-worker-read-" pid)
                                        :size 1
                                        :queue-capacity 1})
                         (atom nil))))))))

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
