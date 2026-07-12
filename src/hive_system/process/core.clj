(ns hive-system.process.core
  "IProcess implementation via java.lang.ProcessBuilder / ProcessHandle.
   Long-lived process lifecycle: spawn returns a live handle; wait/signal/pipe
   act on it. All operations return hive-dsl Result."
  (:require [hive-system.protocols :as proto]
            [hive-system.process.liveness :as liveness]
            [hive-dsl.result :as r :refer [try-effect*]]
            [hive-weave.pool :as pool]
            [clojure.java.io :as io]
            [clojure.string :as str])
  (:import [java.lang ProcessBuilder Process ProcessHandle]
           [java.io BufferedReader InputStreamReader]
           [java.util.concurrent TimeUnit]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(defn- read-stream
  "Drain a child stream to a string; a closed stream yields \"\"."
  [^java.io.InputStream is]
  (r/guard java.io.IOException ""
    (with-open [rdr (BufferedReader. (InputStreamReader. is))]
      (slurp rdr))))

(defn- build-process
  "Build a ProcessBuilder for a long-lived process (stdin open, output undrained)."
  ^ProcessBuilder [cmd {:keys [dir env redirect-err?]}]
  (let [cmd-vec (if (string? cmd) ["sh" "-c" cmd] (vec cmd))
        pb (ProcessBuilder. ^java.util.List cmd-vec)]
    (when dir (.directory pb (java.io.File. (str dir))))
    (when env
      (let [penv (.environment pb)]
        (doseq [[k v] env]
          (.put penv (str k) (str v)))))
    (when redirect-err? (.redirectErrorStream pb true))
    pb))

(defn- descendant-handles [^Process process]
  (iterator-seq (.iterator (.descendants process))))

(defn- destroy-tree! [^Process process]
  (doseq [^ProcessHandle h (descendant-handles process)]
    (.destroy h))
  (.destroy process))

(defn- kill-signal!
  "Deliver a POSIX signal to pid via `kill -SIG`."
  [pid signal]
  (let [sig (str/upper-case (name signal))]
    (-> (ProcessBuilder. ^java.util.List ["kill" (str "-" sig) (str pid)])
        (.start)
        (.waitFor))))

(defrecord ProcessManager [default-opts]
  proto/IProcess
  (process-spawn! [_ cmd opts]
    (let [opts (merge default-opts opts)]
      (try-effect* :process/spawn-failed
        (let [pb   (build-process cmd opts)
              proc (.start pb)]
          {:pid     (.pid proc)
           :process proc
           :stdin   (.getOutputStream proc)
           :stdout  (.getInputStream proc)
           :stderr  (.getErrorStream proc)
           :cmd     cmd}))))

  (process-wait! [_ handle timeout-ms]
    (let [^Process process (:process handle)
          pid (:pid handle)
          res (try-effect* :process/wait-failed
                (let [out-f     (future (read-stream (.getInputStream process)))
                      err-f     (future (read-stream (.getErrorStream process)))
                      finished? (.waitFor process (long timeout-ms) TimeUnit/MILLISECONDS)]
                  {:finished? finished?
                   :exit      (when finished? (.exitValue process))
                   :out-f     out-f
                   :err-f     err-f}))]
      (if (r/err? res)
        res
        (let [{:keys [finished? exit out-f err-f]} (:ok res)]
          (if finished?
            (r/ok {:exit-code exit :stdout @out-f :stderr @err-f})
            (do (.destroyForcibly process)
                (r/err :process/timeout {:pid pid :timeout-ms timeout-ms})))))))

  (process-signal! [_ handle signal]
    (let [^Process process (:process handle)
          pid (:pid handle)]
      (if (liveness/dead? pid)
        (r/ok {:pid pid :signal signal :delivered? false :already-dead? true})
        (try-effect* :process/signal-failed
          (case signal
            :term (do (.destroy process)         {:pid pid :signal :term :delivered? true})
            :kill (do (.destroyForcibly process) {:pid pid :signal :kill :delivered? true})
            :tree (do (destroy-tree! process)    {:pid pid :signal :tree :delivered? true})
            (do (kill-signal! pid signal)        {:pid pid :signal signal :delivered? true}))))))

  (process-pipe! [_ from-handle to-handle]
    (try-effect* :process/pipe-failed
      (let [from-out (:stdout from-handle)
            to-in    (:stdin to-handle)
            pump (pool/bound-future
                   (try
                     (io/copy from-out to-in)
                     (finally
                       (.close ^java.io.OutputStream to-in))))]
        {:from-pid (:pid from-handle) :to-pid (:pid to-handle) :pump pump}))))

(defn make-process-manager
  "Create a ProcessManager with optional default spawn opts (:dir, :env, :redirect-err?)."
  ([] (make-process-manager {}))
  ([opts] (->ProcessManager opts)))

;; --- Convenience API (stateless, uses a default manager) ---

(def ^:private default-manager (delay (make-process-manager)))

(defn spawn!
  "Spawn a long-lived process. Returns Result with the live handle
   {:pid :process :stdin :stdout :stderr :cmd}. cmd is a string (sh -c) or an
   arg vector. Opts: :dir, :env, :redirect-err?."
  ([cmd] (spawn! cmd {}))
  ([cmd opts] (proto/process-spawn! @default-manager cmd opts)))

(defn wait!
  "Wait up to timeout-ms for a handle to exit, draining its output. Returns
   Result {:exit-code :stdout :stderr}, or (err :process/timeout) and force-kills
   on deadline."
  [handle timeout-ms]
  (proto/process-wait! @default-manager handle timeout-ms))

(defn signal!
  "Signal a handle. signal ∈ #{:term :kill :tree} or any POSIX signal keyword
   (e.g. :int, :hup). Returns Result."
  [handle signal]
  (proto/process-signal! @default-manager handle signal))

(defn pipe!
  "Pipe from-handle's stdout into to-handle's stdin on a pooled pump thread.
   Returns Result {:from-pid :to-pid :pump}."
  [from-handle to-handle]
  (proto/process-pipe! @default-manager from-handle to-handle))
