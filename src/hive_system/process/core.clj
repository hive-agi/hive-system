(ns hive-system.process.core
  "IProcess implementation via java.lang.ProcessBuilder / ProcessHandle.
   Long-lived process lifecycle: spawn returns a live handle; wait/signal/pipe
   act on it. All operations return hive-dsl Result.

   Stream draining and process-tree teardown are shared with the IShell
   implementation — see hive-system.process.streams / .tree.

   No hive-weave here on purpose: this namespace has to stay loadable under
   Babashka, and hive-weave.pool is not."
  (:require [hive-system.protocols :as proto]
            [hive-system.process.liveness :as liveness]
            [hive-system.process.streams :as streams]
            [hive-system.process.tree :as tree]
            [hive-dsl.result :as r :refer [try-effect*]]
            [clojure.string :as str])
  (:import [java.lang ProcessBuilder Process ProcessHandle]
           [java.util.concurrent TimeUnit]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

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
    ;; Same shape as IShell's exec!, and for the same reason: the drains are
    ;; abandonable and the deadline branch is a FLAT err produced outside
    ;; try-effect*. Deref'ing the drains unbounded let a descendant holding an
    ;; inherited pipe stretch the wait long past timeout-ms, and killing only
    ;; the root left that descendant alive to keep holding it.
    (let [^Process process (:process handle)
          pid (:pid handle)
          ran (try-effect* :process/wait-failed
                (let [stdout-p  (streams/drain (.getInputStream process))
                      stderr-p  (streams/drain (.getErrorStream process))
                      finished? (.waitFor process (long timeout-ms) TimeUnit/MILLISECONDS)]
                  {:finished? finished? :stdout-p stdout-p :stderr-p stderr-p}))]
      (if (r/err? ran)
        ran
        (let [{:keys [finished? stdout-p stderr-p]} (:ok ran)]
          (if finished?
            (try-effect* :process/wait-failed
              (let [out       (deref stdout-p streams/flush-grace-ms ::open)
                    err       (deref stderr-p streams/flush-grace-ms ::open)
                    detached? (or (= ::open out) (= ::open err))]
                (cond-> {:exit-code (.exitValue process)
                         :stdout    (if (= ::open out) "" out)
                         :stderr    (if (= ::open err) "" err)}
                  detached? (assoc :detached true))))
            (do
              (try (tree/destroy-tree! process true) (catch Exception _ nil))
              (r/err :process/timeout {:pid pid :timeout-ms timeout-ms})))))))

  (process-signal! [_ handle signal]
    (let [^Process process (:process handle)
          pid (:pid handle)]
      (if (liveness/dead? pid)
        (r/ok {:pid pid :signal signal :delivered? false :already-dead? true})
        (try-effect* :process/signal-failed
          (case signal
            :term (do (.destroy process)             {:pid pid :signal :term :delivered? true})
            :kill (do (.destroyForcibly process)     {:pid pid :signal :kill :delivered? true})
            :tree (do (tree/destroy-tree! process)   {:pid pid :signal :tree :delivered? true})
            (do (kill-signal! pid signal)            {:pid pid :signal signal :delivered? true}))))))

  (process-pipe! [_ from-handle to-handle]
    (try-effect* :process/pipe-failed
      {:from-pid (:pid from-handle)
       :to-pid   (:pid to-handle)
       :pump     (streams/pump (:stdout from-handle) (:stdin to-handle))})))

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
