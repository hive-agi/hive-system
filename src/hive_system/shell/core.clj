(ns hive-system.shell.core
  "IShell implementation via ProcessBuilder.
   All operations return hive-dsl Results.

   Stream draining and process-tree teardown are shared with the IProcess
   implementation — see hive-system.process.streams / .tree. Both faced the
   same hazard (a descendant holding an inherited pipe), and one copy of the
   answer is the point."
  (:require [hive-system.protocols :as proto]
            [hive-system.process.streams :as streams]
            [hive-system.process.tree :as tree]
            [hive-system.shell.detect :as detect]
            [hive-system.shell.tools :as tools]
            [hive-dsl.result :as r :refer [try-effect*]]
            [taoensso.timbre :as log])
  (:import [java.lang ProcessBuilder ProcessBuilder$Redirect ProcessHandle]
           [java.util.concurrent TimeUnit]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(defn- build-process
  "Construct a ProcessBuilder from command and opts.

  stdin redirects from /dev/null by default: exec! never writes to a child's
  stdin, and an inherited open pipe makes stdin-sniffing CLIs (nuclei reads
  targets from a piped stdin) block forever. :inherit-io? keeps the
  terminal's stdin instead; :stdin <File/path> overrides explicitly."
  ^ProcessBuilder [cmd {:keys [dir env inherit-io? redirect-err? stdin]}]
  (let [cmd-vec (if (string? cmd) ["sh" "-c" cmd] (vec cmd))
        pb (ProcessBuilder. ^java.util.List cmd-vec)]
    (when dir (.directory pb (java.io.File. (str dir))))
    (when env
      (let [penv (.environment pb)]
        (doseq [[k v] env]
          (.put penv (str k) (str v)))))
    (if inherit-io?
      (.inheritIO pb)
      (.redirectInput pb (ProcessBuilder$Redirect/from
                          (java.io.File. (str (or stdin "/dev/null"))))))
    (when redirect-err?
      (.redirectErrorStream pb true))
    pb))

(defrecord Shell [default-opts]
  proto/IShell
  (shell-exec! [_ cmd opts]
    ;; A timeout is a LAWFUL outcome, not a thrown fault, so it is produced
    ;; OUTSIDE try-effect* — which wraps whatever its body returns in `ok`.
    ;; A timeout err returned from inside became {:ok {:error :shell/timeout}},
    ;; and every caller branching on r/err? read that as success.
    (let [opts       (merge default-opts opts)
          timeout-ms (or (:timeout-ms opts) 30000)
          start      (System/nanoTime)
          ran        (try-effect* :shell/exec-failed
                       (let [pb        (build-process cmd opts)
                             proc      (.start pb)
                             stdout-p  (streams/drain (.getInputStream proc))
                             stderr-p  (streams/drain (.getErrorStream proc))
                             finished? (.waitFor proc (long timeout-ms) TimeUnit/MILLISECONDS)]
                         {:proc        proc
                          :finished?   finished?
                          :stdout-p    stdout-p
                          :stderr-p    stderr-p
                          :duration-ms (/ (- (System/nanoTime) start) 1e6)}))]
      (if (r/err? ran)
        ran
        (let [{:keys [finished? stdout-p stderr-p duration-ms]} (:ok ran)
              ^Process proc (:proc (:ok ran))]
          (if finished?
            (try-effect* :shell/exec-failed
              (let [out       (deref stdout-p streams/flush-grace-ms ::open)
                    err       (deref stderr-p streams/flush-grace-ms ::open)
                    detached? (or (= ::open out) (= ::open err))]
                (cond-> {:exit        (.exitValue proc)
                         :stdout      (if (= ::open out) "" out)
                         :stderr      (if (= ::open err) "" err)
                         :duration-ms duration-ms
                         :cmd         cmd}
                  detached? (assoc :detached true))))
            (do
              ;; a deadline kill forces, and takes the descendants with it;
              ;; best-effort, since the timeout is the answer either way
              (try (tree/destroy-tree! proc true) (catch Exception _ nil))
              (r/err :shell/timeout
                     {:cmd         cmd
                      :timeout-ms  timeout-ms
                      :duration-ms duration-ms})))))))

  (shell-env [_]
    (into {} (System/getenv)))

  (shell-which [_ program]
    (detect/which program)))

(defn make-shell
  "Create a Shell instance with optional default opts.
   Opts: :dir, :env, :timeout-ms."
  ([] (make-shell {}))
  ([opts] (->Shell opts)))

;; --- Convenience API (stateless, uses default shell) ---

(def ^:private default-shell (delay (make-shell)))

(defn exec!
  "Execute a shell command. Returns Result.
   cmd can be a string (passed to sh -c) or a vector of args.

   Opts:
     :dir        — working directory
     :env        — extra env vars map
     :timeout-ms — kill after N ms (default 30s)"
  ([cmd] (exec! cmd {}))
  ([cmd opts] (proto/shell-exec! @default-shell cmd opts)))

(defn exec-ok!
  "Like exec! but returns (err ...) if exit code is non-zero."
  ([cmd] (exec-ok! cmd {}))
  ([cmd opts]
   (let [result (exec! cmd opts)]
     (if (r/err? result)
       result
       (let [{:keys [exit] :as v} (:ok result)]
         (if (zero? exit)
           (r/ok v)
           (r/err :shell/non-zero-exit v)))))))

(defn which
  "Resolve program to path. Returns Result."
  [program]
  (detect/which program))

(defn env
  "Get environment variables as map."
  []
  (proto/shell-env @default-shell))

(defn require-tool
  "Check tool availability with install hints. See shell.tools/require-tool."
  [tool-key]
  (tools/require-tool tool-key))
