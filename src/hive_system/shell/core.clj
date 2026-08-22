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
    (detect/which program))

  proto/IBoundedShell
  (shell-lines! [_ cmd opts]
    ;; Same timeout doctrine as shell-exec!: the deadline is produced OUTSIDE
    ;; try-effect*, or an err would come back wrapped in `ok`.
    (let [opts       (merge default-opts opts)
          timeout-ms (or (:timeout-ms opts) 30000)
          max-lines  (or (:max-lines opts) 1000)
          max-bytes  (or (:max-bytes opts) (* 8 1024 1024))
          start      (System/nanoTime)
          elapsed    #(/ (- (System/nanoTime) start) 1e6)
          ran        (try-effect* :shell/exec-failed
                       (let [proc (.start (build-process cmd opts))]
                         {:proc     proc
                          ;; both reads are abandonable: the cap may fire long
                          ;; before EOF, and EOF may never come at all while a
                          ;; descendant holds the inherited pipe
                          :stdout-p (streams/drain-lines-capped
                                     (.getInputStream proc) max-lines max-bytes)
                          :stderr-p (streams/drain (.getErrorStream proc))}))]
      (if (r/err? ran)
        ran
        (let [{:keys [stdout-p stderr-p]} (:ok ran)
              ^Process proc (:proc (:ok ran))
              capped        (deref stdout-p (long timeout-ms) ::timeout)]
          (if (= ::timeout capped)
            (do (try (tree/destroy-tree! proc true) (catch Exception _ nil))
                (r/err :shell/timeout {:cmd cmd
                                       :timeout-ms  timeout-ms
                                       :duration-ms (elapsed)}))
            (let [{:keys [lines truncated? reason]} capped
                  ;; A cap is a decision to stop the producer, not merely to
                  ;; stop reading it: leaving it running would spend exactly
                  ;; the resources the budget was declared to bound.
                  _         (when truncated?
                              (try (tree/destroy-tree! proc true) (catch Exception _ nil)))
                  remaining (max 0 (long (- timeout-ms (elapsed))))
                  finished? (.waitFor proc
                                      (if truncated?
                                        (long streams/flush-grace-ms)
                                        remaining)
                                      TimeUnit/MILLISECONDS)
                  err       (deref stderr-p streams/flush-grace-ms ::open)]
              (if (or finished? truncated?)
                (r/ok (cond-> {:lines       lines
                               :truncated?  truncated?
                               :reason      reason
                               ;; killed for exceeding the budget, so whatever
                               ;; exit status it now carries describes the KILL
                               :exit        (when-not truncated?
                                              (when finished? (.exitValue proc)))
                               :stderr      (if (= ::open err) "" err)
                               :duration-ms (elapsed)
                               :cmd         cmd}
                        (= ::open err) (assoc :detached true)))
                (do (try (tree/destroy-tree! proc true) (catch Exception _ nil))
                    (r/err :shell/timeout {:cmd cmd
                                           :timeout-ms  timeout-ms
                                           :duration-ms (elapsed)}))))))))))

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

(defn lines!
  "Run a command, reading at most a bounded number of output lines. Result.

   `exec!` captures everything the command printed, so its memory cost is set
   by the child. Use this where the caller has a budget:

     (lines! [\"rg\" \"--files\" root] {:max-lines 1000})
     => (ok {:lines […] :truncated? true :reason :max-lines :exit nil …})

   Opts, on top of `exec!`'s:
     :max-lines  — lines to return (default 1000)
     :max-bytes  — total bytes to read (default 8 MiB). A line budget does not
                   bound memory; one pathological line exhausts the heap with
                   the line count still at 1.

   `:truncated?` is the load-bearing key. A caller handed exactly :max-lines
   lines cannot otherwise tell a command that printed that many from one that
   printed more, and a silently truncated list reads as a complete answer.
   `:reason` names which bound stopped it: :eof, :max-lines or :max-bytes.

   When truncated the process TREE is destroyed — a cap is a decision to stop
   the producer, not merely to stop reading it — and `:exit` is nil, because
   the only status such a process could report describes the kill."
  ([cmd] (lines! cmd {}))
  ([cmd opts] (proto/shell-lines! @default-shell cmd opts)))

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
