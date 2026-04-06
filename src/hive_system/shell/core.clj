(ns hive-system.shell.core
  "IShell implementation via ProcessBuilder.
   All operations return hive-dsl Results."
  (:require [hive-system.protocols :as proto]
            [hive-system.shell.detect :as detect]
            [hive-system.shell.tools :as tools]
            [hive-dsl.result :as r :refer [try-effect*]]
            [taoensso.timbre :as log])
  (:import [java.lang ProcessBuilder ProcessBuilder$Redirect]
           [java.io BufferedReader InputStreamReader]
           [java.util.concurrent TimeUnit]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: AGPL-3.0-or-later

(defn- read-stream [^java.io.InputStream is]
  (with-open [rdr (BufferedReader. (InputStreamReader. is))]
    (slurp rdr)))

(defn- build-process
  "Construct a ProcessBuilder from command and opts."
  ^ProcessBuilder [cmd {:keys [dir env inherit-io? redirect-err?]}]
  (let [cmd-vec (if (string? cmd) ["sh" "-c" cmd] (vec cmd))
        pb (ProcessBuilder. ^java.util.List cmd-vec)]
    (when dir (.directory pb (java.io.File. (str dir))))
    (when env
      (let [penv (.environment pb)]
        (doseq [[k v] env]
          (.put penv (str k) (str v)))))
    (when inherit-io? (.inheritIO pb))
    (when redirect-err?
      (.redirectErrorStream pb true))
    pb))

(defrecord Shell [default-opts]
  proto/IShell
  (shell-exec! [_ cmd opts]
    (let [opts (merge default-opts opts)
          timeout-ms (or (:timeout-ms opts) 30000)
          start (System/nanoTime)]
      (try-effect* :shell/exec-failed
        (let [pb (build-process cmd opts)
              proc (.start pb)
              stdout-future (future (read-stream (.getInputStream proc)))
              stderr-future (future (read-stream (.getErrorStream proc)))
              finished? (.waitFor proc timeout-ms TimeUnit/MILLISECONDS)
              duration-ms (/ (- (System/nanoTime) start) 1e6)]
          (if finished?
            {:exit (.exitValue proc)
             :stdout @stdout-future
             :stderr @stderr-future
             :duration-ms duration-ms
             :cmd cmd}
            (do
              (.destroyForcibly proc)
              (r/err :shell/timeout
                     {:cmd cmd
                      :timeout-ms timeout-ms
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
