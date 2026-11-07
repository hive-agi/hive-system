(ns hive-system.remote.repl
  "IReplEndpoint: start an nREPL (or any TCP REPL) server on a remote host and
   reach it on a local port. Composed only from IRemoteHost: remote-exec!
   launches the server detached (pid to a file), remote-exec! probes its
   port until it listens, remote-forward! binds 127.0.0.1:local-port to it.
   Closing kills the server by its pid file; the forward goes with the host's
   remote-release!.

   How a server is launched is an OPEN set: `launch-command` is a multimethod
   on :runtime (:bb, :clojure-cli, :shell built in). A runtime is pure data
   -> one POSIX shell string."
  (:require [hive-dsl.result :as r]
            [hive-system.remote.ports :as ports]
            [hive-system.shell.posix :as posix]
            [malli.core :as m]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(defprotocol IReplEndpoint
  "A REPL server on a remote host, reachable locally."
  (repl-open! [this opts]
    "Launch the server, wait until it listens, forward it. Returns Result
     {:host \"127.0.0.1\" :port <local-port> :remote-port :forward-id :pid-file}.")
  (repl-close! [this]
    "Kill the server this endpoint launched. Idempotent. Returns Result."))

(def ReplSpec
  [:map
   [:runtime :keyword]
   [:remote-port [:int {:min 1 :max 65535}]]
   [:local-port [:int {:min 1 :max 65535}]]
   [:dir {:optional true} [:string {:min 1}]]
   [:pid-file {:optional true} [:string {:min 1}]]
   [:log-file {:optional true} [:string {:min 1}]]
   [:ready-timeout-ms {:optional true} [:int {:min 1}]]
   [:poll-ms {:optional true} [:int {:min 1}]]])

(defmulti server-argv
  "The argv that runs the REPL server for `spec` in the FOREGROUND, by :runtime."
  :runtime)

(defmethod server-argv :bb [{:keys [remote-port]}]
  ["bb" "nrepl-server" (str "127.0.0.1:" remote-port)])

(defmethod server-argv :clojure-cli [{:keys [remote-port aliases nrepl-version]}]
  ["clojure" "-Sdeps" (binding [*print-namespace-maps* false] (pr-str {:deps {'nrepl/nrepl {:mvn/version (or nrepl-version "1.3.1")}}}))
   (str "-M" (apply str (map #(str ":" (name %)) aliases)))
   "-m" "nrepl.cmdline" "--bind" "127.0.0.1" "--port" (str remote-port)])

(defmethod server-argv :shell [{:keys [argv]}] (vec argv))

(defmethod server-argv :default [spec]
  (throw (ex-info "no REPL runtime registered" {:runtime (:runtime spec)})))

(defn- pid-file [spec] (or (:pid-file spec) (str "/tmp/hive-repl-" (:remote-port spec) ".pid")))

(defn- log-file [spec] (or (:log-file spec) (str "/tmp/hive-repl-" (:remote-port spec) ".log")))

(defn launch-command
  "One shell string starting the server detached, its pid in the pid file.
   With setsid on the host the server leads its own process group, so
   stop-command can take its children down with it."
  [spec]
  (let [argv (posix/join-as-cmd (server-argv spec))]
    (str (when (:dir spec) (str "cd " (posix/join-as-cmd [(:dir spec)]) " && "))
         "if command -v setsid >/dev/null 2>&1; then nohup setsid " argv
         "; else nohup " argv "; fi"
         " >" (posix/join-as-cmd [(log-file spec)]) " 2>&1 </dev/null & echo $! >"
         (posix/join-as-cmd [(pid-file spec)]))))

(defn probe-command
  "A shell string that exits 0 once 127.0.0.1:port accepts a connection, and
   fails fast when the server process is already gone. Uses nc when present,
   else bash's /dev/tcp."
  [spec]
  (let [port (:remote-port spec) pf (posix/join-as-cmd [(pid-file spec)])]
    (str "kill -0 \"$(cat " pf ")\" 2>/dev/null || exit 3; "
         "if command -v nc >/dev/null 2>&1; then nc -z 127.0.0.1 " port "; "
         "else bash -c 'exec 3<>/dev/tcp/127.0.0.1/" port "' 2>/dev/null; fi")))

(defn stop-command
  "A shell string killing the server's process group (its children too), or
   the pid alone when it does not lead one; then dropping the pid file."
  [spec]
  (let [pf (posix/join-as-cmd [(pid-file spec)])]
    (str "if [ -f " pf " ]; then p=\"$(cat " pf ")\"; "
         "kill -TERM -- -\"$p\" 2>/dev/null || kill \"$p\" 2>/dev/null; fi; rm -f " pf "; true")))

(defn- exit-ok! [res err-key data]
  (r/let-ok [out res]
    (if (zero? (:exit out)) (r/ok out) (r/err err-key (merge data (select-keys out [:exit :stderr]))))))

(defn- await-listening!
  [host spec sleep!]
  (let [timeout (or (:ready-timeout-ms spec) 120000)
        poll    (or (:poll-ms spec) 1000)]
    (loop [waited 0]
      (let [res (ports/remote-exec! host (probe-command spec) {:timeout-ms 15000})]
        (cond
          (r/err? res)                 res
          (zero? (:exit (:ok res)))    (r/ok {:waited-ms waited})
          (= 3 (:exit (:ok res)))      (r/err :remote/repl-died {:log-file (log-file spec)})
          (>= waited timeout)          (r/err :remote/repl-not-listening {:waited-ms waited :log-file (log-file spec)})
          :else                        (do (sleep! poll) (recur (+ waited poll))))))))

(defrecord NreplEndpoint [host sleep! opened]
  IReplEndpoint
  (repl-open! [_ spec]
    (if-not (m/validate ReplSpec spec)
      (r/err :remote/invalid-spec {:explain (m/explain ReplSpec spec)})
      (r/let-ok [_   (if (contains? (methods server-argv) (:runtime spec))
                       (r/ok nil)
                       (r/err :remote/unknown-runtime {:runtime (:runtime spec)}))
                 _   (exit-ok! (ports/remote-exec! host (launch-command spec) {:timeout-ms 30000})
                               :remote/repl-launch-failed {:runtime (:runtime spec)})
                 _   (do (reset! opened spec) (r/ok nil))
                 _   (await-listening! host spec sleep!)
                 fwd (ports/remote-forward! host (:local-port spec) (:remote-port spec) {})]
        (r/ok {:host        "127.0.0.1"
               :port        (:local-port spec)
               :remote-port (:remote-port spec)
               :forward-id  (:forward-id fwd)
               :pid-file    (pid-file spec)}))))
  (repl-close! [_]
    (let [[spec _] (reset-vals! opened nil)]
      (if spec
        (exit-ok! (ports/remote-exec! host (stop-command spec) {:timeout-ms 15000})
                  :remote/repl-stop-failed {:pid-file (pid-file spec)})
        (r/ok {:closed? false :reason :not-open})))))

(defn nrepl-endpoint
  "An IReplEndpoint on `host` (an IRemoteHost). opts: :sleep! (fn [ms])."
  ([host] (nrepl-endpoint host {}))
  ([host {:keys [sleep!]}]
   (->NreplEndpoint host (or sleep! #(Thread/sleep (long %))) (atom nil))))

(defn with-repl
  "Open a REPL endpoint on `host` for `spec`, call (f endpoint-info), close the
   server on every path. Returns f's value, or the open err."
  [host spec f]
  (let [ep  (nrepl-endpoint host)
        res (repl-open! ep spec)]
    (try
      (if (r/err? res) res (f (:ok res)))
      (finally (repl-close! ep)))))
