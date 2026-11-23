(ns hive-system.remote.target
  "The HostTarget value and the OpenSSH argv built from it. Pure: nothing
   here runs a process."
  (:require [hive-system.shell.posix :as posix]
            [malli.core :as m]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(def HostTarget
  "Where and how to reach a host over ssh. :options are extra `-o Key=Value`
   pairs, emitted sorted by key."
  [:map
   [:host [:string {:min 1}]]
   [:user {:optional true} [:maybe [:string {:min 1}]]]
   [:port {:optional true} [:maybe [:int {:min 1 :max 65535}]]]
   [:identity-file {:optional true} [:maybe [:string {:min 1}]]]
   [:connect-timeout-s {:optional true} [:maybe [:int {:min 1}]]]
   [:options {:optional true} [:maybe [:map-of [:string {:min 1}] :string]]]])

(def Argv [:vector [:string]])

(def Port [:int {:min 1 :max 65535}])

(def Command [:or [:string {:min 1}] [:vector {:min 1} :string]])

(defn destination
  "`user@host`, or `host` when no user is given."
  [{:keys [user host]}]
  (if user (str user "@" host) host))

(m/=> destination [:=> [:cat HostTarget] :string])

(defn- option-args
  [{:keys [identity-file connect-timeout-s options]}]
  (vec (concat ["-o" "BatchMode=yes"]
               (when identity-file ["-i" identity-file])
               (when connect-timeout-s ["-o" (str "ConnectTimeout=" connect-timeout-s)])
               (mapcat (fn [[k v]] ["-o" (str k "=" v)]) (sort-by key options)))))

(defn remote-command
  "The single string ssh hands the remote shell: a string as given, an argv
   vector POSIX-quoted element by element."
  [cmd]
  (if (string? cmd) cmd (posix/join-as-cmd cmd)))

(m/=> remote-command [:=> [:cat Command] :string])

(defn- ssh-prefix
  [target]
  (cond-> (into ["ssh"] (option-args target))
    (:port target) (into ["-p" (str (:port target))])))

(defn exec-argv
  "argv running `cmd` on `target`."
  [target cmd]
  (into (ssh-prefix target) ["--" (destination target) (remote-command cmd)]))

(m/=> exec-argv [:=> [:cat HostTarget Command] Argv])

(defn- scp-prefix
  [target]
  (cond-> (into ["scp"] (option-args target))
    (:port target) (into ["-P" (str (:port target))])))

(defn put-argv
  "argv copying `local-path` to `remote-path` on `target`."
  [target local-path remote-path]
  (into (scp-prefix target) ["--" local-path (str (destination target) ":" remote-path)]))

(m/=> put-argv [:=> [:cat HostTarget [:string {:min 1}] [:string {:min 1}]] Argv])

(defn get-argv
  "argv copying `remote-path` on `target` to `local-path`."
  [target remote-path local-path]
  (into (scp-prefix target) ["--" (str (destination target) ":" remote-path) local-path]))

(m/=> get-argv [:=> [:cat HostTarget [:string {:min 1}] [:string {:min 1}]] Argv])

(defn forward-argv
  "argv holding a forward of 127.0.0.1:local-port to remote-host:remote-port
   as seen from `target`. The process runs until it is signalled."
  [target local-port remote-port remote-host]
  (into (ssh-prefix target)
        ["-N" "-o" "ExitOnForwardFailure=yes"
         "-L" (str "127.0.0.1:" local-port ":" remote-host ":" remote-port)
         "--" (destination target)]))

(m/=> forward-argv [:=> [:cat HostTarget Port Port [:string {:min 1}]] Argv])
