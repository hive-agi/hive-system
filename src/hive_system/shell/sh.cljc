(ns hive-system.shell.sh
  "IShell adapter over `clojure.java.shell/sh`: the portable one.

   `hive-system.shell.core` is the JVM adapter (ProcessBuilder, abandonable
   drains, process-tree teardown, deadlines). This one rides the host's
   `clojure.java.shell`, which the JVM, cljw and cljrs all ship, so a host
   without ProcessBuilder still gets an IShell.

   Port faithfulness: the same opts mean the same thing here as in core.
     cmd   a string runs as [\"sh\" \"-c\" cmd]; a sequence is the argv.
     :dir  working directory.
     :env  merged OVER the inherited environment, as core .put's onto it
           (`sh`'s own :env replaces the environment wholesale).
     :in   a String or bytes fed to the child's stdin. Without it stdin is
           closed at once, which a child reads as EOF, as /dev/null in core.

   Declared gaps, as data (`capabilities`), never as silent parity: `sh`
   has no deadline, no stdin-from-file, no inherited terminal and no
   stderr merge. An opt this adapter cannot honour is REFUSED up front
   with (err :shell/unsupported-opt {:opt k}) rather than ignored, so a
   caller that asked for a bound never runs unbounded believing it has one."
  (:require [clojure.java.shell :as jsh]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            ;; cljw also answers :clj, so its branch must come first:
            ;; babashka.fs (behind detect) is JVM-only.
            #?@(:cljw [] :clj [[hive-system.shell.detect :as detect]])
            [clojure.string :as str]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

;; =============================================================================
;; Data: what this adapter can and cannot do
;; =============================================================================

(def capabilities
  "What the `sh` adapter honours. A conformance suite reads this map to
   decide which expectations apply, so a gap is a declared fact."
  {:timeout?     false
   :stdin-file?  false
   :inherit-io?  false
   :redirect-err? false
   :stdin-bytes? true
   :env-merge?   true})

(def ^:private unsupported-opts
  "opt key -> why `sh` cannot honour it."
  {:timeout-ms    "clojure.java.shell/sh waits for the child without a deadline"
   :stdin         "clojure.java.shell/sh feeds stdin from :in only, not from a file"
   :inherit-io?   "clojure.java.shell/sh always captures stdout and stderr"
   :redirect-err? "clojure.java.shell/sh always captures stderr separately"})

;; =============================================================================
;; Pure calculations
;; =============================================================================

(defn ->argv
  "A string command runs under `sh -c`; a sequence is the argv itself."
  [cmd]
  (if (string? cmd) ["sh" "-c" cmd] (mapv str cmd)))

(defn unsupported-opt
  "The first opt in `opts` this adapter cannot honour, or nil. An opt set
   to nil or false asks for nothing, so it is not a refusal."
  [opts]
  (some (fn [k] (when (some? (get opts k))
                  (when-not (false? (get opts k)) k)))
        (keys unsupported-opts)))

(defn merge-env
  "`extra` over `inherited`, keys and values as strings — core's semantics."
  [inherited extra]
  (into (or inherited {})
        (map (fn [[k v]] [(str k) (str v)]))
        extra))

(defn sh-args
  "The argument list for `clojure.java.shell/sh`."
  [cmd {:keys [dir env in]} inherited-env]
  (cond-> (->argv cmd)
    (some? in) (into [:in in])
    dir        (into [:dir (str dir)])
    env        (into [:env (merge-env inherited-env env)])))

(defn ->exec-result
  "The IShell result map from `sh`'s {:exit :out :err}."
  [cmd {:keys [exit out err]} duration-ms]
  {:exit        exit
   :stdout      (or out "")
   :stderr      (or err "")
   :duration-ms duration-ms
   :cmd         cmd})

;; =============================================================================
;; Host edges
;; =============================================================================

(defn- host-env [] (into {} (System/getenv)))

(defn- now-ns [] (System/nanoTime))

(defn- which-via-command-v
  "Resolve `program` through POSIX `command -v`, for hosts without babashka.fs."
  [program]
  (let [p   (str program)
        res (try (jsh/sh "sh" "-c" "command -v \"$1\"" "sh" p)
                 (catch #?(:clj Exception :default :default) _ nil))
        out (some-> (:out res) str/trim)]
    (if (and res (zero? (:exit res)) (seq out))
      (r/ok {:path out :program p})
      (r/err :shell/not-found {:program p}))))

;; =============================================================================
;; Adapter
;; =============================================================================

(defrecord ShShell [default-opts]
  proto/IShell
  (shell-exec! [_ cmd opts]
    (let [opts (merge default-opts opts)]
      (if-let [k (unsupported-opt opts)]
        (r/err :shell/unsupported-opt {:opt     k
                                       :reason  (get unsupported-opts k)
                                       :adapter :sh
                                       :cmd     cmd})
        (let [start (now-ns)]
          (r/try-effect* :shell/exec-failed
            (let [res (apply jsh/sh (sh-args cmd opts (when (:env opts) (host-env))))]
              (->exec-result cmd res (/ (- (now-ns) start) 1e6))))))))

  (shell-env [_]
    (host-env))

  (shell-which [_ program]
    ;; the JVM shares core's resolver (babashka.fs); elsewhere POSIX
    ;; `command -v` answers the same question with the same Result shape
    #?(:cljw    (which-via-command-v program)
       :clj     (detect/which program)
       :default (which-via-command-v program))))

(defn make-shell
  "Create a ShShell with optional default opts (:dir, :env)."
  ([] (make-shell {}))
  ([opts] (->ShShell opts)))
