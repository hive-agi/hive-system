(ns hive-system.events.system
  "Event-driven system operations.

   Registers event handlers for shell execution, tool checking,
   and process lifecycle. Each handler returns a Result in the
   effects map, which the journal interceptor persists.

   Init:
     (init!)                        ;; default — no journal
     (init! {:journal-fn record!})  ;; with IJournal callback

   Dispatch:
     (dispatch [:sys/exec \"ls -la\"])
     (dispatch [:sys/exec [\"rg\" \"pattern\" \"src/\"]])
     (dispatch [:sys/exec-ok \"make test\"])
     (dispatch [:sys/which \"rg\"])
     (dispatch [:sys/require-tool :ripgrep])
     (dispatch [:sys/require-tools [:ripgrep :fd :jq]])

   All handlers return {:result (ok ...) or (err ...)} in effects.
   The timing interceptor adds :_duration-ms.
   The journal interceptor persists to IJournal if configured."
  (:require [hive.events :as ev]
            [hive.events.router :as router]
            [hive-dsl.result :as r :refer [try-effect*]]
            [hive-system.events.interceptors :as sys-i]
            [hive-system.shell.core :as sh]
            [hive-system.shell.tools :as tools]
            [hive-system.shell.detect :as detect]
            [clojure.string :as str]
            [taoensso.timbre :as log]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: AGPL-3.0-or-later

;; =============================================================================
;; Initialization
;; =============================================================================

(declare register-handlers!)

(defonce ^:private initialized? (atom false))

(defn init!
  "Initialize the event-driven system layer.

   Opts:
     :journal-fn — (fn [op-map]) callback for IJournal recording.
                   op-map: {:op-type :input :output :duration-ms :success?}
     :db         — initial app-db atom (default: fresh atom)"
  ([] (init! {}))
  ([{:keys [journal-fn db]}]
   (when-not @initialized?
     (let [db-atom (or db (atom {}))]
       (router/init! db-atom)

       ;; Register no-op effects — read from context, not executed
       (ev/reg-fx :result (fn [_] nil))
       (ev/reg-fx :_duration-ms (fn [_] nil))

       ;; Inject journal-fn as a coeffect
       (when journal-fn
         (ev/reg-cofx :journal
           (fn [coeffects]
             (assoc coeffects :journal-fn journal-fn))))

       (register-handlers! journal-fn)
       (reset! initialized? true)
       (log/info "hive-system events initialized"
                 {:journal? (boolean journal-fn)})))))

(defn shutdown!
  "Stop the event processing loop and reset state."
  []
  (when (compare-and-set! initialized? true false)
    (router/stop!)))

;; =============================================================================
;; Effect: :result
;; =============================================================================
;; Handlers return {:result (r/ok ...)} or {:result (r/err ...)}.
;; The journal interceptor reads :result from effects to record it.
;; Callers use dispatch-sync to get the context and extract :result.

(defn dispatch-result
  "Dispatch synchronously and extract the :result from effects.
   Returns the Result (ok/err) directly."
  [event]
  (let [ctx (ev/dispatch-sync event)]
    (get-in ctx [:effects :result])))

;; =============================================================================
;; Handler Registration
;; =============================================================================

(defn- register-handlers!
  "Register all system event handlers."
  [journal-fn]
  (let [inject-journal (when journal-fn [(ev/inject-cofx :journal)])
        chain (into (vec inject-journal) sys-i/standard)]

    ;; ── :sys/exec ──────────────────────────────────────────────────────
    ;; Execute a shell command. Returns Result with exit/stdout/stderr.
    (ev/reg-event-fx :sys/exec
      chain
      (fn [_coeffects [_ cmd opts]]
        {:result (sh/exec! cmd (or opts {}))}))

    ;; ── :sys/exec-ok ───────────────────────────────────────────────────
    ;; Execute and enforce zero exit code.
    (ev/reg-event-fx :sys/exec-ok
      chain
      (fn [_coeffects [_ cmd opts]]
        {:result (sh/exec-ok! cmd (or opts {}))}))

    ;; ── :sys/exec-pipe ─────────────────────────────────────────────────
    ;; Execute a pipeline of commands (cmd1 | cmd2 | ...).
    (ev/reg-event-fx :sys/exec-pipe
      chain
      (fn [_coeffects [_ cmds opts]]
        {:result (try-effect* :shell/pipe-failed
                   (let [pipeline (clojure.string/join " | " cmds)]
                     (:ok (sh/exec! pipeline (or opts {})))))}))

    ;; ── :sys/which ─────────────────────────────────────────────────────
    ;; Resolve binary path.
    (ev/reg-event-fx :sys/which
      chain
      (fn [_coeffects [_ program]]
        {:result (detect/which program)}))

    ;; ── :sys/require-tool ──────────────────────────────────────────────
    ;; Check tool with install hints.
    (ev/reg-event-fx :sys/require-tool
      chain
      (fn [_coeffects [_ tool-key]]
        {:result (tools/require-tool tool-key)}))

    ;; ── :sys/require-tools ─────────────────────────────────────────────
    ;; Batch tool check.
    (ev/reg-event-fx :sys/require-tools
      chain
      (fn [_coeffects [_ tool-keys]]
        {:result (r/ok (tools/require-tools tool-keys))}))

    ;; ── :sys/env ───────────────────────────────────────────────────────
    ;; Get environment variables.
    (ev/reg-event-fx :sys/env
      chain
      (fn [_coeffects _event]
        {:result (r/ok (sh/env))}))

    ;; ── :sys/tool-exec ─────────────────────────────────────────────────
    ;; Execute a registered tool by key. Checks existence first via
    ;; tool-check interceptor, then runs with provided args.
    (ev/reg-event-fx :sys/tool-exec
      (into chain [(sys-i/tool-check
                     (fn [[_ tool-key _args]]
                       (some-> (tools/require-tool tool-key)
                               :ok :program)))])
      (fn [_coeffects [_ tool-key args opts]]
        (let [tool-result (tools/require-tool tool-key)]
          (if (r/err? tool-result)
            {:result tool-result}
            (let [bin (get-in tool-result [:ok :path])
                  cmd (into [bin] (or args []))]
              {:result (sh/exec! cmd (or opts {}))})))))))
