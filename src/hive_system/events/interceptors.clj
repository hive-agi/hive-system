(ns hive-system.events.interceptors
  "Reusable interceptors for system operations.

   - timing:      Measures wall-clock duration, injects into effects
   - journal:     Records operation to IJournal after execution
   - tool-check:  Validates binary exists before shell exec
   - result-lift: Converts raw handler return into Result-typed effect

   All interceptors follow the re-frame context model:
   {:coeffects {:event [...] :db ...} :effects {...}}"
  (:require [hive.events.interceptor :as i]
            [hive-dsl.result :as r]
            [hive-system.shell.detect :as detect]
            [taoensso.timbre :as log]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: AGPL-3.0-or-later

;; =============================================================================
;; Timing Interceptor
;; =============================================================================

(def timing
  "Measures wall-clock duration of the handler phase.
   Injects :duration-ms into the effects map on :after."
  (i/->interceptor
   :id :sys/timing
   :before (fn [ctx]
             (assoc-in ctx [:coeffects :_start-ns] (System/nanoTime)))
   :after (fn [ctx]
            (let [start (get-in ctx [:coeffects :_start-ns] (System/nanoTime))
                  elapsed-ms (/ (- (System/nanoTime) start) 1e6)]
              (assoc-in ctx [:effects :_duration-ms] elapsed-ms)))))

;; =============================================================================
;; Journal Interceptor
;; =============================================================================

(def journal
  "Records the operation to IJournal after execution.
   Reads :journal-fn from coeffects (injected at init).
   Captures: event type, input, output, duration, success."
  (i/->interceptor
   :id :sys/journal
   :after (fn [ctx]
            (when-let [record! (get-in ctx [:coeffects :journal-fn])]
              (let [event      (get-in ctx [:coeffects :event])
                    result     (get-in ctx [:effects :result])
                    duration   (get-in ctx [:effects :_duration-ms] 0)
                    op-type    (first event)]
                (try
                  (record! {:op-type     op-type
                            :input       (vec (rest event))
                            :output      result
                            :duration-ms duration
                            :success?    (r/ok? result)})
                  (catch Exception e
                    (log/debug "journal record failed:" (.getMessage e))))))
            ctx)))

;; =============================================================================
;; Tool-Check Interceptor
;; =============================================================================

(defn tool-check
  "Interceptor that verifies a binary exists before execution.
   If the binary is not found, short-circuits with an err Result
   containing install hints.

   Usage:
     (reg-event-fx :shell/exec
       [(tool-check :cmd-extractor-fn)]
       handler)

   The extract-fn receives the event and returns the binary name to check.
   Defaults to extracting from the first arg if it's a vector command."
  ([]
   (tool-check nil))
  ([extract-bin-fn]
   (i/->interceptor
    :id :sys/tool-check
    :before (fn [ctx]
              (let [event (get-in ctx [:coeffects :event])
                    cmd   (second event)
                    bin   (cond
                            extract-bin-fn (extract-bin-fn event)
                            (vector? cmd)  (first cmd)
                            :else          nil)]
                (if (and bin (r/err? (detect/which (str bin))))
                  ;; Short-circuit: set result to err, clear queue
                  (-> ctx
                      (assoc :queue [])
                      (assoc-in [:effects :result]
                                (r/err :shell/binary-not-found
                                       {:binary bin
                                        :message (str bin " not found on PATH")})))
                  ctx))))))

;; =============================================================================
;; Emit Interceptor
;; =============================================================================

(def emit
  "After handler completes, dispatches a completion event if :emit is in effects.
   Enables event chaining: handler returns {:result ... :emit [:next-event data]}"
  (i/->interceptor
   :id :sys/emit
   :after (fn [ctx]
            (when-let [event (get-in ctx [:effects :emit])]
              (assoc-in ctx [:effects :dispatch] event))
            ctx)))

;; =============================================================================
;; Convenience: standard system interceptor chain
;; =============================================================================

(def standard
  "Standard interceptor chain for system operations.
   Timing → Journal → Emit (applied in order)."
  [timing journal emit])
