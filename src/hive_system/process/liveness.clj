(ns hive-system.process.liveness
  "Process liveness detection — single source of truth for `is this pid alive?`
   semantics across the hive ecosystem.

   Use this instead of inlining `kill -0`, `ProcessHandle/of`, or backend-
   specific tricks. Liveness check is a system-level concern and belongs in
   hive-system (per the IProcess family of protocols), not in callers.

   The `LivenessSignal` ADT is the closed sum of valid outcomes:

     :liveness/alive   — pid is owned by a live OS process
     :liveness/dead    — pid was once valid but the process is gone (ESRCH)
     :liveness/unknown — pid is nil/non-integer, or the check itself raised
                         transiently. Callers MUST NOT zombify on :unknown
                         (degrade-soft semantics — protect against false
                         positives during boot races, container migrations,
                         and short-lived OS hiccups)."
  (:require [hive-dsl.adt :refer [defadt]])
  (:import [java.lang ProcessHandle]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: AGPL-3.0-or-later

;; =============================================================================
;; ADT
;; =============================================================================

(defadt LivenessSignal
  "OS-level liveness check outcome. See ns docstring."
  :liveness/alive
  :liveness/dead
  :liveness/unknown)

;; =============================================================================
;; Public API
;; =============================================================================

(defn check-pid-alive
  "Return a LivenessSignal ADT value for the given pid.

   Pure-ish: only side effect is asking the JVM about a numeric pid.
   No shell-out, no subprocess spawn — uses ProcessHandle.of which is a
   syscall-level lookup against the OS process table.

     nil pid                 → :liveness/unknown
     non-integer pid         → :liveness/unknown
     ProcessHandle.of throws → :liveness/unknown   (degrade, do NOT zombify)
     handle present + alive  → :liveness/alive
     handle absent OR !alive → :liveness/dead"
  [pid]
  (if-not (and (some? pid) (integer? pid))
    (->liveness-signal :liveness/unknown)
    (try
      (let [opt (ProcessHandle/of (long pid))]
        (->liveness-signal
         (if (and (.isPresent opt) (.isAlive (.get opt)))
           :liveness/alive
           :liveness/dead)))
      (catch Throwable _
        (->liveness-signal :liveness/unknown)))))

(defn dead?
  "True iff the pid resolves to :liveness/dead. False on alive/unknown.
   Use this when you only zombify on confirmed-dead — e.g. terminal-sweep
   pid-fallback when the addon channel itself errored."
  [pid]
  (= :liveness/dead (:adt/variant (check-pid-alive pid))))

(defn alive?
  "True iff the pid resolves to :liveness/alive. False on dead/unknown."
  [pid]
  (= :liveness/alive (:adt/variant (check-pid-alive pid))))
