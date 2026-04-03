(ns hive-system.temporal.journal
  "IJournal implementation backed by Datahike.

   Stores operation executions as Datalog entities with bitemporal attributes:
   - :op/tx-time     — when the operation was recorded (Datahike transaction time)
   - :op/valid-time  — when the operation actually occurred (wall clock)
   - :op/type        — keyword (:process/spawn, :network/connect, :shell/exec, etc.)
   - :op/input       — EDN-serialized input args
   - :op/output      — EDN-serialized Result (ok value or err)
   - :op/duration-ms — wall-clock duration
   - :op/success?    — boolean (derived from Result)
   - :op/caller      — agent-id or context string
   - :op/session     — session identifier
   - :op/causal-prev — reference to prior operation (causal chain)

   Schema is installed on first connection. Idempotent."
  (:require [hive-system.protocols :as proto]
            [hive-dsl.result :as r]
            [taoensso.timbre :as log]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: AGPL-3.0-or-later

;; TODO: Implement Datahike connection, schema, and IJournal methods.
;; Placeholder for scaffold — implementation follows in Wave 1.
