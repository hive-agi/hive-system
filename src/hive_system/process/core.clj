(ns hive-system.process.core
  "IProcess implementation wrapping Java ProcessBuilder.

   Every operation returns hive-dsl Result and is journaled via IJournal.

   Design:
   - process-spawn!: ProcessBuilder + start, captures pid, streams
   - process-wait!: waitFor with timeout, captures exit code + output
   - process-signal!: pid-based signal via ProcessHandle
   - process-pipe!: redirects stdout→stdin between processes

   All errors are values (Result/err), never thrown exceptions."
  (:require [hive-system.protocols :as proto]
            [hive-dsl.result :as r]
            [taoensso.timbre :as log]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: AGPL-3.0-or-later

;; TODO: Implement IProcess via ProcessBuilder.
;; Placeholder for scaffold — implementation follows in Wave 2.
