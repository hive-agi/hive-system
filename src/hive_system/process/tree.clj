(ns hive-system.process.tree
  "Destroying a process together with everything it spawned.

   Killing only the direct child leaves grandchildren alive, holding the pipes
   and whatever resource the kill was meant to reclaim — a timeout that reaps
   just the shell reclaims nothing.

   Leaf namespace: java.lang only. No hive-weave, so it loads under Babashka."
  (:import [java.lang Process ProcessHandle]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(defn descendant-handles
  "Every live descendant of `proc`, as a seq of ProcessHandle."
  [^Process proc]
  (iterator-seq (.iterator (.descendants proc))))

(defn destroy-tree!
  "Destroy `proc` and every process it spawned, descendants first so a parent
   cannot respawn a child that was already reaped.

   `force?` selects SIGKILL (.destroyForcibly) over SIGTERM (.destroy): a
   deadline kill forces, a :term-style signal asks. Returns nil."
  ([proc] (destroy-tree! proc false))
  ([^Process proc force?]
   (doseq [^ProcessHandle h (descendant-handles proc)]
     (if force? (.destroyForcibly h) (.destroy h)))
   (if force? (.destroyForcibly proc) (.destroy proc))
   nil))
