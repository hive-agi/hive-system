(ns hive-system.shell.posix
  "Pure POSIX shell-quoting helpers.

   Two functions:

     - `shell-quote` — single-quote a string for safe embedding in a
       `sh -c` command, escaping embedded single-quotes and quoting the
       empty string as `''` so it survives tokenization.
     - `join-as-cmd`  — join an argv into one shell-command string by
       quoting each element with `shell-quote`.

   Re-quoting an already-quoted string nests correctly — each `sh -c`
   peel removes exactly one quoting layer."
  (:require [clojure.string :as str]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: AGPL-3.0-or-later

(def ^:private needs-quoting
  "Match any character whose presence forces single-quoting under POSIX
   sh: whitespace, command/variable substitution, glob, redirection,
   grouping, history, etc."
  #"[\s'\"$`\\!*?\[\](){}|&;<>#~]")

(defn shell-quote
  "POSIX single-quote `arg` for safe embedding in a `sh -c` command.

   - empty string → `''` (otherwise it would collapse into adjacent
     whitespace during sh tokenization)
   - string with shell metacharacters → `'…'`, with embedded `'`
     rewritten as `'\\''`
   - otherwise → returned unchanged."
  ^String [^String arg]
  (cond
    (.isEmpty arg)              "''"
    (re-find needs-quoting arg) (str \' (str/replace arg "'" "'\\''") \')
    :else                       arg))

(defn join-as-cmd
  "Quote every element of `argv` with `shell-quote` and join with spaces
   into a single command string suitable for `sh -c`."
  ^String [argv]
  (str/join " " (map shell-quote argv)))
