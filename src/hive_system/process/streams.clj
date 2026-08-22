(ns hive-system.process.streams
  "Reading a child process's output without blocking on its descendants.

   EOF on a process stream arrives when the LAST holder of the write end closes
   it, which is not when the command exits: a backgrounded grandchild inherits
   the pipe and holds it open. Every read here is therefore abandonable — it
   runs on a daemon thread and is collected with a BOUNDED deref, so a detached
   descendant cannot extend its caller's deadline.

   Leaf namespace: java.io and clojure.java.io only. No hive-weave, so it loads
   under Babashka."
  (:require [clojure.java.io :as io])
  (:import [java.io BufferedReader InputStream InputStreamReader OutputStream]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(def flush-grace-ms
  "How long a stream drain is given once the command itself has exited."
  1000)

(defn read-stream
  "Drain `is` to a string, blocking until EOF. A closed or faulting stream
   yields \"\".

   This blocks for as long as ANY holder keeps the write end open. Call it
   directly only where there is no deadline; otherwise use `drain`."
  [^InputStream is]
  (try
    (with-open [rdr (BufferedReader. (InputStreamReader. is))]
      (slurp rdr))
    (catch Exception _ "")))

(defn drain
  "Read `is` on a daemon thread. Returns a promise of the string.

   Collect it with a BOUNDED deref — (deref p flush-grace-ms ::open) — so a
   descendant still holding the pipe cannot block the caller. A drain left
   uncollected dies with the JVM rather than holding it open."
  [^InputStream is]
  (let [p (promise)]
    (doto (Thread. #(deliver p (read-stream is)) "hive-system-drain")
      (.setDaemon true)
      (.start))
    p))

(defn read-lines-capped
  "Read at most LIMIT lines from `is`, and at most MAX-BYTES of them.
   Returns {:lines […] :truncated? bool :reason …}.

   ## Why it reads one line PAST the limit

   A caller handed exactly LIMIT lines cannot tell a command that printed LIMIT
   from one that printed more, and those are different answers — the same
   reason `fs.core/find-files` refuses rather than returning a partial walk.
   So one extra line is read purely to decide `:truncated?`, and discarded; it
   is never returned.

   That extra read blocks while a slow producer is still computing, which is
   the honest behaviour: until the next line arrives or the stream closes,
   `is there more?` genuinely has no answer yet. Bound it with a deadline —
   `drain-lines-capped` is the abandonable form.

   ## Why bytes as well as lines

   A line budget does not bound memory: one pathological line exhausts the heap
   while the line count sits at 1. Time, admission and output cardinality are
   independent budgets, and so are the two dimensions of output.

   `:reason` names which bound stopped it — :eof, :max-lines or :max-bytes."
  [^InputStream is ^long limit ^long max-bytes]
  (try
    (let [rdr (BufferedReader. (InputStreamReader. is))]
      (loop [acc (transient []) n 0 bytes 0]
        (if-let [line (.readLine rdr)]
          (let [bytes' (+ bytes (count line) 1)]
            (cond
              ;; the read one past the limit: decide, discard, stop
              (>= n limit)   {:lines (persistent! acc) :truncated? true :reason :max-lines}
              (> bytes' max-bytes) {:lines (persistent! acc) :truncated? true :reason :max-bytes}
              :else          (recur (conj! acc line) (inc n) bytes')))
          {:lines (persistent! acc) :truncated? false :reason :eof})))
    (catch Exception _
      {:lines [] :truncated? false :reason :eof})))

(defn drain-lines-capped
  "`read-lines-capped` on a daemon thread. Returns a promise of its map.

   Collect with a BOUNDED deref, for the reason `drain` gives: a descendant
   holding the inherited pipe must not extend the caller's deadline."
  [^InputStream is limit max-bytes]
  (let [p (promise)]
    (doto (Thread. #(deliver p (read-lines-capped is limit max-bytes))
                   "hive-system-drain-capped")
      (.setDaemon true)
      (.start))
    p))

(defn pump
  "Copy `from-out` into `to-in` on a daemon thread, closing `to-in` at EOF so
   the downstream process sees the end of its input.

   Returns a promise of :done, or of the Throwable that stopped the copy — a
   pump that died silently would look exactly like one that finished."
  [^InputStream from-out ^OutputStream to-in]
  (let [p (promise)]
    (doto (Thread. #(deliver p (try
                                 (io/copy from-out to-in)
                                 :done
                                 (catch Throwable t t)
                                 (finally
                                   (try (.close to-in) (catch Exception _ nil)))))
                   "hive-system-pump")
      (.setDaemon true)
      (.start))
    p))
