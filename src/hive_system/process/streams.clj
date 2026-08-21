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
