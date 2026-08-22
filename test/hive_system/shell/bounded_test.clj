(ns hive-system.shell.bounded-test
  "IBoundedShell — output cardinality as a budget in its own right.

   `shell-exec!` is correct when the caller wants what the command printed; its
   memory cost is then set by the CHILD. A caller with a line budget needs a
   different contract, and the three budgets do not substitute for one another:
   a timeout does not bound memory, and an admission gate does not bound output.

   Two claims here are load-bearing and neither is provable by inspection:

     TRUNCATION IS DISTINGUISHABLE. A caller handed exactly :max-lines lines
     must be able to tell a command that printed that many from one that
     printed more. A silently truncated list reads as a complete answer — the
     same hazard `fs.core/find-files` refuses a partial walk over.

     THE CAP STOPS THE PRODUCER. Reading less is not spending less: a command
     left running goes on consuming exactly the resources the budget was
     declared to bound. Proven against a process that never exits on its own."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [hive-system.process.streams :as streams]
            [hive-system.shell.core :as sh])
  (:import [java.io ByteArrayInputStream]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(defn- lines! [cmd opts]
  (let [res (sh/lines! cmd opts)]
    (is (r/ok? res) (str "lines! refused: " (pr-str res)))
    (:ok res)))

(defn- stream-of [^String s]
  (ByteArrayInputStream. (.getBytes s "UTF-8")))

;;; =============================================================================
;;; The seam
;;; =============================================================================

(deftest the-shell-satisfies-both-protocols-and-they-stay-separate
  (let [s (sh/make-shell)]
    (is (satisfies? proto/IShell s))
    (is (satisfies? proto/IBoundedShell s))
    (testing "IShell has no line budget and IBoundedShell no full capture"
      (is (nil? (:max-lines (:ok (sh/exec! ["echo" "x"] {}))))
          "exec! answers with :stdout, never a bounded :lines")
      (is (nil? (:stdout (lines! ["echo" "x"] {})))
          "lines! answers with :lines, never the whole capture"))))

;;; =============================================================================
;;; Truncation is distinguishable from completion
;;; =============================================================================

(deftest a-command-under-the-cap-is-complete
  (let [{:keys [lines truncated? reason exit]} (lines! ["sh" "-c" "seq 1 3"] {:max-lines 5})]
    (is (= ["1" "2" "3"] lines))
    (is (false? truncated?))
    (is (= :eof reason))
    (is (= 0 exit) "it ran to completion, so it has a real exit status")))

(deftest a-command-printing-EXACTLY-the-cap-is-still-complete
  ;; The case the whole design turns on. A reader that simply stops at the cap
  ;; cannot tell this from the next test, and would report both as truncated —
  ;; or, worse, both as complete.
  (let [{:keys [lines truncated? reason exit]} (lines! ["sh" "-c" "seq 1 5"] {:max-lines 5})]
    (is (= ["1" "2" "3" "4" "5"] lines))
    (is (false? truncated?)
        "exactly :max-lines lines is a COMPLETE answer, not a coincidence")
    (is (= :eof reason))
    (is (= 0 exit))))

(deftest a-command-over-the-cap-is-truncated-and-says-so
  (let [{:keys [lines truncated? reason exit]} (lines! ["sh" "-c" "seq 1 100000"] {:max-lines 5})]
    (is (= ["1" "2" "3" "4" "5"] lines) "the budget is honoured exactly")
    (is (true? truncated?))
    (is (= :max-lines reason))
    (is (nil? exit)
        "it was killed for exceeding the budget, so any status it now carries
         describes the kill rather than the command")))

(deftest the-lines-returned-are-a-prefix-of-what-the-command-printed
  ;; Metamorphic: truncating must not reorder or drop from the middle.
  (let [full (str/split-lines (:stdout (:ok (sh/exec! ["sh" "-c" "seq 1 50"] {}))))]
    (doseq [cap [1 7 50]]
      (is (= (take cap full) (:lines (lines! ["sh" "-c" "seq 1 50"] {:max-lines cap})))
          (str "cap " cap)))))

;;; =============================================================================
;;; Bytes bound what lines cannot
;;; =============================================================================

(deftest the-byte-budget-binds-independently-of-the-line-budget
  (testing "a generous line cap does not license unbounded memory"
    (let [{:keys [lines truncated? reason]}
          (lines! ["sh" "-c" "seq 1 100000"] {:max-lines 1000000 :max-bytes 12})]
      (is (true? truncated?))
      (is (= :max-bytes reason) "the BYTE bound is what stopped it")
      (is (= ["1" "2" "3" "4" "5" "6"] lines) "6 lines of \"n\\n\" is exactly 12 bytes")))
  (testing "and one pathological line is caught with the line count still at 1"
    (let [{:keys [lines truncated? reason]}
          (lines! ["sh" "-c" "head -c 100000 /dev/zero | tr '\\0' 'x'"]
                  {:max-lines 1000 :max-bytes 500})]
      (is (true? truncated?))
      (is (= :max-bytes reason))
      (is (empty? lines)
          "the single over-budget line is refused rather than half-returned"))))

;;; =============================================================================
;;; The cap stops the PRODUCER, not just the reading
;;; =============================================================================

(deftest hitting-the-cap-destroys-the-process-tree
  ;; `yes` never exits. If the cap only stopped READING, this test would hang
  ;; until the timeout and leave the child running afterwards — so both halves
  ;; of the assertion are the point.
  (let [t0  (System/currentTimeMillis)
        res (lines! ["yes"] {:max-lines 3 :timeout-ms 10000})
        ms  (- (System/currentTimeMillis) t0)]
    (is (= ["y" "y" "y"] (:lines res)))
    (is (true? (:truncated? res)))
    (is (< ms 5000)
        "it returned on the cap, not on the deadline")
    (Thread/sleep 300)
    (let [survivors (str/trim (str (:stdout (:ok (sh/exec! ["pgrep" "-x" "yes"] {})))))]
      (is (str/blank? survivors)
          (str "a capped command was left running: pids " survivors)))))

(deftest a-descendant-holding-the-pipe-cannot-outlive-the-cap
  ;; EOF on the pipe arrives when the LAST holder closes it, so a backgrounded
  ;; grandchild keeps the stream open after the command itself is gone. The
  ;; read is abandonable and the teardown covers the whole tree.
  (let [t0  (System/currentTimeMillis)
        res (lines! ["sh" "-c" "seq 1 100; sleep 30 &"] {:max-lines 10 :timeout-ms 8000})
        ms  (- (System/currentTimeMillis) t0)]
    (is (= 10 (count (:lines res))))
    (is (true? (:truncated? res)))
    (is (< ms 5000) "the detached grandchild did not extend the caller's deadline")))

;;; =============================================================================
;;; Time is still its own budget
;;; =============================================================================

(deftest the-deadline-is-a-lawful-err-not-a-thrown-fault
  (let [res (sh/lines! ["sh" "-c" "sleep 5"] {:timeout-ms 300})]
    (is (r/err? res) "a timeout must not come back wrapped in ok")
    (is (= :shell/timeout (:error res)))
    (is (= 300 (:timeout-ms res)))))

(deftest a-slow-command-under-its-deadline-still-answers
  (let [{:keys [lines truncated?]} (lines! ["sh" "-c" "echo a; sleep 0.2; echo b"]
                                           {:max-lines 10 :timeout-ms 5000})]
    (is (= ["a" "b"] lines))
    (is (false? truncated?))))

;;; =============================================================================
;;; stderr and exit survive the budget
;;; =============================================================================

(deftest stderr-is-captured-alongside-the-bounded-stdout
  (let [{:keys [lines stderr]} (lines! ["sh" "-c" "echo out; echo boom >&2"] {:max-lines 10})]
    (is (= ["out"] lines))
    (is (str/includes? stderr "boom")
        "a bounded stdout must not cost the caller its diagnostics")))

(deftest a-nonzero-exit-is-reported-rather-than-refused
  (let [{:keys [lines exit truncated?]} (lines! ["sh" "-c" "echo x; exit 3"] {:max-lines 10})]
    (is (= ["x"] lines))
    (is (= 3 exit) "exit status is data here, as it is for exec!")
    (is (false? truncated?))))

;;; =============================================================================
;;; The reader itself — leaf, pure over a stream, total
;;; =============================================================================

(defn- rlc [s limit max-bytes]
  (streams/read-lines-capped (stream-of s) limit max-bytes))

(deftest the-leaf-reader-agrees-with-the-shell-contract
  (testing "under, exactly at, and over the line bound"
    (is (= {:lines ["a" "b"] :truncated? false :reason :eof} (rlc "a\nb\n" 5 1000)))
    (is (= {:lines ["a" "b"] :truncated? false :reason :eof} (rlc "a\nb\n" 2 1000)))
    (is (= {:lines ["a" "b"] :truncated? true  :reason :max-lines} (rlc "a\nb\nc\n" 2 1000))))
  (testing "the byte bound"
    (is (= :max-bytes (:reason (rlc "aaaa\nbbbb\n" 100 5)))))
  (testing "empty input is complete, not truncated"
    (is (= {:lines [] :truncated? false :reason :eof} (rlc "" 5 1000)))))

(defspec the-reader-is-total-and-never-exceeds-its-budget 100
  (prop/for-all [ls    (gen/vector (gen/such-that #(not (str/includes? % "\n"))
                                                  gen/string-ascii)
                                   0 30)
                 limit (gen/choose 0 30)]
    (let [{:keys [lines truncated? reason]} (rlc (str/join "\n" ls) limit 1000000)]
      (and (<= (count lines) limit)
           (= lines (vec (take (count lines) ls)))
           (contains? #{:eof :max-lines :max-bytes} reason)
           ;; truncated exactly when the source had more than the budget allowed
           (= truncated? (> (count ls) limit))))))
