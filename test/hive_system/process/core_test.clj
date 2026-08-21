(ns hive-system.process.core-test
  "Tests for IProcess implementation — spawn!/wait!/signal!/pipe!.
   Golden snapshots the spawn+wait output shape. Property tests verify Result
   railway totality. Mutation tests catch blind spots in error handling.

   Isolation: spawns ONLY hermetic OS builtins (echo, sleep, cat, true, exit)
   as ephemeral child processes it creates and reaps — never a live/shared
   hive system."
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.string :as str]
            [clojure.test.check.generators :as gen]
            [hive-test.golden :refer [deftest-golden]]
            [hive-test.mutation :refer [deftest-mutation-witness]]
            [hive-test.properties :refer [defprop-total]]
            [hive-dsl.result :as r]
            [hive-system.process.core :as proc]
            [hive-system.protocols :as proto]))

;; =============================================================================
;; Golden: spawn + wait output shape (deterministic command)
;; =============================================================================

(deftest-golden spawn-wait-echo-shape
  "test/golden/process/spawn-wait-echo.edn"
  (let [h (:ok (proc/spawn! "echo deterministic"))]
    (proc/wait! h 5000)))

;; =============================================================================
;; Unit: spawn! returns a live handle
;; =============================================================================

(deftest spawn-returns-handle
  (testing "spawn! returns ok with pid, process, and open streams"
    (let [result (proc/spawn! "echo hi")]
      (is (r/ok? result))
      (let [{:keys [pid process stdin stdout stderr]} (:ok result)]
        (is (integer? pid))
        (is (pos? pid))
        (is (instance? Process process))
        (is (some? stdin))
        (is (some? stdout))
        (is (some? stderr)))
      ;; reap so we don't leak the child
      (proc/wait! (:ok result) 5000))))

;; =============================================================================
;; Unit: wait! drains output and captures exit code
;; =============================================================================

(deftest wait-success
  (testing "wait! returns exit-code 0 and captured stdout"
    (let [h (:ok (proc/spawn! "echo hello"))
          result (proc/wait! h 5000)]
      (is (r/ok? result))
      (is (zero? (get-in result [:ok :exit-code])))
      (is (= "hello\n" (get-in result [:ok :stdout])))
      (is (= "" (get-in result [:ok :stderr]))))))

(deftest wait-nonzero-exit
  (testing "wait! surfaces a non-zero exit code (still ok)"
    (let [h (:ok (proc/spawn! ["sh" "-c" "exit 7"]))
          result (proc/wait! h 5000)]
      (is (r/ok? result))
      (is (= 7 (get-in result [:ok :exit-code]))))))

(deftest wait-stderr-capture
  (testing "wait! captures stderr separately"
    (let [h (:ok (proc/spawn! "echo err >&2"))
          result (proc/wait! h 5000)]
      (is (r/ok? result))
      (is (= "err\n" (get-in result [:ok :stderr]))))))

(deftest wait-timeout
  (testing "wait! returns err :process/timeout and kills the process"
    (let [h (:ok (proc/spawn! ["sleep" "10"]))
          result (proc/wait! h 100)]
      (is (r/err? result))
      (is (= :process/timeout (:error result))))))

(deftest wait-does-not-block-on-a-backgrounded-grandchild
  (testing "EOF on the pipe is not the child's exit, so the drain is bounded"
    ;; The grandchild inherits the write end of stdout and holds it open long
    ;; after `sh` exits. Deref'ing the drain unbounded made a 5s wait take 30s.
    (let [t0      (System/currentTimeMillis)
          h       (:ok (proc/spawn! ["sh" "-c" "sleep 30 & echo started"]))
          result  (proc/wait! h 5000)
          elapsed (- (System/currentTimeMillis) t0)]
      (is (r/ok? result))
      (is (zero? (get-in result [:ok :exit-code])))
      (is (< elapsed 4000)
          "returned on the flush grace, not on the grandchild")
      (is (true? (get-in result [:ok :detached]))
          "and the caller is told the output was cut short")
      (proc/signal! h :tree))))

(deftest wait-does-not-mark-a-clean-exit-detached
  (testing "a process whose tree really exits reports no truncation"
    (let [h      (:ok (proc/spawn! ["echo" "clean"]))
          result (proc/wait! h 5000)]
      (is (r/ok? result))
      (is (nil? (get-in result [:ok :detached])))
      (is (str/includes? (get-in result [:ok :stdout]) "clean")))))

(deftest wait-timeout-kills-the-whole-tree
  (testing "a grandchild does not outlive the timeout that killed its parent"
    ;; Asked of the filesystem, not of the process table: `pgrep -f` also
    ;; matches whatever shell happens to carry the marker in ITS command line.
    (let [witness (java.io.File/createTempFile "hive-system-proc-tree-" ".witness")
          path    (.getAbsolutePath witness)]
      (.delete witness)
      (let [h (:ok (proc/spawn! ["sh" "-c" (str "(sleep 2; touch " path ") & sleep 30")]))]
        (is (r/err? (proc/wait! h 500))))
      (Thread/sleep 3000)
      (is (not (.exists (java.io.File. path)))
          "the backgrounded grandchild was reaped with its parent")
      (.delete (java.io.File. path)))))

(deftest wait-timeout-forces-a-child-that-ignores-term
  (testing "the deadline has already passed, so the kill does not ask politely"
    ;; `trap '' TERM` installs SIG_IGN, which survives the exec into sleep. A
    ;; graceful .destroy is silently ignored by such a child and the timeout
    ;; reclaims nothing; only .destroyForcibly ends it.
    (let [h      (:ok (proc/spawn! ["sh" "-c" "trap '' TERM; sleep 30"]))
          ^Process p (:process h)
          result (proc/wait! h 500)]
      (is (r/err? result))
      (is (= :process/timeout (:error result)))
      (is (.waitFor p 4000 java.util.concurrent.TimeUnit/MILLISECONDS)
          "a TERM-ignoring child must still be gone after the deadline kill"))))

;; =============================================================================
;; Unit: signal!
;; =============================================================================

(deftest signal-kill-terminates
  (testing "signal! :kill terminates a long-running process"
    (let [h (:ok (proc/spawn! ["sleep" "30"]))
          sig (proc/signal! h :kill)]
      (is (r/ok? sig))
      (is (true? (get-in sig [:ok :delivered?])))
      ;; the killed process now exits; wait! reaps it
      (let [w (proc/wait! h 5000)]
        (is (r/ok? w))
        (is (integer? (get-in w [:ok :exit-code])))))))

(deftest signal-dead-is-noop
  (testing "signal! on an already-dead pid is a successful no-op"
    (let [h (:ok (proc/spawn! ["true"]))]
      (proc/wait! h 5000)                       ; process exits and is reaped
      (let [sig (proc/signal! h :term)]
        (is (r/ok? sig))
        (is (false? (get-in sig [:ok :delivered?])))
        (is (true? (get-in sig [:ok :already-dead?])))))))

;; =============================================================================
;; Unit: pipe! wires stdout(A) -> stdin(B)
;; =============================================================================

(deftest pipe-connects-processes
  (testing "pipe! feeds A's stdout into B's stdin"
    (let [a (:ok (proc/spawn! ["echo" "piped-data"]))
          b (:ok (proc/spawn! ["cat"]))
          piped (proc/pipe! a b)]
      (is (r/ok? piped))
      (let [w (proc/wait! b 5000)]
        (is (r/ok? w))
        (is (str/includes? (get-in w [:ok :stdout]) "piped-data")))
      (proc/signal! a :kill))))

;; =============================================================================
;; Unit: IProcess protocol satisfied
;; =============================================================================

(deftest process-satisfies-protocol
  (testing "ProcessManager record satisfies IProcess"
    (is (satisfies? proto/IProcess (proc/make-process-manager)))))

;; =============================================================================
;; Mutation: spawn! error path — a faked handle must not survive wait!
;; =============================================================================

(deftest-mutation-witness spawn-real-output-witness
  hive-system.process.core/spawn!
  ;; Mutant: return a fake handle with a nil process
  (fn
    ([_]   (r/ok {:pid 0 :process nil :stdin nil :stdout nil :stderr nil :cmd "fake"}))
    ([_ _] (r/ok {:pid 0 :process nil :stdin nil :stdout nil :stderr nil :cmd "fake"})))
  (fn []
    (let [h (:ok (proc/spawn! "echo real-output"))
          w (proc/wait! h 5000)]
      (is (r/ok? w))
      (is (= "real-output\n" (get-in w [:ok :stdout]))))))

;; =============================================================================
;; Property: spawn! + wait! is total for safe echo commands
;; =============================================================================

(defprop-total spawn-wait-total
  (fn [s]
    (let [spawned (proc/spawn! (str "echo " s))]
      (if (r/ok? spawned)
        (proc/wait! (:ok spawned) 5000)
        spawned)))
  gen/string-alphanumeric
  {:num-tests 20
   :pred (fn [r] (or (r/ok? r) (r/err? r)))})
