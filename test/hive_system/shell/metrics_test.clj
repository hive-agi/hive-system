(ns hive-system.shell.metrics-test
  "Shell runs are timed as `[:proc/shell program]` through the late-bound
   hive-ttracking metrics port, observed with a recording stub sink."
  (:require [clojure.test :refer [deftest is testing]]
            [hive-dsl.result :as r]
            [hive-system.shell.core :as shell]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(deftest program-label-is-bounded
  (testing "only the program base name, never arguments or directories"
    (is (= "git" (shell/program-label ["/usr/bin/git" "status" "/secret/path"])))
    (is (= "rg" (shell/program-label ["rg" "--files"])))
    (is (= "sh" (shell/program-label "echo hi && cat /etc/passwd")))
    (is (= "?" (shell/program-label [])))
    (is (= "?" (shell/program-label nil)))))

(deftest timed-proc-returns-the-thunk-value-and-rethrows
  (is (= (r/ok 1) (shell/timed-proc ["x"] #(r/ok 1))))
  (is (r/err? (shell/timed-proc ["x"] #(r/err :e {}))))
  (is (thrown? ArithmeticException (shell/timed-proc ["x"] #(/ 1 0)))))

(defn- recording-sink
  "A stub IMetricsSink appending [k outcome] to `log`, built with eval because
   the port is bound late."
  [proto-var log]
  (let [psym (symbol (str (:ns (meta proto-var))) (str (:name (meta proto-var))))]
    ((eval `(fn [l#]
              (reify ~psym
                (~'observe! [~'_ k# ~'_ns outcome#] (swap! l# conj [k# outcome#]) nil)
                (~'snapshot [~'_] {}))))
     log)))

(deftest exec-records-through-the-port
  (when-let [install (try (requiring-resolve 'hive-ttracking.metrics/install!)
                          (catch Throwable _ nil))]
    (let [current (requiring-resolve 'hive-ttracking.metrics/current-sink)
          proto   (requiring-resolve 'hive-ttracking.metrics/IMetricsSink)
          log     (atom [])
          prev    (current)]
      (install (recording-sink proto log))
      (try
        (shell/exec! ["true"])
        (shell/exec! ["sh" "-c" "sleep 2"] {:timeout-ms 50})
        (shell/lines! ["echo" "a"])
        (finally (install prev)))
      (is (some #{[[:proc/shell "true"] :ok]} @log))
      (is (some #{[[:proc/shell "sh"] :error]} @log))
      (is (some #{[[:proc/shell "echo"] :ok]} @log)))))
