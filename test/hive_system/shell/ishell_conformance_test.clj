(ns hive-system.shell.ishell-conformance-test
  "One IShell contract, run against every adapter.

   The adapters ARE the subject here (an adapter test), so they run for
   real: no stubs, no with-redefs. What an adapter cannot do is read from
   its `capabilities` data, and the suite asserts the declared answer for
   that case — a refusal — instead of skipping it silently."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [hive-system.shell.core :as core]
            [hive-system.shell.sh :as sh]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(def ^:private capability-keys
  #{:timeout? :stdin-file? :inherit-io? :redirect-err? :stdin-bytes? :env-merge?})

(defn- exec [shell cmd & [opts]]
  (proto/shell-exec! shell cmd (or opts {})))

(defn conformance
  "The IShell contract. `make-shell` builds a fresh adapter; `caps` is the
   adapter's declared capability map."
  [make-shell caps]
  (let [shell (make-shell)]
    (testing "capabilities are declared as data, over the shared key set"
      (is (= capability-keys (set (keys caps))))
      (is (every? boolean? (vals caps))))

    (testing "satisfies IShell"
      (is (satisfies? proto/IShell shell)))

    (testing "echo: the result shape"
      (let [res (exec shell "echo hello")]
        (is (r/ok? res))
        (is (= {:exit 0 :stdout "hello\n" :stderr "" :cmd "echo hello"}
               (dissoc (:ok res) :duration-ms :detached)))
        (is (number? (get-in res [:ok :duration-ms])))))

    (testing "a non-zero exit is an ok carrying the code, not an err"
      (let [res (exec shell "exit 42")]
        (is (r/ok? res))
        (is (= 42 (get-in res [:ok :exit])))))

    (testing "stderr is captured separately"
      (let [res (exec shell "echo err >&2")]
        (is (= "" (get-in res [:ok :stdout])))
        (is (= "err\n" (get-in res [:ok :stderr])))))

    (testing ":dir sets the working directory"
      (is (= "/tmp\n" (get-in (exec shell "pwd" {:dir "/tmp"}) [:ok :stdout]))))

    (testing ":env is merged OVER the inherited environment"
      (let [res (exec shell "echo $MY_VAR; command -v cat >/dev/null && echo has-path"
                      {:env {"MY_VAR" "hello-hive"}})]
        (is (= "hello-hive\nhas-path\n" (get-in res [:ok :stdout]))
            "the inherited PATH survives the extra variable")))

    (testing "a vector command is the argv, with no shell expansion"
      (is (= "hello $HOME\n"
             (get-in (exec shell ["echo" "hello" "$HOME"]) [:ok :stdout]))))

    (testing ":in reaches the child's stdin as a String or as bytes"
      (is (= "secret line\nsecond ✓" (get-in (exec shell ["cat"] {:in "secret line\nsecond ✓"})
                                             [:ok :stdout])))
      (when (:stdin-bytes? caps)
        (is (= "raw" (get-in (exec shell ["cat"] {:in (.getBytes "raw" "UTF-8")})
                             [:ok :stdout])))))

    (testing ":in never appears in the result"
      (let [marker (str "IN-MARKER-" (random-uuid))
            res    (exec shell ["sh" "-c" "cat >/dev/null; echo done"] {:in marker})]
        (is (= "done\n" (get-in res [:ok :stdout])))
        (is (not (str/includes? (pr-str res) marker)))))

    (testing "without :in the child reads EOF at once"
      (is (= "" (get-in (exec shell ["cat"]) [:ok :stdout]))))

    (testing "a command that cannot start is an err, not a throw"
      (let [res (exec shell ["/nonexistent/hive-xyz"])]
        (is (r/err? res))
        (is (= :shell/exec-failed (:error res)))))

    (testing "shell-env returns the environment as a string map"
      (let [e (proto/shell-env shell)]
        (is (map? e))
        (is (string? (get e "PATH")))))

    (testing "shell-which resolves sh and refuses what is not there"
      (let [found (proto/shell-which shell "sh")]
        (is (r/ok? found))
        (is (str/ends-with? (get-in found [:ok :path]) "/sh")))
      (is (= :shell/not-found (:error (proto/shell-which shell "nonexistent-hive-xyz")))))

    (testing ":timeout-ms: honoured, or refused up front — never ignored"
      (let [res (exec shell "sleep 10" {:timeout-ms 100})]
        (is (r/err? res))
        (if (:timeout? caps)
          (is (= :shell/timeout (:error res)))
          (do (is (= :shell/unsupported-opt (:error res)))
              (is (= :timeout-ms (:opt res)))))))

    (testing "an opt set to nil or false asks for nothing"
      (is (r/ok? (exec shell "true" {:timeout-ms nil :inherit-io? false}))))))

(deftest processbuilder-shell-conforms
  (conformance #(core/->Shell {}) core/capabilities))

(deftest sh-shell-conforms
  (conformance #(sh/->ShShell {}) sh/capabilities))

;; =============================================================================
;; Pure calculations of the sh adapter
;; =============================================================================

(deftest sh-argv
  (is (= ["sh" "-c" "echo hi"] (sh/->argv "echo hi")))
  (is (= ["echo" "1"] (sh/->argv ["echo" 1]))))

(deftest sh-unsupported-opt
  (is (nil? (sh/unsupported-opt {:dir "/tmp" :env {"A" "b"} :in "x"})))
  (is (= :timeout-ms (sh/unsupported-opt {:timeout-ms 5})))
  (is (= :stdin (sh/unsupported-opt {:stdin "/etc/hostname"})))
  (is (nil? (sh/unsupported-opt {:timeout-ms nil :redirect-err? false}))))

(deftest sh-merge-env
  (is (= {"A" "1" "B" "2"} (sh/merge-env {"A" "0" "B" "2"} {"A" 1})))
  (is (= {"X" "y"} (sh/merge-env nil {"X" "y"}))))

(deftest sh-default-opts-merge-under-call-opts
  (is (= "/\n" (get-in (proto/shell-exec! (sh/->ShShell {:dir "/tmp"}) "pwd" {:dir "/"})
                       [:ok :stdout])))
  (is (= :shell/unsupported-opt
         (:error (proto/shell-exec! (sh/->ShShell {:timeout-ms 1000}) "true" {})))))
