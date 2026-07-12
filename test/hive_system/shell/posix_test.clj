(ns hive-system.shell.posix-test
  "Trifecta tests for `hive-system.shell.posix`.

   Coverage:
   - golden  : pinpoint cases (empty, plain, space, embedded quote,
               backtick, etc.) pin the quoted form per input.
   - property: forall argv, round-tripping through `sh -c printf '%s\\n'`
               recovers the original argv.
   - mutation: strawmen quoters (identity, double-quote-only) are
               rejected — proves the property test is not trivially
               satisfiable."
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [clojure.string :as str]
            [hive-system.shell.posix :as posix]
            [hive-test.trifecta :refer [deftrifecta]])
  (:import [java.lang ProcessBuilder]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

;; =============================================================================
;; Generators

(def ^:private gen-arg
  "Strings that exercise empty, plain, and metacharacter cases."
  (gen/one-of
   [(gen/elements ["simple" "%h:%p" "127.0.0.1" "-o" "Port=22" ""])
    (gen/fmap (fn [parts] (str/join " " parts))
              (gen/vector (gen/elements ["ssh" "-o" "nc" "%h" "%p" "a" "b"])
                          1 6))
    gen/string-alphanumeric
    (gen/elements ["a'b" "x\"y" "$VAR" "`cmd`" "a;b" "a&b" "a|b" "*" "?"])]))

(def ^:private gen-argv (gen/vector gen-arg 1 8))

;; =============================================================================
;; Helpers

(defn- sh-roundtrip
  "Quote `argv` into a shell command via `join-as-cmd`, run it through
   `sh -c`, recover argv from `printf %s\\n` output. Returns the
   recovered argv or `:sh-failed`."
  [argv]
  (let [cmd  (posix/join-as-cmd (into ["printf" "%s\\n"] argv))
        pb   (doto (ProcessBuilder. ["sh" "-c" cmd])
               (.redirectErrorStream true))
        proc (.start pb)
        out  (slurp (.getInputStream proc))
        exit (.waitFor proc)]
    (if (zero? exit)
      (vec (drop-last (str/split out #"\n" -1)))
      :sh-failed)))

;; =============================================================================
;; Trifecta — shell-quote

(deftrifecta shell-quote-trifecta
  hive-system.shell.posix/shell-quote
  {:golden-path "test/golden/shell-quote.edn"
   :cases     {:empty         ""
               :plain         "simple"
               :space         "has space"
               :single-quote  "a'b"
               :dollar        "$VAR"
               :backtick      "`whoami`"
               :semicolon     "a;b"
               :percent       "%h:%p"
               :proxy-command "ProxyCommand=nc -x 127.0.0.1:9050 -X 5 %h %p"
               :nested-once   "ssh -o 'ProxyCommand=nc -x %h %p' r1"}
   :xf        identity
   :gen       gen-arg
   :pred      string?
   :mutations [["identity-no-quote"  identity]
               ["double-quote-only"  (fn [^String s]
                                       (if (re-find #"\s" s)
                                         (str \" s \")
                                         s))]]})

;; =============================================================================
;; Property — argv round-trips through `sh -c`
;;
;; The contract that motivates the namespace: every argv we quote into
;; a single shell-command string must come back unchanged.

(defspec join-as-cmd-roundtrips-through-sh 100
  (prop/for-all [argv gen-argv]
    (= argv (sh-roundtrip argv))))

;; =============================================================================
;; Targeted regression — the bug that motivated the empty-string branch

(deftest empty-string-survives-roundtrip
  (testing "empty argv element must not collapse during sh tokenization"
    (is (= ["" "simple"] (sh-roundtrip ["" "simple"])))))

;; =============================================================================
;; join-as-cmd — joins with single spaces, quoting only when needed

(deftest join-as-cmd-joins-quoting-only-when-needed
  (is (= "ssh -o Port=22 127.0.0.1"
         (posix/join-as-cmd ["ssh" "-o" "Port=22" "127.0.0.1"])))
  (is (= "ssh -o 'has space' 127.0.0.1"
         (posix/join-as-cmd ["ssh" "-o" "has space" "127.0.0.1"]))))
