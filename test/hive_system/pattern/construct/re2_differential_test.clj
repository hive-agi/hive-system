(ns hive-system.pattern.construct.re2-differential-test
  "The :re2 dialect, proven against a real `rg` process.

   Every other construct suite asks regal whether it rendered something. That
   is one rung of evidence, and it is the wrong rung for this dialect: :re2
   exists to describe what ripgrep and sd actually accept, and regal renders it
   with the :ecma flavor because regal has no RE2 flavor at all. Nothing had
   ever fed a :re2 emission to rg.

   Two directions, and both matter:

     ACCEPTANCE + AGREEMENT — a pattern the dialect emits must be accepted by
     rg (exit 2 is a parse error, not a miss), and must match the strings drawn
     from that construct's OWN generator. This is the generator-as-oracle
     property, re-asked of the real tool.

     REFUSAL IS WARRANTED — a construct the dialect refuses must be one rg
     genuinely rejects. A gate that refuses more than the tool does is not
     safe, it is just wrong in the other direction, and no unit test can tell
     the two apart.

   `rg` is a hard requirement here, deliberately. Skipping when it is absent
   would turn `the :re2 dialect is proven` into a claim the suite reports as
   green without having checked."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [babashka.fs :as fs]
            [hive-dsl.result :as r]
            [hive-system.pattern.construct.api :as api]
            [hive-system.pattern.construct.core :as cc]
            [hive-system.pattern.construct.test-gen :as tg]
            [hive-system.shell.core :as sh]
            [lambdaisland.regal.generator :as rgen]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

;;; =============================================================================
;;; Driving a real rg
;;; =============================================================================

(defn- rg
  "Run rg with PATTERN over SUBJECTS, one per line. Returns
   {:exit n :matched m :stderr s}. exit 2 is rg REJECTING the pattern; 0 and 1
   are match and no-match.

   --no-config and --no-ignore keep the answer independent of the invoking
   user's ripgrep config and of any .gitignore above the temp dir; --regexp
   keeps a pattern that starts with `-` from being read as a flag."
  [pattern subjects]
  (let [f (fs/create-temp-file {:prefix "hs-re2-diff-" :suffix ".txt"})]
    (try
      (spit (fs/file f) (str (str/join "\n" subjects) "\n"))
      (let [res (sh/exec! ["rg" "--no-config" "--no-ignore" "--text"
                           "--no-filename" "--count" "--regexp" pattern
                           "--" (str f)]
                          {:timeout-ms 15000})]
        (if-let [ok (:ok res)]
          {:exit    (:exit ok)
           :stderr  (:stderr ok)
           :matched (or (some-> (:stdout ok) str/trim not-empty parse-long) 0)}
          {:exit :exec-failed :stderr (pr-str res) :matched 0}))
      (finally (fs/delete-if-exists f)))))

(defn- line-subjects
  "Strings drawn from CONSTRUCT's own generator that a line-oriented tool can
   actually be asked about: no embedded newline, not blank, and ASCII only.

   The ASCII restriction is NOT incidental tidying — it is the exact width of
   the known divergence pinned below. Java's \\w is [a-zA-Z0-9_]; RE2's is
   Unicode-aware. Above U+007F the two engines disagree about what the perl
   classes mean, so a non-ASCII subject would fail this property for a reason
   that has nothing to do with emission being wrong."
  [construct n]
  (->> (gen/sample (rgen/gen (cc/->regal construct)) n)
       (remove #(or (str/blank? %)
                    (re-find #"[\r\n]" %)
                    (some (fn [ch] (> (int ch) 127)) %)))
       distinct
       vec))

;;; =============================================================================
;;; The tool is part of the claim
;;; =============================================================================

(deftest ripgrep-is-installed
  (testing "without a real rg there is no differential, and green would be a lie"
    (is (r/ok? (sh/which "rg"))
        "install ripgrep — the :re2 dialect's whole claim is about rg specifically")))

;;; =============================================================================
;;; Direction 1 — what :re2 emits, rg accepts and agrees with
;;; =============================================================================

(defspec rg-accepts-every-re2-emission-and-matches-its-own-generator 40
  (prop/for-all [c tg/gen-construct]
    (let [res (api/->expr :re2 c)]
      (and
       ;; the generator emits no lookaround or atomic, so :re2 must never refuse
       (r/ok? res)
       (let [pattern  (:ok res)
             subjects (line-subjects c 6)]
         (if (empty? subjects)
           true
           (let [{:keys [exit matched]} (rg pattern subjects)]
             (and (not= 2 exit)                    ; rg parsed it
                  (= (count subjects) matched)))))))))  ; and agreed with the oracle

(deftest a-known-re2-pattern-round-trips-through-rg
  (testing "a hand-checked case, so a wholesale generator failure cannot pass silently"
    (let [c       (:ok (cc/normalize [:cat [:+ :digit] "-" [:+ :word]]))
          pattern (:ok (api/->expr :re2 c))
          {:keys [exit matched]} (rg pattern ["42-abc" "7-x"])]
      (is (= 0 exit))
      (is (= 2 matched))
      (is (= 0 (:matched (rg pattern ["no-digits-here"])))
          "and it does not match what it should not"))))

;;; =============================================================================
;;; Direction 2 — what :re2 refuses, rg genuinely cannot do
;;; =============================================================================

(deftest the-re2-refusal-is-warranted-not-merely-cautious
  (let [c (:ok (cc/normalize [:lookahead "x"]))]
    (testing "the dialect refuses lookaround and names it"
      (let [res (api/->expr :re2 c)]
        (is (r/err? res))
        (is (= :construct/unsupported (:error res)))
        (is (= [:lookaround] (:missing res)))))
    (testing "and rg really does reject the pattern java emits for the same construct"
      ;; If rg accepted this, the gate would be refusing more than the tool
      ;; does — safe-looking, and wrong.
      (let [java-pattern (:ok (api/->expr :java c))
            {:keys [exit stderr]} (rg java-pattern ["x"])]
        (is (= 2 exit) "rg must reject it, or the capability is mis-declared")
        (is (str/includes? (str/lower-case (str stderr)) "look-around"))))))

(deftest the-re2-refusal-is-warranted-for-atomic-groups-too
  (let [c (:ok (cc/normalize [:atomic "x"]))]
    (is (= [:atomic] (:missing (api/->expr :re2 c))))
    (let [java-pattern (:ok (api/->expr :java c))
          {:keys [exit]} (rg java-pattern ["x"])]
      (is (= 2 exit) "rg has no atomic groups either"))))

;;; =============================================================================
;;; A divergence the capability gate does NOT currently catch
;;; =============================================================================

(deftest re2-and-java-disagree-about-perl-classes-above-ascii
  ;; Found by this suite on its first run, shrunk to [:cat :non-word].
  ;;
  ;; Both dialects declare :perl-class and both emit the identical source "\W".
  ;; The SOURCE agrees; the LANGUAGE does not. Java's \w is [a-zA-Z0-9_], so \W
  ;; matches "é"; RE2's \w is Unicode-aware, so "é" IS a word character and \W
  ;; does not match it.
  ;;
  ;; That is the failure mode the dialect docstring names -- "a DIFFERENT
  ;; LANGUAGE that still compiles and still returns hits" -- reached by a route
  ;; the capability gate cannot see, because nothing was dropped. The gate
  ;; compares feature AVAILABILITY; this is a difference in feature MEANING.
  ;;
  ;; Pinned rather than fixed: making :re2 agree means rendering perl-class
  ;; tokens as (?-u:\W) or [^0-9A-Za-z_] for that dialect only, which is a
  ;; per-token emitter change, and choosing whether a Construct denotes Java's
  ;; language or the target's is a design decision, not a patch. Tracked
  ;; separately. This test fails the day someone changes it, which is the point.
  (let [c            (:ok (cc/normalize [:cat :non-word]))
        re2-pattern  (:ok (api/->expr :re2 c))
        java-pattern (:ok (api/->expr :java c))]
    (testing "the two dialects emit the same source, so no gate fires"
      (is (= re2-pattern java-pattern))
      (is (empty? (:missing (api/->expr :re2 c)))))
    (testing "the JVM treats a non-ASCII letter as a NON-word character"
      (is (re-find (re-pattern java-pattern) "é")))
    (testing "rg does not -- same pattern, different language"
      (is (= 0 (:matched (rg re2-pattern ["é"])))
          "if this starts matching, :re2 was fixed and this test should go"))
    (testing "and they agree again once the subject is ASCII"
      (is (re-find (re-pattern java-pattern) "&"))
      (is (= 1 (:matched (rg re2-pattern ["&"])))))
    (testing "the ASCII-forced spelling is what agreement would require"
      (is (= 1 (:matched (rg (str "(?-u:" re2-pattern ")") ["é"])))
          "rg accepts (?-u:...) and it restores the JVM's semantics"))))
