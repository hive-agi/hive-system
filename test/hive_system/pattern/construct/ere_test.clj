(ns hive-system.pattern.construct.ere-test
  "The POSIX ERE emitter, proven against a real `grep -E`.

   ## Why this suite cannot be a unit suite

   Every other dialect is checked by compiling its output in-process. There is
   no in-process ERE engine, so an ERE claim verified on the JVM would be a
   claim about `java.util.regex` wearing ERE's name.

   ## Why the refusals matter more here than for :re2

   rg REJECTS what it cannot do — exit 2, with a message. GNU grep does not: it
   reinterprets, silently, and returns hits. So `the-refusals-are-warranted`
   below asserts something stronger and stranger than its :re2 counterpart — not
   that grep errors on a refused construct, but that grep ANSWERS A DIFFERENT
   QUESTION. That is the whole justification for gating before the fork.

   ## grep, not `grep`

   The binary is addressed as /usr/bin/grep on purpose. `grep` on a developer's
   PATH is routinely a shell function or an alias onto ugrep, which accepts
   `(?:…)` and `\\d` and would quietly turn this suite green for the wrong
   reason. A JVM ProcessBuilder does not see shell functions, but this suite
   should not depend on that being true."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing are]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [babashka.fs :as fs]
            [hive-dsl.result :as r]
            [hive-system.pattern.construct.api :as api]
            [hive-system.pattern.construct.core :as cc]
            [hive-system.pattern.construct.ere :as ere]
            [hive-system.pattern.construct.dialect :as dial]
            [hive-system.shell.core :as sh]
            [lambdaisland.regal.generator :as rgen]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(def ^:private gnu-grep
  "GNU grep by path, never by name — see the namespace docstring."
  "/usr/bin/grep")

(defn- grep-in
  "Run `grep -E PATTERN` over SUBJECTS under LOCALE.
   {:exit n :matched m :stderr s}. GNU grep's exit 2 is reserved for I/O and for
   a pattern it will not even attempt; a merely UNSUPPORTED construct exits 0 or
   1, which is exactly the hazard this dialect exists to remove."
  [locale pattern subjects]
  (let [f (fs/create-temp-file {:prefix "hs-ere-" :suffix ".txt"})]
    (try
      (spit (fs/file f) (str (str/join "\n" subjects) "\n"))
      (let [res (sh/exec! [gnu-grep "-E" "-c" "-e" pattern "--" (str f)]
                          {:env {"LC_ALL" locale} :timeout-ms 15000})]
        (if-let [ok (:ok res)]
          {:exit    (:exit ok)
           :stderr  (:stderr ok)
           :matched (or (some-> (:stdout ok) str/trim not-empty parse-long) 0)}
          {:exit :exec-failed :stderr (pr-str res) :matched 0}))
      (finally (fs/delete-if-exists f)))))

(defn- grep
  "`grep-in` under LC_ALL=C.

   The locale is PINNED rather than inherited. A bracket range is ordered by
   collation, so the ambient locale decides what half these patterns mean, and
   a suite that inherits it reports a different answer per machine — which is
   how the collation gap below was first mistaken for a flaky test."
  [pattern subjects]
  (grep-in "C" pattern subjects))

(def ^:private utf8-collation-locale
  "An installed UTF-8 locale whose collation is NOT code-point order, or nil.
   `locale -a` spells them `en_US.utf8`; `LC_ALL` accepts either spelling."
  (delay
    (let [res (sh/exec! ["locale" "-a"] {:timeout-ms 15000})
          installed (some-> res :ok :stdout str/split-lines set)]
      (first (filter installed ["en_US.utf8" "en_US.UTF-8" "en_GB.utf8"])))))

(defn- ere! [form]
  (let [res (api/->expr :posix-ere form)]
    (is (r/ok? res) (str "ERE refused " (pr-str form) ": " (pr-str res)))
    (:ok res)))

(defn- missing [form] (:missing (api/->expr :posix-ere form)))

;;; =============================================================================
;;; The tool is part of the claim
;;; =============================================================================

(deftest gnu-grep-is-installed-at-a-known-path
  (testing "a PATH `grep` may be ugrep, which speaks a superset and would hide every gap"
    (is (fs/exists? gnu-grep))
    (let [{:keys [exit]} (grep "a" ["a"])]
      (is (= 0 exit) "and it runs"))))

;;; =============================================================================
;;; The profile
;;; =============================================================================

(deftest posix-ere-provides-nothing-and-says-so
  (is (= #{} (:dialect/capabilities ere/posix-ere)))
  (is (= :posix-ere (:dialect/flavor ere/posix-ere))
      "the flavor names this emitter, not a regal flavor — regal has no ERE")
  (is (r/ok? (dial/emitter :posix-ere)) "and it is registered on load"))

(deftest an-unknown-dialect-and-an-unsupported-one-are-different-errors
  ;; Before :posix-ere existed, targeting ERE returned :dialect/unknown, which
  ;; reads as a typo rather than as a target that cannot express the construct.
  (is (= :dialect/unknown (:error (api/->expr :not-a-dialect [:+ :digit]))))
  (is (= :construct/unsupported (:error (api/->expr :posix-ere [:+ :digit])))))

;;; =============================================================================
;;; Rendering
;;; =============================================================================

(deftest renders-the-ere-subset
  (are [form expected] (= expected (ere! form))
    "abc"                              "abc"
    "a.b*c"                            "a\\.b\\*c"
    :any                               "."
    [:cat :start "x" :end]             "^x$"
    [:class [\0 \9]]                   "[0-9]"
    [:not [\a \z]]                     "[^a-z]"
    [:+ [:class [\0 \9]]]              "[0-9]+"
    [:* "ab"]                          "(ab)*"
    [:? [:alt "a" "b"]]                "(a|b)?"
    [:cat "a" [:alt "b" "c"]]          "a(b|c)"
    [:alt [:cat "x" "y"] "z"]          "xy|z"
    [:repeat [:class [\a \z]] 2 4]     "[a-z]{2,4}"
    [:repeat "ab" 3]                   "(ab){3}"
    [:repeat "ab" 3 nil]               "(ab){3,}"))

(deftest a-literal-is-matched-verbatim-by-grep
  ;; Escaping is the emitter's quietest duty and its most damaging failure: an
  ;; unescaped literal still compiles, still returns hits, and describes a
  ;; larger language than the caller wrote. Only a real grep can tell the two
  ;; apart, so every ERE metacharacter is asked about here.
  (doseq [text ["a.b*c" "1+1=2" "f(x)" "a|b" "x?" "^start" "end$" "a{2}" "[set]" "back\\slash"]]
    (let [pattern (ere! [:cat :start text :end])]
      (is (= 1 (:matched (grep pattern [text])))
          (str (pr-str text) " must match itself, anchored"))))
  (testing "and an unescaped metacharacter would have matched strictly more"
    (is (= 0 (:matched (grep (ere! [:cat :start "a.c" :end]) ["abc"])))
        "a.c is a literal dot here; if the dot were live it would match abc")
    (is (= 0 (:matched (grep (ere! [:cat :start "x*" :end]) ["xxx" ""])))
        "x* is a literal star; if the star were live it would match xxx")
    (is (= 1 (:matched (grep (ere! [:cat :start "x*" :end]) ["x*"]))))))

(deftest a-bracket-expression-uses-position-because-posix-has-no-escape-in-one
  (testing "] must lead and - must trail, or the class ends early or spells a range"
    (is (= "[]a-]" (ere! [:class \] \- \a])))
    (is (= "[^]a-]" (ere! [:not \] \- \a])))
    (testing "and GNU grep reads them as the literal characters"
      (is (= 3 (:matched (grep (ere! [:class \] \- \a]) ["]" "-" "a"])))))))

(deftest only-a-single-atom-carries-a-quantifier
  (testing "a multi-character literal must be grouped, a one-character one must not"
    (is (= "(ab)+" (ere! [:+ "ab"])))
    (is (= "a+"    (ere! [:+ "a"])))
    (is (= "[0-9]+" (ere! [:+ [:class [\0 \9]]])) "a bracket expression is already an atom"))
  (testing "and grep agrees about what got quantified"
    (is (= 1 (:matched (grep (ere! [:+ "ab"]) ["abab"]))))
    (is (= 0 (:matched (grep (ere! [:cat :start [:+ "ab"] :end]) ["abb"])))
        "abb is a+b+ territory; (ab)+ must not match it")))

;;; =============================================================================
;;; The refusals — named, and each one warranted
;;; =============================================================================

(deftest every-capability-ere-lacks-is-refused-by-name
  (are [form cap] (= [cap] (missing form))
    [:+ :digit]          :perl-class
    [:*? "x"]            :lazy
    [:lookahead "x"]     :lookaround
    [:atomic "x"]        :atomic
    [:capture "x"]       :capture
    [:cat :tab "x"]      :control-escape
    [:class [\A \a]]     :collation-range)
  (testing "a range whose ends share a class is not refused"
    (is (= "[a-z]" (ere! [:class [\a \z]])))
    (is (= "[A-Z]" (ere! [:class [\A \Z]])))
    (is (= "[0-9]" (ere! [:class [\0 \9]])))
    (is (= "[a-zA-Z0-9]" (ere! [:class [\a \z] [\A \Z] [\0 \9]])))))

(deftest the-refusals-are-warranted-and-grep-would-not-have-said-so
  ;; Each case emits the JAVA rendering of a construct :posix-ere refuses, and
  ;; shows grep answering a DIFFERENT question rather than reporting an error.
  ;; A gate is only justified where the tool itself stays silent.
  (testing "\\d is a literal d — no warning, no error, wrong answer"
    (is (= [:perl-class] (missing [:+ :digit])))
    (let [{:keys [exit matched]} (grep (:ok (api/->expr :java [:+ :digit])) ["ddd"])]
      (is (= 0 exit) "grep is perfectly happy")
      (is (= 1 matched) "and matched the letter d, which \\d does not mean")))

  (testing "a non-capturing group is not a group at all"
    (is (= [:capture] (missing [:capture "x"])))
    (let [{:keys [exit matched]} (grep "(?:a|b)c" ["abc"])]
      (is (not= 2 exit) "grep does not reject it")
      (is (= 1 matched) "it matched abc, which (?:a|b)c does not describe")))

  (testing "a lazy quantifier is silently greedy"
    (is (= [:lazy] (missing [:*? "x"])))
    (let [{:keys [exit matched]} (grep (:ok (api/->expr :java [:cat "a" [:*? "b"] "c"])) ["abbc"])]
      (is (= 0 exit))
      (is (= 1 matched) "ERE has no *?, so the ? became an optional quantifier")))

  (testing "lookahead never errors, it just never matches"
    (is (= [:lookaround] (missing [:lookahead "x"])))
    (let [{:keys [exit]} (grep (:ok (api/->expr :java [:cat [:lookahead "x"] "x"])) ["x"])]
      (is (not= 2 exit) "no error — and no match either")))

  (testing "a named control character is the letter"
    (is (= [:control-escape] (missing [:cat :tab "x"])))
    (let [{:keys [matched]} (grep "\\tx" ["tx"])]
      (is (= 1 matched) "\\t matched a literal t"))))

(deftest a-cross-class-range-fails-BOTH-ways-which-is-why-it-is-refused
  ;; POSIX orders a bracket range by the runtime locale's COLLATION, not by code
  ;; point, so one source names different sets under different locales. Both
  ;; failure modes are shown, and the SILENT one is what justifies a gate: a
  ;; loud error is something the caller could have discovered by running the tool.
  (let [subjects ["0" "9" ":" "@" "A"]
        utf8     @utf8-collation-locale]

    (testing "the gate refuses both ranges, naming the capability"
      (is (= [:collation-range] (missing [:class [\A \a]])))
      (is (= [:collation-range] (missing [:class [\0 \A]]))))

    (testing "under LC_ALL=C a range IS code-point ordered, and grep agrees with the JVM"
      (is (= 5 (:matched (grep-in "C" "[0-A]" subjects))))
      (is (= 5 (count (filter #(re-find #"[0-A]" %) subjects))))
      (is (= 0 (:exit (grep-in "C" "[A-a]" ["A" "a"]))) "and [A-a] is accepted"))

    (if-not utf8
      (println (str "\n  SKIPPED: no UTF-8 collation locale installed, so the "
                    "locale-DEPENDENCE half of :collation-range is unproven here. "
                    "`locale -a` listed none of en_US.utf8 / en_US.UTF-8 / en_GB.utf8.\n"))
      (do
        (testing "under a UTF-8 collation the same source is a HARD ERROR"
          (let [{:keys [exit stderr]} (grep-in utf8 "[A-a]" ["A" "a"])]
            (is (= 2 exit) (str utf8 " must reject [A-a]: A does not collate before a"))
            (is (str/includes? (str/lower-case (str stderr)) "invalid range"))))

        (testing "and [0-A] is worse — accepted, silent, and a different set"
          (let [{:keys [exit matched]} (grep-in utf8 "[0-A]" subjects)]
            (is (= 0 exit) "grep raises nothing at all")
            (is (not= 5 matched)
                "a silently different language, which is exactly what the
                 capability gate exists to refuse")))))

    (testing "a same-class range means the same thing under both"
      (doseq [loc (remove nil? ["C" utf8])]
        (is (= 1 (:matched (grep-in loc (ere! [:class [\A \Z]]) subjects)))
            (str "[A-Z] under " loc))))))

;;; =============================================================================
;;; Differential — what ERE emits, grep accepts and agrees with
;;; =============================================================================

(def ^:private gen-portable-range
  "A bracket range whose ends share a POSIX class, and which therefore names
   the same set under every collation. A cross-class range would demand
   `:collation-range`, which `:posix-ere` does not provide — so drawing one
   here would only prove the gate refuses it, which its own test already does."
  (gen/fmap (fn [[a b]] (if (<= (int a) (int b)) [a b] [b a]))
            (gen/bind (gen/elements [[\a \z] [\A \Z] [\0 \9]])
                      (fn [[lo hi]]
                        (let [chars (map char (range (int lo) (inc (int hi))))]
                          (gen/tuple (gen/elements chars) (gen/elements chars)))))))

(def ^:private gen-ere-construct
  "Constructs drawn from the ERE subset: no capability at all is required, so
   the gate admits every one of them by construction."
  (gen/such-that
   #(empty? (cc/required-capabilities %))
   (gen/recursive-gen
    (fn [inner]
      (gen/one-of
       [(gen/fmap #(hash-map :construct/op :cat :construct/args (vec %)) (gen/vector inner 1 3))
        (gen/fmap #(hash-map :construct/op :alt :construct/args (vec %)) (gen/vector inner 1 3))
        (gen/fmap (fn [[c op]] #:construct{:op op :args [c] :lazy? false})
                  (gen/tuple inner (gen/elements [:* :+ :?])))
        (gen/fmap (fn [[c a b]]
                    #:construct{:op :repeat :arg c :min (min a b) :max (max a b) :lazy? false})
                  (gen/tuple inner (gen/choose 0 2) (gen/choose 1 3)))]))
    (gen/one-of
     [(gen/fmap #(hash-map :construct/op :literal :construct/text %)
                (gen/not-empty (gen/fmap str/join (gen/vector gen/char-alphanumeric 1 4))))
      (gen/fmap (fn [es] #:construct{:op :class :negated? false :entries (vec es)})
                (gen/vector (gen/one-of [gen/char-alphanumeric gen-portable-range]) 1 3))]))
   100))

(defn- ere-subjects
  "Strings drawn from CONSTRUCT's own generator that a line-oriented tool can be
   asked about. The corpus above is alphanumeric-only, so nothing here narrows
   the claim — it only drops the empty string, which grep cannot be asked about."
  [construct n]
  (->> (gen/sample (rgen/gen (cc/->regal construct)) n)
       (remove str/blank?)
       distinct
       vec))

(defspec grep-accepts-every-ere-emission-and-matches-its-own-generator 30
  (prop/for-all [c gen-ere-construct]
    (let [res (api/->expr :posix-ere c)]
      (and
       (r/ok? res)
       (let [pattern  (:ok res)
             subjects (ere-subjects c 5)]
         (or (empty? subjects)
             (let [{:keys [exit matched]} (grep pattern subjects)]
               (and (not= 2 exit)
                    (= (count subjects) matched)))))))))

(deftest a-hand-checked-case-so-a-wholesale-generator-failure-cannot-pass-silently
  (let [pattern (ere! [:cat :start [:+ [:class [\0 \9]]] "-" [:+ [:class [\a \z]]] :end])]
    (is (= "^[0-9]+-[a-z]+$" pattern))
    (is (= 2 (:matched (grep pattern ["42-abc" "7-x"]))))
    (is (= 0 (:matched (grep pattern ["42-ABC" "-abc" "42-"]))))))

;;; =============================================================================
;;; ERE and Java describe the same language where both can express it
;;; =============================================================================

(defspec ere-and-java-agree-on-the-shared-subset 30
  (prop/for-all [c gen-ere-construct]
    (let [ere-pattern  (:ok (api/->expr :posix-ere c))
          java-pattern (:ok (api/->expr :java c))
          subjects     (ere-subjects c 5)]
      (or (empty? subjects)
          (let [{:keys [matched]} (grep ere-pattern subjects)
                jvm-hits (count (filter #(re-find (re-pattern java-pattern) %) subjects))]
            (= matched jvm-hits))))))
