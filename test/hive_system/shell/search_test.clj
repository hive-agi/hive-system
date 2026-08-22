(ns hive-system.shell.search-test
  "The argv builder, proven against the programs whose parsers it is a claim about.

   An argv is not a value the JVM can validate. `[\"sd\" \"-\\\\d+\" \"X\" f]` is a
   perfectly good vector of strings and a broken command line, and only sd can
   say so. So the shape tests below are paired with runs of the real binaries,
   and each run is written to FAIL if the rule under test is removed — the
   negative control is part of the claim, not decoration.

   `rg`, `sd` and `grep` are driven for real. `fd` is not installed on the
   machine where this landed; its argv is asserted from sd's measured shape and
   its E2E is skipped LOUDLY, never silently."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing are use-fixtures]]
            [babashka.fs :as fs]
            [hive-dsl.result :as r]
            [hive-system.pattern.construct.api :as api]
            [hive-system.pattern.construct.dialect :as dial]
            [hive-system.shell.core :as sh]
            [hive-system.shell.search :as search]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

;;; =============================================================================
;;; Fixtures and helpers
;;; =============================================================================

(defn- restore-registry
  "The tool registry is process-wide; a test that registers must put it back."
  [f]
  (let [before (search/registered)]
    (try (f)
         (finally
           (doseq [id (keys (search/registered))] (search/unregister! id))
           (doseq [t (vals before)] (search/register! t))))))

(use-fixtures :each restore-registry)

(defn- argv! [tool-id form opts]
  (let [res (search/argv tool-id form opts)]
    (is (r/ok? res) (str "argv refused: " (pr-str res)))
    (:ok res)))

(defn- run
  "Run ARGV. {:exit n :out s :err s}. exit 2 is the tool rejecting the command
   line or the pattern; 0 and 1 are match and no-match."
  [argv]
  (let [res (sh/exec! argv {:timeout-ms 15000})]
    (if-let [ok (:ok res)]
      {:exit (:exit ok) :out (str/trim (str (:stdout ok))) :err (str (:stderr ok))}
      {:exit :exec-failed :out "" :err (pr-str res)})))

(defn- with-file
  "Call F with the path of a temp file holding CONTENT, then delete it."
  [content f]
  (let [p (fs/create-temp-file {:prefix "hs-search-" :suffix ".txt"})]
    (try (spit (fs/file p) content)
         (f (str p))
         (finally (fs/delete-if-exists p)))))

(def ^:private rg-quiet
  "Flags that keep an rg answer independent of the invoking user's config and
   of any .gitignore above the temp dir."
  ["--no-config" "--no-ignore" "--text" "--no-filename"])

;;; =============================================================================
;;; The tools are part of the claim
;;; =============================================================================

(deftest ripgrep-and-sd-are-installed
  (testing "without the real binaries the argv claims are untested, and green would be a lie"
    (is (r/ok? (sh/which "rg")) "install ripgrep")
    (is (r/ok? (sh/which "sd")) "install sd")))

;;; =============================================================================
;;; The registry
;;; =============================================================================

(deftest the-built-in-profiles-are-registered-on-load
  (is (= #{:rg :sd :fd :grep} (set (keys (search/registered)))))
  (doseq [[id t] (search/registered)]
    (is (= id (:tool/id t)) "a profile is keyed by its own id"))
  (testing "and each names a dialect that is actually registered"
    (doseq [[id t] (search/registered)]
      (is (r/ok? (dial/emitter (:tool/dialect t)))
          (str id " claims " (:tool/dialect t))))))

(deftest an-unregistered-tool-is-refused-and-says-what-it-knows
  (let [res (search/tool :ugrep)]
    (is (r/err? res))
    (is (= :search/unknown-tool (:error res)))
    (is (= [:fd :grep :rg :sd] (:known res))
        "the refusal names the alternatives rather than leaving the caller to guess")))

(deftest an-invalid-profile-is-refused-not-stored
  (let [res (search/register! #:tool{:id :bogus :bin "bogus" :dialect :re2})]
    (is (r/err? res))
    (is (= :search/invalid-tool (:error res)))
    (is (nil? (get (search/registered) :bogus))
        "a profile that failed the schema must not be reachable")))

(deftest an-unknown-tool-is-refused-before-the-form-is-even-read
  ;; Ordering matters: resolving the tool first is what lets `argv` report
  ;; :search/unknown-tool instead of a confusing normalization error about a
  ;; form it was never going to emit.
  (let [res (search/argv :ugrep [:definitely-not-an-op "x"] {})]
    (is (= :search/unknown-tool (:error res)))))

;;; =============================================================================
;;; argv — the shape
;;; =============================================================================

(deftest argv-places-the-pattern-where-each-tool-reads-one
  (are [tool-id form opts expected] (= expected (argv! tool-id form opts))
    ;; flag-introduced pattern: `--` is left to guard the operands
    :rg [:cat [:+ :digit] "-"] {:operands ["src"]}
    ["rg" "--regexp" "\\d+-" "--" "src"]

    ;; ... and is not emitted when there are no operands to guard
    :rg [:+ :digit] {}
    ["rg" "--regexp" "\\d+"]

    ;; caller flags precede the pattern
    :rg [:+ :digit] {:flags ["--count"] :operands ["src"]}
    ["rg" "--count" "--regexp" "\\d+" "--" "src"]

    ;; positional pattern: `--` must come BEFORE it, and then covers everything
    :sd [:+ :digit] {:operands ["N" "f.txt"]}
    ["sd" "--" "\\d+" "N" "f.txt"]

    :fd [:cat "core" [:? ".clj"]] {:operands ["src"]}
    ["fd" "--" "core(?:\\.clj)?" "src"]

    ;; dialect-flags come first: grep reads BRE until -E says otherwise
    :grep [:+ [:class [\0 \9]]] {:operands ["src"]}
    ["grep" "-E" "-e" "[0-9]+" "--" "src"]

    :grep [:+ [:class [\0 \9]]] {:flags ["-c"] :operands ["src"]}
    ["grep" "-E" "-c" "-e" "[0-9]+" "--" "src"]))

(deftest argv-emits-exactly-what-the-dialect-emits
  ;; argv must not re-render, re-escape or decorate the expression: the pattern
  ;; in the argv is the dialect's own output, or the differential suite proves
  ;; nothing about what actually reaches the tool.
  (doseq [form [[:+ :digit] [:cat "a" [:alt "b" "c"]] [:*? "x"] [:cat :start "z" :end]]]
    (let [expr (:ok (api/->expr :re2 form))]
      (is (some #{expr} (argv! :rg form {}))
          (str "rg argv must carry the :re2 emission of " (pr-str form)))
      (is (some #{expr} (argv! :sd form {:operands ["N"]}))))))

;;; =============================================================================
;;; The refusal happens before the fork
;;; =============================================================================

(deftest a-construct-re2-cannot-express-never-becomes-an-argv
  (doseq [[form missing] [[[:lookahead "x"] [:lookaround]]
                          [[:negative-lookbehind "x"] [:lookaround]]
                          [[:atomic "x"] [:atomic]]]]
    (let [res (search/argv :rg form {:operands ["src"]})]
      (is (r/err? res))
      (is (= :construct/unsupported (:error res)))
      (is (= missing (:missing res))
          "the refusal names the capability, so the caller need not parse stderr")
      (is (= :re2 (:dialect res))))))

(deftest runnable?-answers-from-the-shape-alone
  (is (= true  (:ok (search/runnable? :rg [:+ :digit]))))
  (is (= false (:ok (search/runnable? :rg [:lookahead "x"]))))
  (testing "and it separates the TOOLS, not just the constructs"
    (is (= false (:ok (search/runnable? :grep [:+ :digit])))
        "grep speaks ERE, which has no \\d")
    (is (= true  (:ok (search/runnable? :grep [:+ [:class [\0 \9]]])))
        "spelled as a bracket range it runs everywhere"))
  (is (r/err? (search/runnable? :ugrep [:+ :digit]))
      "an unknown tool is an error, not an unrunnable one"))

(deftest explain-partitions-the-registry
  (testing "nothing runs a lookahead"
    (let [{:keys [runnable blocked requires]} (:ok (search/explain [:lookahead "x"]))]
      (is (= #{:lookaround} requires))
      (is (empty? runnable))
      (is (= {:fd [:lookaround] :grep [:lookaround]
              :rg [:lookaround] :sd [:lookaround]}
             (into {} blocked)))))

  (testing "a perl class splits the registry — which is the answer a caller wants"
    (let [{:keys [runnable blocked]} (:ok (search/explain [:+ :digit]))]
      (is (= #{:fd :rg :sd} (set runnable)))
      (is (= {:grep [:perl-class]} (into {} blocked))
          "and it names WHY grep is out, so the caller can respell it")))

  (testing "respelled as a bracket range, every tool can run it"
    (let [{:keys [runnable blocked]} (:ok (search/explain [:+ [:class [\0 \9]]]))]
      (is (= #{:fd :grep :rg :sd} (set runnable)))
      (is (empty? blocked))))

  (testing "runnable and blocked partition the registry for any construct"
    (doseq [form [[:+ :digit] [:lookahead "x"] [:atomic "y"] [:*? "z"]
                  [:capture "c"] [:class [\A \a]]]]
      (let [{:keys [runnable blocked]} (:ok (search/explain form))]
        (is (= (set (keys (search/registered)))
               (into (set runnable) (keys blocked))))
        (is (empty? (into #{} (filter (set runnable)) (keys blocked))))))))

(deftest explain-reads-the-registry-rather-than-a-hardcoded-list
  ;; The whole point of tools-as-data: a tool registered against a dialect that
  ;; DOES have lookaround must show up as runnable, with no edit to `explain`.
  (search/register! #:tool{:id :jvm-tool :bin "jvm-tool" :dialect :java
                           :flag "--regexp" :separator "--"})
  (let [{:keys [runnable blocked]} (:ok (search/explain [:lookahead "x"]))]
    (is (contains? (set runnable) :jvm-tool))
    (is (not (contains? blocked :jvm-tool))))
  (testing "and unregistering it removes it again"
    (search/unregister! :jvm-tool)
    (is (not (contains? (set (:runnable (:ok (search/explain [:lookahead "x"])))) :jvm-tool)))))

(deftest a-tool-whose-dialect-is-unregistered-is-refused-not-guessed
  (let [restore (dial/unregister-emitter! :re2)]
    (try
      (let [res (search/argv :rg [:+ :digit] {})]
        (is (r/err? res))
        (is (= :dialect/unknown (:error res))))
      (finally (dial/register-emitter! restore)))))

;;; =============================================================================
;;; E2E — the argv actually runs, and the rules in it are load-bearing
;;; =============================================================================

(deftest the-rg-argv-runs-and-finds-what-the-construct-describes
  (with-file "42-abc\nnope\n7-x\n"
    (fn [path]
      (let [{:keys [exit out]} (run (argv! :rg [:cat [:+ :digit] "-" [:+ :word]]
                                           {:flags rg-quiet :operands [path]}))]
        (is (= 0 exit) "rg parsed the pattern and matched")
        (is (= ["42-abc" "7-x"] (str/split-lines out))))
      (let [{:keys [exit]} (run (argv! :rg [:cat "zzz" [:+ :digit]]
                                       {:flags rg-quiet :operands [path]}))]
        (is (= 1 exit) "and reports no-match rather than a parse error")))))

(deftest the-rg-pattern-flag-is-load-bearing
  ;; Negative control: strip `--regexp` from the argv the builder produced and
  ;; the same command dies. If this ever passes, the flag has stopped mattering
  ;; and the profile is carrying a field for nothing.
  (with-file "-7\n"
    (fn [path]
      (let [built  (argv! :rg [:cat "-" [:+ :digit]] {:flags rg-quiet :operands [path]})
            without (vec (remove #{"--regexp"} built))]
        (is (= 0 (:exit (run built)))
            "the built argv matches a pattern that begins with a dash")
        (let [{:keys [exit err]} (run without)]
          (is (= 2 exit) "without --regexp rg reads the pattern as a flag")
          (is (str/includes? err "unrecognized flag")))))))

(deftest the-sd-argv-runs-and-rewrites-the-file
  (with-file "id-42 and id-7\n"
    (fn [path]
      (let [{:keys [exit err]} (run (argv! :sd [:cat "id-" [:+ :digit]]
                                           {:operands ["REDACTED" path]}))]
        (is (= 0 exit) err)
        (is (= "REDACTED and REDACTED\n" (slurp path)))))))

(deftest the-sd-separator-must-precede-the-pattern
  ;; Negative control, and the reason this profile differs from rg's. sd takes
  ;; the pattern and the replacement as positionals, so a `--` placed after the
  ;; pattern — where rg's belongs — protects neither. Measured on sd 1.0.0.
  (with-file "-42\n"
    (fn [path]
      (let [built (argv! :sd [:cat "-" [:+ :digit]] {:operands ["-X" path]})]
        (is (= ["sd" "--" "-\\d+" "-X" path] built))
        (is (= 0 (:exit (run built))))
        (is (= "-X\n" (slurp path))
            "both the leading-dash pattern and the leading-dash replacement survived"))))
  (with-file "-42\n"
    (fn [path]
      (let [moved ["sd" "-\\d+" "--" "-X" path]
            {:keys [exit err]} (run moved)]
        (is (= 2 exit) "a separator placed after the pattern leaves the pattern exposed")
        (is (str/includes? err "unexpected argument"))
        (is (= "-42\n" (slurp path)) "and the file is untouched")))))

(deftest the-grep-argv-runs-and-the-dialect-flag-is-load-bearing
  (with-file "42-abc\nnope\n"
    (fn [path]
      (testing "the built argv finds what the construct describes"
        (let [{:keys [exit out]} (run (argv! :grep [:cat [:+ [:class [\0 \9]]] "-"]
                                             {:operands [path]}))]
          (is (= 0 exit))
          (is (= "42-abc" out))))

      (testing "-E is load-bearing: without it grep reads BRE, where + is a literal"
        ;; Negative control. In BRE `[0-9]+-` means a digit followed by a
        ;; literal `+`, so the same pattern quietly stops matching -- grep does
        ;; not report anything, it just answers a different question.
        (let [built   (argv! :grep [:cat [:+ [:class [\0 \9]]] "-"] {:operands [path]})
              without (vec (remove #{"-E"} built))
              {:keys [exit]} (run without)]
          (is (= 1 exit) "BRE finds nothing, and says so only by exit code")))

      (testing "a construct ERE cannot express never reaches grep"
        (let [res (search/argv :grep [:+ :digit] {:operands [path]})]
          (is (r/err? res))
          (is (= :construct/unsupported (:error res)))
          (is (= [:perl-class] (:missing res))
              "and this is the case grep would have answered WRONGLY, not loudly"))))))

(deftest a-refused-construct-is-one-rg-genuinely-rejects
  ;; The gate must not be merely cautious: what it refuses, rg must also refuse.
  (with-file "x\n"
    (fn [path]
      (is (r/err? (search/argv :rg [:lookahead "x"] {:operands [path]})))
      (let [java-expr (:ok (api/->expr :java [:lookahead "x"]))
            {:keys [exit err]} (run (into ["rg"] (concat rg-quiet ["--regexp" java-expr "--" path])))]
        (is (= 2 exit) "rg must reject it, or :re2 is refusing more than the tool does")
        (is (str/includes? (str/lower-case err) "look-around"))))))

;;; =============================================================================
;;; fd — asserted, not observed
;;; =============================================================================

(deftest the-fd-argv-is-run-when-fd-exists-and-the-gap-is-announced-when-it-does-not
  (if (r/err? (sh/which "fd"))
    (println (str "\n  SKIPPED: fd is not installed. "
                  "hive-system.shell.search/fd is the one profile whose argv is "
                  "asserted from sd's measured shape rather than observed. "
                  "Tracked as [PATTERN-FD-ARGV].\n"))
    (let [dir (fs/create-temp-dir {:prefix "hs-search-fd-"})]
      (try
        (spit (fs/file (fs/path dir "core-42.clj")) "")
        (spit (fs/file (fs/path dir "other.txt")) "")
        (let [{:keys [exit out]} (run (argv! :fd [:cat "core" [:+ [:class [\- \-] [\0 \9]]]]
                                             {:flags ["--no-ignore"] :operands [(str dir)]}))]
          (is (= 0 exit))
          (is (str/includes? out "core-42.clj"))
          (is (not (str/includes? out "other.txt"))))
        (finally (fs/delete-tree dir))))))
