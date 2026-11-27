(ns hive-system.pattern.common-test
  "The catalog pinned two ways: each construct compiles to exactly the Java
   source its `:replaces` names (golden), and `matches?` agrees with that
   regex on generated strings (differential)."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [hive-system.pattern.common :as common]
            [hive-system.pattern.construct.api :as api]))

(deftest every-entry-registers
  (is (common/catalog-registered?))
  (doseq [[id result] (common/register-all!)]
    (is (contains? result :ok) (str id " " (pr-str result)))))

(deftest every-construct-is-the-literal-it-replaces
  (doseq [[id {:keys [form replaces replaces-find]}] common/catalog]
    (testing (str id)
      ;; an entry with only an unanchored form (a `-anywhere` sibling) compiles
      ;; to :replaces-find; the rest to the anchored :replaces
      (is (= {:ok (or replaces replaces-find)} (api/->expr :java form))))))

(def ^:private subject
  (gen/one-of
   [(gen/fmap str/join (gen/vector (gen/elements ["0" "9" "a" "f" "g" "A" "-" " " "\t" "z"]) 0 70))
    (gen/fmap (fn [n] (apply str (repeat n "a"))) (gen/elements [8 12 16 32 40 64 65]))
    (gen/fmap (fn [[d h]] (str d "-" h))
              (gen/tuple (gen/fmap str/join (gen/vector (gen/elements ["1" "2" "x"]) 14))
                         (gen/fmap str/join (gen/vector (gen/elements ["a" "0" "g"]) 8))))]))

(defspec matches-agrees-with-the-regex-it-replaces 500
  (prop/for-all [[id {:keys [replaces replaces-find]}] (gen/elements (seq common/catalog))
                 s subject]
    (= (boolean (re-find (re-pattern (or replaces replaces-find)) s))
       (common/matches? id s))))

(deftest matches-is-total
  (is (false? (common/matches? :hive.pattern/hex64 nil)))
  (is (false? (common/matches? :hive.pattern/no-such-id "abc")))
  (is (true? (common/matches? :hive.pattern/digits "20261126")))
  (is (true? (common/matches? :hive.pattern/memory-id "20261126111610-72bb520b"))))

(deftest every-catalog-entry-satisfies-its-schema
  (doseq [[id entry] common/catalog]
    (is (common/catalog-entry-valid? entry) (str id " " (pr-str entry)))))

(deftest mode-find-refuses-an-entry-with-no-unanchored-source
  (testing "a missing :replaces-find is refused, never silently anchored"
    (is (= {:error :pattern/no-find-variant :id :hive.pattern/hex64}
           (common/matches? :hive.pattern/hex64 (apply str (repeat 64 "a")) {:mode :find}))))
  (testing "an unknown id under opts is refused"
    (is (= :pattern/unknown (:error (common/matches? :hive.pattern/no-such-id "x" {:mode :find})))))
  (testing "a non-string subject is a false under opts, not an error"
    (is (= {:ok false} (common/matches? :hive.pattern/digits nil {:mode :find})))))

(deftest mode-find-agrees-with-the-unanchored-regex-it-replaces
  (let [entries (filter (fn [[_ e]] (:replaces-find e)) common/catalog)]
    (if (empty? entries)
      (is true "no entry declares :replaces-find yet: the differential is vacuous")
      (doseq [s (gen/sample subject 200)
              [id {:keys [replaces-find]}] entries]
        (is (= (boolean (re-find (re-pattern replaces-find) s))
               (true? (:ok (common/matches? id s {:mode :find}))))
            (str id " " (pr-str s)))))))

(deftest flags-pass-through-and-an-unsupported-flag-refuses
  (testing "a :flags option reaches the engine: a lower-case slug accepts upper case under :case-insensitive"
    (is (false? (common/matches? :hive.pattern/slug "ABC")))
    (is (= {:ok true} (common/matches? :hive.pattern/slug "ABC" {:flags #{:case-insensitive}}))))
  (testing "an unsupported flag is a refusal, never dropped"
    (is (= :pattern/unsupported-flag
           (:error (common/matches? :hive.pattern/slug "abc" {:flags #{:nonsense}}))))))

(deftest ws-run-aliases-are-exactly-the-semantically-equal-sources
  (let [entry (get common/catalog :hive.pattern/ws-run)]
    (testing "only the two EQUAL spellings are aliases"
      (is (= ["\\s+" "[\\s]+"] (:aliases entry))))
    (testing "a one-char `\\s` and a newline-less `[ \t]+` are NOT aliases"
      (is (not (contains? (set (:aliases entry)) "\\s")))
      (is (not (contains? (set (:aliases entry)) "[ \\t]+"))))))

(deftest ws-run-aliases-are-differentially-equal-to-replaces
  (let [replaces (:replaces (get common/catalog :hive.pattern/ws-run))
        aliases  (:aliases (get common/catalog :hive.pattern/ws-run))]
    (doseq [alias aliases
            s (gen/sample subject 200)]
      (is (= (re-seq (re-pattern replaces) s)
             (re-seq (re-pattern alias) s))
          (str alias " " (pr-str s))))))

(deftest ws-run-non-aliases-are-shown-not-equal
  (let [replaces (:replaces (get common/catalog :hive.pattern/ws-run))]
    (testing "`\\s` is one char: a run of two spaces splits differently"
      (is (not= (re-seq (re-pattern "\\s") "a  b")
                (re-seq (re-pattern replaces) "a  b"))))
    (testing "`[ \\t]+` has no newline: a newline run is not a whitespace run to it"
      (is (not= (re-seq (re-pattern "[ \\t]+") "a\nb")
                (re-seq (re-pattern replaces) "a\nb"))))))

(deftest digits-anywhere-is-unanchored
  (testing "the unanchored sibling matches digits embedded in text"
    (is (true? (common/matches? :hive.pattern/digits-anywhere "a12")))
    (is (true? (:ok (common/matches? :hive.pattern/digits-anywhere "a12" {:mode :find})))))
  (testing "and rejects a subject with no digit"
    (is (false? (common/matches? :hive.pattern/digits-anywhere "abc")))
    (is (false? (:ok (common/matches? :hive.pattern/digits-anywhere "abc" {:mode :find})))))
  (testing "the anchored :hive.pattern/digits still refuses embedded digits"
    (is (false? (common/matches? :hive.pattern/digits "a12")))))
