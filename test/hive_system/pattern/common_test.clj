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
   [(gen/fmap str/join (gen/vector (gen/elements ["0" "9" "a" "f" "g" "A" "-" " " "\t" "\n" "\u000B" "\f" "\r" "z" "!"]) 0 70))
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
  (testing "a flag outside the Flag enum is caught at opts validation, never dropped"
    (is (= :pattern/bad-opts
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

(deftest anywhere-siblings-match-an-id-embedded-in-text
  (let [h64 (apply str (repeat 64 "a"))
        h40 (apply str (repeat 40 "a"))
        h32 (apply str (repeat 32 "a"))
        uuid "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"]
    (testing "a valid id surrounded by text is found under :mode :find"
      (doseq [[id body] [[:hive.pattern/hex64-anywhere (str "blob " h64 " done")]
                         [:hive.pattern/hex40-anywhere (str "commit=" h40 ";")]
                         [:hive.pattern/hex32-anywhere (str "(" h32 ")")]
                         [:hive.pattern/uuid-anywhere (str "id: " uuid " .")]]]
        (is (true? (:ok (common/matches? id body {:mode :find}))) (str id " " body))))
    (testing "and the anchored parent still refuses the embedded form"
      (is (false? (common/matches? :hive.pattern/hex64 (str "blob " h64 " done"))))
      (is (false? (common/matches? :hive.pattern/uuid (str "id: " uuid " .")))))))

(deftest anywhere-siblings-reject-a-one-char-short-near-miss
  (let [short64 (apply str (repeat 63 "a"))
        short40 (apply str (repeat 39 "a"))
        short32 (apply str (repeat 31 "a"))]
    (doseq [[id body] [[:hive.pattern/hex64-anywhere (str "x" short64 "y")]
                       [:hive.pattern/hex40-anywhere (str "x" short40 "y")]
                       [:hive.pattern/hex32-anywhere (str "x" short32 "y")]]]
      (is (false? (:ok (common/matches? id body {:mode :find}))) (str id " " body)))))

(deftest uuid-anywhere-is-case-tolerant-but-uuid-is-not
  (let [lower "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
        upper (str/upper-case lower)]
    (testing "uuid-anywhere carries :flags #{:case-insensitive}"
      (is (= #{:case-insensitive} (:flags (get common/catalog :hive.pattern/uuid-anywhere)))))
    (testing "uuid-anywhere accepts either case, embedded"
      (is (true? (:ok (common/matches? :hive.pattern/uuid-anywhere (str "id " upper " x") {:mode :find})))))
    (testing "the strict :hive.pattern/uuid still REFUSES upper case"
      (is (false? (common/matches? :hive.pattern/uuid upper)))
      (is (true? (common/matches? :hive.pattern/uuid lower))))))

(deftest sha256-prefixed-is-anchored-and-needs-its-prefix
  (let [digest (apply str (repeat 64 "a"))]
    (testing "the prefixed form is whole-string: a bare digest is refused"
      (is (true? (common/matches? :hive.pattern/sha256-prefixed (str "sha256:" digest))))
      (is (false? (common/matches? :hive.pattern/sha256-prefixed digest))))
    (testing "a one-char-short digest is refused"
      (is (false? (common/matches? :hive.pattern/sha256-prefixed (str "sha256:" (apply str (repeat 63 "a")))))))
    (testing "it declares no unanchored variant"
      (is (= :pattern/no-find-variant
             (:error (common/matches? :hive.pattern/sha256-prefixed digest {:mode :find})))))))

(deftest bad-opts-stays-on-the-result-railway
  (testing "a :flags that is not a set of Flags is REFUSED, never thrown"
    (is (= :pattern/bad-opts
           (:error (common/matches? :hive.pattern/slug "abc" {:flags :case-insensitive}))))
    (is (= :pattern/bad-opts
           (:error (common/matches? :hive.pattern/slug "abc" {:flags 1})))))
  (testing "an unknown :mode is REFUSED, never a silent fall-back to the anchored source"
    (is (= :pattern/bad-opts
           (:error (common/matches? :hive.pattern/digits-anywhere "a12" {:mode :bogus})))))
  (testing "the refusal carries the malformed opts and the malli explanation"
    (let [result (common/matches? :hive.pattern/slug "abc" {:flags 1})]
      (is (= {:flags 1} (:opts result)))
      (is (= [:flags] (-> result :explain :errors first :path)))))
  (testing "nil and {} still mean the default"
    (is (= {:ok true} (common/matches? :hive.pattern/digits "2026" nil)))
    (is (= {:ok true} (common/matches? :hive.pattern/digits "2026" {})))))

(deftest ws-run-golden-the-vertical-tab-and-friends-are-a-whitespace-run
  (let [entry    (get common/catalog :hive.pattern/ws-run)
        replaces (:replaces entry)
        sources  (into [replaces] (:aliases entry))]
    (testing "every ASCII whitespace code point is a WHOLE run under :replaces and both aliases"
      (doseq [ch ["\u000B" "\n" "\f" "\r" " " "\t"]
              src sources]
        (is (true? (boolean (re-matches (re-pattern src) ch)))
            (str (pr-str ch) " against " (pr-str src)))))
    (testing "and the catalog agrees: matches? finds a vertical tab"
      (is (true? (common/matches? :hive.pattern/ws-run "\u000B"))))
    (testing "a non-whitespace char is not a run under any equal source"
      (doseq [src sources]
        (is (false? (boolean (re-matches (re-pattern src) "!")))
            (str "! against " (pr-str src)))))))
