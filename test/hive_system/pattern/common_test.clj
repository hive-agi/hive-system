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
  (doseq [[id {:keys [form replaces]}] common/catalog]
    (testing (str id)
      (is (= {:ok replaces} (api/->expr :java form))))))

(def ^:private subject
  (gen/one-of
   [(gen/fmap str/join (gen/vector (gen/elements ["0" "9" "a" "f" "g" "A" "-" " " "\t" "z"]) 0 70))
    (gen/fmap (fn [n] (apply str (repeat n "a"))) (gen/elements [8 12 16 32 40 64 65]))
    (gen/fmap (fn [[d h]] (str d "-" h))
              (gen/tuple (gen/fmap str/join (gen/vector (gen/elements ["1" "2" "x"]) 14))
                         (gen/fmap str/join (gen/vector (gen/elements ["a" "0" "g"]) 8))))]))

(defspec matches-agrees-with-the-regex-it-replaces 500
  (prop/for-all [[id {:keys [replaces]}] (gen/elements (seq common/catalog))
                 s subject]
    (= (boolean (re-find (re-pattern replaces) s))
       (common/matches? id s))))

(deftest matches-is-total
  (is (false? (common/matches? :hive.pattern/hex64 nil)))
  (is (false? (common/matches? :hive.pattern/no-such-id "abc")))
  (is (true? (common/matches? :hive.pattern/digits "20261126")))
  (is (true? (common/matches? :hive.pattern/memory-id "20261126111610-72bb520b"))))
