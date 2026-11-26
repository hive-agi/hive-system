(ns hive-system.text-test
  "Each `hive-system.text` function proven DIFFERENTIALLY against the regex it
   replaces: the oracle is built at test time from `Pattern/quote`d literals,
   and both sides judge the same generated strings. Alphabets are chosen so
   matches are frequent and every edge (ASCII vs non-ASCII case, line breaks,
   non-ASCII spaces) is reachable. Anchored-end oracles use subjects with no
   line terminator: that is the one documented difference."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [hive-system.text :as text]
            [hive-test.mutation :as mut])
  (:import (java.util.regex Pattern)))

(defn- q [s] (Pattern/quote s))
(defn- alt [xs] (str "(?:" (str/join "|" (map q xs)) ")"))
(defn- found? [re s] (boolean (re-find (re-pattern re) s)))

(defn- gen-text [pieces] (gen/fmap str/join (gen/vector (gen/elements pieces) 0 12)))

(def ^:private flat-pieces ["a" "b" "ab" "/" "." "clj" "cljs" "x" "-" ":" ""])
(def ^:private needles     (gen/vector (gen/elements ["a" "b" "ab" ".clj" "/" "x-"]) 1 3))

;;; --- where a literal sits ---------------------------------------------------

(defspec starts-with-any-is-anchored-alternation 400
  (prop/for-all [s (gen-text flat-pieces) ps needles]
    (= (found? (str "^" (alt ps)) s) (text/starts-with-any? s ps))))

(defspec ends-with-any-is-end-anchored-alternation 400
  (prop/for-all [s (gen-text flat-pieces) ps needles]
    (= (found? (str (alt ps) "$") s) (text/ends-with-any? s ps))))

(defspec includes-any-is-alternation 400
  (prop/for-all [s (gen-text flat-pieces) ps needles]
    (= (found? (alt ps) s) (text/includes-any? s ps))))

(defspec extension-in-is-dot-alternation-at-end 400
  (prop/for-all [s (gen-text flat-pieces) exts (gen/vector (gen/elements ["clj" "cljs" "edn" "b"]) 1 3)]
    (= (found? (str "\\." (alt exts) "$") s) (text/extension-in? s exts))))

(defspec under-path-is-root-then-slash-or-end 400
  (prop/for-all [s (gen-text ["/w" "/ww" "/" "a" "/w/" "x"]) root (gen/elements ["/w" "/w/a" "/"])]
    (= (found? (str "^" (q root) "(?:/|$)") s) (text/under-path? s root))))

;;; --- case and order ---------------------------------------------------------

(defspec includes-ci-folds-ascii-only-like-java 400
  (prop/for-all [s (gen-text ["a" "A" "b" "B" "é" "É" "k" "K" "x"])
                 n (gen-text ["a" "A" "é" "É" "b" "K"])]
    (= (found? (str "(?i)" (q n)) s) (text/includes-ci? s n))))

(defspec in-order-stays-on-one-line 400
  (prop/for-all [s (gen-text ["a" "b" "c" "\n" "ab" " "]) ns (gen/vector (gen/elements ["a" "b" "c" "ab"]) 1 3)]
    (= (found? (str/join ".*" (map q ns)) s) (text/in-order-on-a-line? s ns))))

;;; --- strips and collapses ---------------------------------------------------

(defspec strip-prefix-is-anchored-replace 400
  (prop/for-all [s (gen-text flat-pieces) p (gen/elements ["a" "ab" "/" ":" "x-"])]
    (= (str/replace s (re-pattern (str "^" (q p))) "") (text/strip-prefix s p))))

(defspec strip-suffix-is-end-anchored-replace 400
  (prop/for-all [s (gen-text flat-pieces) p (gen/elements ["a" "ab" "/" ".clj" "-"])]
    (= (str/replace s (re-pattern (str (q p) "$")) "") (text/strip-suffix s p))))

(defspec trim-leading-char-is-caret-run 400
  (prop/for-all [s (gen-text [":" "::" "a" "/" ""]) ch (gen/elements [\: \/ \a])]
    (= (str/replace s (re-pattern (str "^" (q (str ch)) "+")) "") (text/trim-leading-char s ch))))

(defspec trim-trailing-char-is-run-at-end 400
  (prop/for-all [s (gen-text ["/" "//" "a" ":" ""]) ch (gen/elements [\/ \: \a])]
    (= (str/replace s (re-pattern (str (q (str ch)) "+$")) "") (text/trim-trailing-char s ch))))

(defspec collapse-whitespace-is-java-s-plus 400
  (prop/for-all [s (gen-text ["a" " " "\t" "\n" "\u000B" "\f" "\r" "\u00A0" "\u2003" "b"])]
    (= (str/replace s #"\s+" " ") (text/collapse-whitespace s))))

;;; --- totality and the pinned edges -------------------------------------------

(deftest non-strings-are-false-or-unchanged
  (is (false? (text/starts-with-any? nil ["a"])))
  (is (false? (text/includes-ci? 42 "a")))
  (is (false? (text/under-path? nil "/w")))
  (is (nil? (text/strip-prefix nil "a")))
  (is (= :k (text/collapse-whitespace :k))))

(deftest the-documented-difference-from-dollar
  (testing "Java's $ under re-find matches before a final newline; ends-with does not"
    (is (true? (found? "\\.clj$" "a.clj\n")))
    (is (false? (text/extension-in? "a.clj\n" ["clj"])))))

(deftest under-path-examples
  (is (true? (text/under-path? "/w" "/w")))
  (is (true? (text/under-path? "/w/a" "/w")))
  (is (false? (text/under-path? "/ww" "/w"))))

(mut/deftest-mutations ends-with-any-mutants-are-caught
  hive-system.text/ends-with-any?
  [["includes anywhere" (fn [s xs] (text/includes-any? s xs))]
   ["starts instead" (fn [s xs] (text/starts-with-any? s xs))]]
  (fn []
    (is (true? (text/ends-with-any? "src/a.clj" [".clj"])))
    (is (false? (text/ends-with-any? "a.clj.bak" [".clj"])))
    (is (false? (text/ends-with-any? ".clj/x" [".clj"])))))

(mut/deftest-mutations under-path-mutants-are-caught
  hive-system.text/under-path?
  [["plain prefix" (fn [p r] (str/starts-with? (str p) (str r)))]
   ["root itself excluded" (fn [p r] (str/starts-with? (str p) (str r "/")))]]
  (fn []
    (is (true? (text/under-path? "/w" "/w")))
    (is (false? (text/under-path? "/ww" "/w")))))
