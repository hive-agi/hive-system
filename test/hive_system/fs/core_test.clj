(ns hive-system.fs.core-test
  "find-files / expand-path walk contract. Every test works inside a temp dir it
   created itself — never a production path. The tree is described as DATA and
   materialized at one boundary, so no test names a path literal."
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [clojure.set :as set]
            [clojure.string :as str]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [babashka.fs :as fs]
            [hive-dsl.result :as r]
            [hive-test.properties :as htp]
            [hive-system.fs.core :as sut]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

;; =============================================================================
;; Collect — the fixture as pure data
;; =============================================================================

(def ^:private probe-tree
  "relative-path -> content. Pure; `materialize!` is the only thing touching disk."
  {"a.clj"               "root-level source"
   "sub/b.clj"           "nested source"
   "sub/deep/c.cljc"     "deeper source"
   "target/skipme.clj"   "build output — must never be walked"
   "data/store.edn"      "konserve-shaped store — the hang hazard"
   "node_modules/v.clj"  "vendored — must never be walked"
   ".hidden/h.clj"       "inside a hidden dir"
   ".dotfile.clj"        "a hidden file"
   "notes.txt"           "non-matching extension"})

(def ^:private source-exts #{"clj" "cljs" "cljc" "edn"})

(def ^:private prunable-dirs
  "Top-level dirs of `probe-tree` that a skip set may name."
  ["target" "data" "node_modules" "sub"])

(def ^:private ^:dynamic *root* nil)

;; =============================================================================
;; Boundary — the only disk effects
;; =============================================================================

(defn- materialize!
  "Write `spec` under `root`. Returns root."
  [root spec]
  (doseq [[rel content] spec
          :let          [f (fs/path root rel)]]
    (fs/create-dirs (fs/parent f))
    (spit (fs/file f) content))
  root)

(defn- with-temp-root [f]
  (let [dir (fs/create-temp-dir {:prefix "hs-fs-core-test-"})]
    (try
      (materialize! dir probe-tree)
      (binding [*root* (str dir)] (f))
      (finally (fs/delete-tree dir)))))

(use-fixtures :each with-temp-root)

;; =============================================================================
;; Promote — pure projections over a walk result
;; =============================================================================

(defn- ok! [res]
  (is (r/ok? res) (str "expected ok, got " (pr-str res)))
  (:ok res))

(defn- rel-set
  "Walk output -> sorted set of root-relative paths, so assertions are readable
   and independent of the temp dir the fixture happened to get."
  [paths]
  (into (sorted-set) (map #(str (fs/relativize *root* %))) paths))

(defn- walk
  ([]     (walk {}))
  ([opts] (rel-set (ok! (sut/find-files *root* source-exts opts)))))

(defn- under-any?
  "Is `p` inside one of `dirs`?"
  [dirs p]
  (boolean (some #(str/starts-with? p (str % "/")) dirs)))

;; =============================================================================
;; The regression this namespace exists for
;; =============================================================================

(deftest find-files-prunes-heavy-directories-by-default
  (testing "source outside the skip set is still found, at every depth"
    (is (= #{"a.clj" "sub/b.clj" "sub/deep/c.cljc"} (set (walk)))))
  (testing "the directories that caused the walk hang are never descended into"
    (let [found (walk)]
      (is (not (contains? found "target/skipme.clj")))
      (is (not (contains? found "data/store.edn"))
          "data/ holds konserve stores — descending it is the deep hang cause")
      (is (not (contains? found "node_modules/v.clj"))))))

(deftest find-files-still-excludes-hidden-entries
  (testing "parity with the fs/glob behaviour this walk replaced"
    (let [found (walk)]
      (is (not (contains? found ".hidden/h.clj")))
      (is (not (contains? found ".dotfile.clj"))))))

(deftest find-files-walks-a-root-that-is-itself-skippable
  (testing "an explicitly named root is honoured even when its name is in the skip set"
    (let [target (str (fs/path *root* "target"))
          found  (ok! (sut/find-files target source-exts))]
      (is (= 1 (count found)))
      (is (str/ends-with? (first found) "skipme.clj")))))

(deftest find-files-honours-max-depth
  (testing ":max-depth 1 sees only the root level"
    (is (= #{"a.clj"} (set (walk {:max-depth 1})))))
  (testing ":max-depth 2 reaches one level down but no further"
    (is (= #{"a.clj" "sub/b.clj"} (set (walk {:max-depth 2}))))))

(deftest find-files-honours-a-caller-supplied-skip-set
  (testing "an empty skip set descends everything the default would prune"
    (let [found (walk {:skip-dirs #{}})]
      (is (contains? found "target/skipme.clj"))
      (is (contains? found "data/store.edn"))))
  (testing "a custom set prunes exactly what it names, and nothing else"
    (let [found (walk {:skip-dirs #{"sub"}})]
      (is (not (contains? found "sub/b.clj")))
      (is (contains? found "a.clj"))
      (is (contains? found "target/skipme.clj")
          "target is only pruned because the DEFAULT names it, not intrinsically"))))

(deftest find-files-refuses-a-partial-answer-when-interrupted
  ;; `binding` is thread-local and a raw Thread does not inherit it, so the root
  ;; is captured here rather than dereferenced inside the worker.
  (let [root   *root*
        result (promise)
        flag   (promise)
        t      (Thread. #(do (.interrupt (Thread/currentThread))
                             (deliver result (sut/find-files root source-exts))
                             (deliver flag (.isInterrupted (Thread/currentThread)))))]
    (.start t)
    (.join t 5000)
    (testing "a truncated list would read as a complete answer, so the walk errs instead"
      (is (r/err? @result))
      (is (= :fs/find-failed (:error @result)))
      (is (str/includes? (str (:class @result)) "InterruptedException")))
    (testing "the interrupt flag survives, so the caller still observes its own cancellation"
      (is (true? @flag)))))

;; =============================================================================
;; Contracts the rewrite had to preserve
;; =============================================================================

(deftest find-files-keeps-its-non-directory-contracts
  (testing "a matching regular file returns itself"
    (let [f (str (fs/path *root* "a.clj"))]
      (is (= [f] (ok! (sut/find-files f source-exts))))))
  (testing "a non-matching regular file returns empty"
    (is (= [] (ok! (sut/find-files (str (fs/path *root* "notes.txt")) source-exts)))))
  (testing "a nonexistent path returns empty rather than erring"
    (is (= [] (ok! (sut/find-files (str (fs/path *root* "no-such-thing")) source-exts)))))
  (testing "the 2-arity still exists and means the same as an empty opts map"
    (is (= (ok! (sut/find-files *root* source-exts))
           (ok! (sut/find-files *root* source-exts {}))))))

(deftest expand-path-rescues-to-a-plain-vector
  (testing "it unwraps ok"
    (is (= (walk) (rel-set (sut/expand-path *root* source-exts)))))
  (testing "it passes opts through to find-files"
    (is (= #{"a.clj"} (set (rel-set (sut/expand-path *root* source-exts {:max-depth 1}))))))
  (testing "a nonexistent path degrades to [] rather than throwing"
    (is (= [] (sut/expand-path (str (fs/path *root* "no-such-thing")) source-exts)))))

;; =============================================================================
;; Properties — generated skip sets, not hand-picked ones
;; =============================================================================

(htp/defprop-total find-files-is-total-over-arbitrary-skip-sets
  (fn [skips] (sut/find-files *root* source-exts {:skip-dirs skips}))
  (gen/set (gen/elements (conj prunable-dirs "absent-dir")))
  {:num-tests 60 :pred r/ok?})

(htp/defprop-metamorphic pruning-more-can-only-return-fewer
  (fn [skips] (set (walk {:skip-dirs skips})))
  (fn [skips] (conj skips "sub"))
  (fn [out out'] (set/subset? out' out))
  (gen/set (gen/elements prunable-dirs))
  {:num-tests 60})

(defspec pruning-is-exactly-a-filter-of-the-unpruned-walk 60
  ;; The strong relation: skipping a directory removes precisely the paths under
  ;; it — the walk never drops an unrelated file, and never invents one.
  (prop/for-all [skips (gen/set (gen/elements prunable-dirs))]
    (let [everything (walk {:skip-dirs #{}})
          pruned     (walk {:skip-dirs skips})]
      (= pruned (into (sorted-set) (remove #(under-any? skips %)) everything)))))
