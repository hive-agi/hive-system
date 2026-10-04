(ns hive-system.shell.find-test
  "The find grammar, proven against the real `find`: an argv is a claim about
   find's parser, so each shape below is also run on a temp tree."
  (:require [clojure.java.io :as io]
            [clojure.java.shell :as jsh]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing are]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.properties :as prop]
            [hive-dsl.result :as r]
            [hive-system.shell.find :as find]
            [malli.generator :as mg]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(def ^:private tree
  ["a/x.clj" "a/y.txt" "node_modules/z.clj" "sub/deep/w.clj"])

(defn- with-tree
  "Run `f` with the absolute path of a temp directory holding `tree`."
  [f]
  (let [dir (doto (io/file (System/getProperty "java.io.tmpdir")
                           (str "hive-system-find-" (System/nanoTime)))
              (.mkdirs))]
    (try
      (doseq [rel tree]
        (let [file (io/file dir rel)]
          (.mkdirs (.getParentFile file))
          (spit file "x")))
      (f (.getAbsolutePath dir))
      (finally
        (doseq [^java.io.File g (reverse (file-seq dir))] (.delete g))))))

(defn- run
  "The root-relative paths the real find prints for `query` over `dir`."
  [dir query]
  (let [argv (:ok (find/argv (assoc query :roots [dir])))
        {:keys [exit out err]} (apply jsh/sh argv)
        sep  (if (some #{"-print0"} argv) #"\x00" #"\n")]
    (is (zero? exit) err)
    (->> (str/split out sep)
         (remove str/blank?)
         (map #(subs % (inc (count dir))))
         set)))

(deftest argv-shapes
  (are [q argv] (= argv (:ok (find/argv q)))
    {}                                            ["find" "."]
    {:roots ["src" "test"] :xdev? true :maxdepth 3} ["find" "src" "test" "-xdev" "-maxdepth" "3"]
    {:follow? true :expr [:type :d]}              ["find" "-L" "." "-type" "d"]
    {:expr [:and [:type :f] [:name "*.clj"]]}     ["find" "." "-type" "f" "-a" "-name" "*.clj"]
    {:expr [:and [:or [:name "a"] [:name "b"]] [:print0]]}
    ["find" "." "(" "-name" "a" "-o" "-name" "b" ")" "-a" "-print0"]
    {:expr [:not [:and [:name "*.clj"] [:empty]]]}
    ["find" "." "!" "(" "-name" "*.clj" "-a" "-empty" ")"]
    {:expr [:and [:size "+100M"] [:mtime -2]]}    ["find" "." "-size" "+100M" "-a" "-mtime" "-2"]))

(deftest an-invalid-query-is-refused-as-data
  (are [q] (= :find/invalid-query (:error (find/argv q)))
    {:roots []}
    {:expr [:exec "rm" "{}"]}
    {:expr [:type :x]}
    {:expr [:size "huge"]}
    {:unknown 1}))

(deftest the-real-find-agrees
  (with-tree
    (fn [dir]
      (testing "a type and name test"
        (is (= #{"a/x.clj" "node_modules/z.clj" "sub/deep/w.clj"}
               (run dir {:expr [:and [:type :f] [:name "*.clj"]]}))))
      (testing "prune keeps a directory out"
        (is (= #{"a/x.clj" "sub/deep/w.clj"}
               (run dir {:expr [:or [:and [:name "node_modules"] [:prune]]
                                    [:and [:type :f] [:name "*.clj"] [:print]]]}))))
      (testing "maxdepth"
        (is (= #{"a/x.clj" "node_modules/z.clj"}
               (run dir {:maxdepth 2 :expr [:and [:type :f] [:name "*.clj"]]}))))
      (testing "not binds a whole and, so the parentheses are load-bearing"
        (is (= #{"a/x.clj" "a/y.txt" "sub/deep/w.clj"}
               (run dir {:expr [:and [:type :f]
                                     [:not [:and [:name "*.clj"] [:path "*/node_modules/*"]]]]}))))
      (testing "print0"
        (is (= #{"a/y.txt"} (run dir {:expr [:and [:name "*.txt"] [:print0]]})))))))

(deftest read-only-classification
  (are [argv ro?] (= ro? (find/read-only-argv? argv))
    ["find" "." "-name" "*.clj"]                       true
    ["find" "/" "-xdev" "-maxdepth" "3" "-size" "+100M"] true
    ["find" "." "-print0"]                             true
    ["find" "." "-name" "*.orig" "-delete"]            false
    ["find" "." "-exec" "rm" "{}" ";"]                 false
    ["find" "." "-execdir" "cat" "{}" "+"]             false
    ["find" "." "-fprint" "/tmp/out"]                  false))

(defspec every-built-argv-is-a-read-only-find 200
  (prop/for-all [q (mg/generator find/Query {:size 6})]
    (let [res (find/argv q)]
      (and (r/ok? res)
           (= "find" (first (:ok res)))
           (find/read-only-argv? (:ok res))))))
