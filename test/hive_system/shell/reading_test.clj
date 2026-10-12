(ns hive-system.shell.reading-test
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.test.check.generators :as gen]
            [hive-dsl.result :as r]
            [hive-system.shell.reading :as reading]
            [malli.core :as m]))

(defn- read! [& argv]
  (let [x (reading/read-argv argv)]
    (is (r/ok? x) (str "expected a Reading for " (pr-str argv)))
    (dissoc (:ok x) :reading/tool)))

(defn- reading [patterns paths recursive? globs types]
  #:reading{:patterns patterns :paths paths :recursive? recursive?
            :globs globs :types types})

(deftest grep-roles
  (testing "the first operand is the pattern, the rest are paths"
    (is (= (reading ["q"] ["a/src" "a/test"] true [] [])
           (read! "grep" "-rn" "q" "a/src" "a/test"))))
  (testing "a pattern equal to a directory name is still the pattern"
    (is (= (reading ["test"] ["/var/log"] true [] [])
           (read! "grep" "-rn" "test" "/var/log"))))
  (testing "a flagged pattern leaves every operand a path"
    (is (= (reading ["pat"] ["."] true ["*.go"] [])
           (read! "grep" "-rne" "pat" "--include" "*.go" "."))))
  (testing "--flag=value and an attached short value"
    (is (= (reading ["foo"] ["notes.txt"] false ["*.clj"] [])
           (read! "grep" "-A3" "--include=*.clj" "foo" "notes.txt"))))
  (testing "argv[0] is read by basename, and its aliases count"
    (is (= :grep (:reading/tool (:ok (reading/read-argv ["/usr/bin/egrep" "x"])))))))

(deftest ripgrep-roles
  (testing "rg recurses without a flag, and names no path when given none"
    (is (= (reading ["foo"] [] true [] []) (read! "rg" "foo"))))
  (testing "globs and types"
    (is (= (reading ["foo"] ["src"] true ["*.clj"] ["clojure"])
           (read! "rg" "-t" "clojure" "-g" "*.clj" "foo" "src"))))
  (testing "attached values, repeated patterns, and `--` ending the flags"
    (is (= (reading ["a" "b"] ["-weird"] true ["*.rs"] ["go"])
           (read! "rg" "-tgo" "--glob=*.rs" "-e" "a" "-e" "b" "--" "-weird"))))
  (testing "rg -r is --replace, which takes a value and is not recursion's flag"
    (is (= (reading ["foo"] ["src"] true [] [])
           (read! "rg" "-r" "bar" "foo" "src")))))

(deftest ag-ack-and-git-grep-roles
  (testing "ag and ack recurse without a flag"
    (is (= (reading ["foo"] [] true [] []) (read! "ag" "foo")))
    (is (= (reading ["foo"] ["a/src"] true [] ["clojure"])
           (read! "ack" "--type=clojure" "foo" "a/src"))))
  (testing "git grep, spelled git-grep by the caller, with pathspecs after `--`"
    (is (= (reading ["foo"] ["*.clj"] true [] [])
           (read! "git-grep" "-n" "foo" "--" "*.clj")))))

(deftest rgrep-and-type-switches
  (testing "rgrep is grep that recurses without a flag"
    (is (= :rgrep (:reading/tool (:ok (reading/read-argv ["rgrep" "foo" "a/src"])))))
    (is (= (reading ["foo"] ["a/src"] true [] []) (read! "rgrep" "foo" "a/src")))
    (is (false? (:reading/recursive? (read! "grep" "foo" "a/src")))))
  (testing "a bare --name type switch is a type; an unknown bare flag is not"
    (is (= (reading ["foo"] [] true [] ["clojure"]) (read! "ag" "--clojure" "foo")))
    (is (= (reading ["foo"] [] true [] ["rust"]) (read! "ack" "--rust" "-i" "foo")))
    (is (= (reading ["foo"] [] true [] []) (read! "ag" "--hidden" "foo")))
    (is (= (reading ["foo"] [] true [] []) (read! "rg" "--clojure" "foo")))))

(deftest refusals
  (is (= :reading/unknown-program (:error (reading/read-argv ["ls" "src"]))))
  (is (= :reading/empty-argv (:error (reading/read-argv [])))))

(deftest registry-refuses-a-malformed-grammar
  (is (= :reading/invalid-grammar
         (:error (reading/register! {:grammar/id :nope})))))

(deftest read-argv-is-total-and-well-shaped
  (let [token (gen/one-of [(gen/elements ["-r" "-rn" "-e" "--" "-" "--include=*.clj"
                                          "--include" "-g" "-t" "-A" "-A3" "--type"
                                          "src" "." "x.clj" "" "--regexp=a"])
                           gen/string-alphanumeric])
        argvs (gen/sample (gen/tuple (gen/elements ["grep" "rg" "egrep" "/bin/rg"])
                                     (gen/vector token 0 8))
                          400)]
    (doseq [[head args] argvs
            :let [x (reading/read-argv (into [head] args))]]
      (is (r/ok? x))
      (is (m/validate reading/Reading (:ok x))
          (str "ill-shaped Reading for " (pr-str head args))))))
