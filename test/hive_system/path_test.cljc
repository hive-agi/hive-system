(ns hive-system.path-test
  "hive-system.path: golden tables for join, normalize, under? and
   expand-tilde; test.check properties for the laws (join never doubles a
   separator, normalize is idempotent, an absolute base joins to an absolute
   path); schema trifectas over PathString and Segments; mutants of join.

   Runs under `bb test:bb` and under the JVM suite."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [hive-schemas.test :refer [deftrifecta-from-schema deftrifecta-from-multi]]
            [hive-system.path :as path]
            [hive-test.mutation :as mut]
            [malli.generator :as mg]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

;;; =============================================================================
;;; Generators
;;; =============================================================================

(def ^:private gen-path (mg/generator path/PathString))

(def ^:private gen-segments (mg/generator path/Segments))

(def ^:private gen-abs
  (gen/fmap (fn [segs] (str "/" (str/join "/" segs))) gen-segments))

(def ^:private gen-rel
  (gen/fmap (fn [segs] (str/join "/" segs)) (gen/not-empty gen-segments)))

(defn- doubled-separator? [s] (str/includes? s "//"))

;;; =============================================================================
;;; Golden tables
;;; =============================================================================

(def join-table
  "[base p expected]: the plain-join contract, row by row."
  [["/ws" "../x" "/ws/../x"]
   ["/ws/" "../x" "/ws/../x"]
   ["/ws" "/x" "/ws/x"]
   ["/ws//" "//x" "/ws/x"]
   ["a" "b" "a/b"]
   ["a" "./b" "a/./b"]
   ["/" "x" "/x"]
   [nil "x" "x"]
   ["" "x" "x"]
   ["/ws" "" "/ws"]
   ["/ws" nil "/ws"]
   [nil nil nil]])

(deftest join-golden
  (doseq [[base p expected] join-table]
    (is (= expected (path/join base p)) (pr-str [base p]))))

(deftest join-variadic
  (is (= "/h/.local/share/app/x" (path/join "/h" ".local" "share" "app" "x")))
  (is (= "/h/a" (path/join "/h" nil "a"))))

(def normalize-table
  "[p expected]: lexical normalization, row by row."
  [["/a/./b/../c//" "/a/c"]
   ["/a/b/.." "/a"]
   ["/.." "/"]
   ["/../a" "/a"]
   ["/" "/"]
   ["//" "/"]
   ["a/.." "."]
   ["../a" "../a"]
   ["a/../../b" "../b"]
   ["./" "."]
   ["" "."]
   ["a//b/" "a/b"]
   ["~/x/./y" "~/x/y"]])

(deftest normalize-golden
  (doseq [[p expected] normalize-table]
    (is (= expected (path/normalize p)) (pr-str p))))

(deftest absolute-and-relative
  (is (true? (path/absolute? "/a")))
  (is (true? (path/absolute? "/")))
  (is (false? (path/absolute? "a")))
  (is (false? (path/absolute? "../a")))
  (is (false? (path/absolute? "~/a")) "a tilde is not absolute: expand it first")
  (is (false? (path/absolute? "")))
  (is (false? (path/absolute? nil)))
  (is (true? (path/relative? "a")))
  (is (false? (path/relative? "/a")))
  (is (false? (path/relative? nil))))

(deftest resolve-keeps-an-absolute-p
  (is (= "/opt/x" (path/resolve "/ws" "/opt/x")))
  (is (= "/ws/../x" (path/resolve "/ws" "../x")))
  (is (= "x" (path/resolve nil "x"))))

(deftest under-golden
  (is (true? (path/under? "/w" "/w")))
  (is (true? (path/under? "/w/a" "/w")))
  (is (false? (path/under? "/ww" "/w")))
  (is (false? (path/under? "/w" "/w/a")))
  (is (true? (path/under? "/w/../x" "/w")) "lexical: nothing is normalized")
  (is (false? (path/under? nil "/w")))
  (is (false? (path/under? "/w" nil))))

(deftest expand-tilde-golden
  (is (= "/home/u" (path/expand-tilde "~" "/home/u")))
  (is (= "/home/u/x" (path/expand-tilde "~/x" "/home/u")))
  (is (= "/home/u/x" (path/expand-tilde "~/x" "/home/u/")))
  (is (= "~user/x" (path/expand-tilde "~user/x" "/home/u")))
  (is (= "/a/~" (path/expand-tilde "/a/~" "/home/u")))
  (is (= "~/x" (path/expand-tilde "~/x" nil)))
  (is (= "~/x" (path/expand-tilde "~/x" "  ")))
  (is (nil? (path/expand-tilde nil "/home/u"))))

(deftest segments-golden
  (is (= ["a" "b"] (path/segments "/a//b/")))
  (is (= [] (path/segments "/")))
  (is (= [] (path/segments nil))))

;;; =============================================================================
;;; Flavors
;;; =============================================================================

(deftest windows-flavor-through-the-seam
  (binding [path/*flavor* :windows]
    (is (true? (path/absolute? "C:\\x")))
    (is (true? (path/absolute? "\\x")))
    (is (false? (path/absolute? "C:x")) "drive-relative is not absolute")
    (is (= "C:\\a\\b" (path/join "C:\\a\\" "b")))
    (is (= "C:\\a\\c" (path/normalize "C:\\a\\.\\b\\..\\c")))
    (is (= ["a" "b"] (path/segments "C:/a\\b")))))

(deftest a-new-flavor-is-a-new-defmethod
  (defmethod path/separator ::colon [_] ":")
  (defmethod path/separator? ::colon [_ c] (= c \:))
  (defmethod path/root ::colon [_ p] (if (str/starts-with? p ":") ":" ""))
  (defmethod path/absolute-flavor? ::colon [_ p] (str/starts-with? p ":"))
  (defmethod path/split ::colon [_ s] (vec (remove str/blank? (str/split-lines (str/replace s ":" "\n")))))
  (binding [path/*flavor* ::colon]
    (is (= ":a:b" (path/join ":a:" ":b")))
    (is (true? (path/absolute? ":a")))))

(deftrifecta-from-multi separator-dispatch path/separator
  {:args     [:cat path/Flavor]
   :dispatch path/Flavor
   :out      [:enum "/" "\\"]
   :total?   true})

(deftrifecta-from-multi absolute-flavor-dispatch path/absolute-flavor?
  {:args     [:cat path/Flavor path/PathString]
   :dispatch path/Flavor
   :out      :boolean
   :total?   true})

;;; =============================================================================
;;; Schema trifectas
;;; =============================================================================

(deftrifecta-from-schema normalize-over-paths path/normalize
  {:in          path/PathString
   :out         :string
   :mutation    false
   :idempotent? true
   :rel         (fn [p out]
                  (and (not (doubled-separator? out))
                       (= (path/absolute? p) (path/absolute? out))
                       (or (= "." out) (not-any? #{"."} (path/segments out)))))})

(deftrifecta-from-schema segments-over-paths path/segments
  {:in       path/PathString
   :out      [:vector [:string {:min 1}]]
   :mutation false
   :rel      (fn [p out] (every? (fn [s] (not (str/includes? s "/"))) out))})

(deftrifecta-from-schema join-over-two-paths path/join
  {:in       [:cat path/PathString path/PathString]
   :out      [:maybe :string]
   :mutation false
   :rel      (fn [[b p] out]
               (cond
                 (= "" b) (= p out)
                 (= "" p) (= b out)
                 :else (and (str/includes? out "/")
                            (= (path/segments (str b "/" p)) (path/segments out)))))})

;;; =============================================================================
;;; Laws
;;; =============================================================================

(defspec join-never-doubles-a-separator 300
  (prop/for-all [b (gen/one-of [gen-abs gen-rel (gen/fmap (fn [s] (str s "/")) gen-abs)])
                 p (gen/one-of [gen-rel (gen/fmap (fn [s] (str "/" s)) gen-rel)])]
    (not (doubled-separator? (path/join b p)))))

(defspec normalize-is-idempotent 300
  (prop/for-all [p gen-path]
    (= (path/normalize p) (path/normalize (path/normalize p)))))

(defspec an-absolute-base-joins-to-an-absolute-path 300
  (prop/for-all [b gen-abs r gen-rel]
    (path/absolute? (path/join b r))))

(defspec join-keeps-every-segment 300
  (prop/for-all [b gen-abs r gen-rel]
    (= (into (path/segments b) (path/segments r))
       (path/segments (path/join b r)))))

(defspec a-joined-path-is-under-its-base 300
  (prop/for-all [segs (gen/not-empty gen-segments) r gen-rel]
    (let [b (str "/" (str/join "/" segs))]
      (path/under? (path/join b r) b))))

(deftest the-root-covers-only-itself
  (is (true? (path/under? "/" "/")))
  (is (false? (path/under? "/a" "/")) "root then separator is \"//\", as under-path? always read it"))

(defspec normalize-output-is-normal 300
  (prop/for-all [p gen-path]
    (path/normal? (path/normalize p))))

(defspec total-over-any-value 200
  (prop/for-all [x gen/any-equatable]
    (and (boolean? (path/absolute? x))
         (boolean? (path/under? x x))
         (vector? (path/segments x))
         (or (string? x) (= x (path/normalize x))))))

;;; =============================================================================
;;; Mutants
;;; =============================================================================

(mut/deftest-mutations join-mutants-are-caught
  hive-system.path/join
  [["doubles a separator" (fn [b p] (str b "/" p))]
   ["normalizes" (fn [b p] (path/normalize (str b "/" p)))]
   ["drops the base when blank-free" (fn [_ p] p)]]
  (fn []
    (is (= "/ws/../x" (path/join "/ws/" "../x")))
    (is (= "/ws/../x" (path/join "/ws" "../x")))
    (is (= "x" (path/join nil "x")))))

(mut/deftest-mutations under-mutants-are-caught
  hive-system.path/under?
  [["plain prefix" (fn [p r] (str/starts-with? (str p) (str r)))]
   ["root excluded" (fn [p r] (str/starts-with? (str p) (str r "/")))]]
  (fn []
    (is (true? (path/under? "/w" "/w")))
    (is (false? (path/under? "/ww" "/w")))))
