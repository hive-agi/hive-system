(ns hive-system.text
  "String predicates and transforms the workspace kept spelling as regex
   literals: a prefix, a suffix, an extension set, a path root, a literal
   anywhere, case-insensitively, or in order on a line, and the strips and
   collapses around them. Pure, total over any value (a non-string subject is
   false or returned unchanged), and regex-free.

   Each function names the literal it replaces. The tests prove each one
   DIFFERENTIALLY against that regex over generated strings.

   One deliberate difference: Java's `$` under `re-find` also matches before
   a FINAL line terminator, so `#\"\\.clj$\"` is true on \"a.clj\\n\". These
   functions end at the end of the string. `re-matches` has no such quirk,
   and neither do paths, ids or tokens."
  (:require [clojure.string :as str]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

;;; ===========================================================================
;;; Where a literal sits
;;; ===========================================================================

(defn starts-with-any?
  "True when `s` starts with one of `prefixes`. Replaces `#\"^(a|b)\"`."
  [s prefixes]
  (boolean (and (string? s) (some #(str/starts-with? s %) prefixes))))

(defn ends-with-any?
  "True when `s` ends with one of `suffixes`. Replaces `#\"(a|b)$\"`."
  [s suffixes]
  (boolean (and (string? s) (some #(str/ends-with? s %) suffixes))))

(defn includes-any?
  "True when `s` contains one of `needles`. Replaces `#\"a|b\"`."
  [s needles]
  (boolean (and (string? s) (some #(str/includes? s %) needles))))

(defn extension-in?
  "True when `path` ends in `.` followed by one of `exts`.
   Replaces `#\"\\.(clj|cljs)$\"`."
  [path exts]
  (ends-with-any? path (map #(str "." %) exts)))

(defn under-path?
  "True when `path` is `root` or lies under it (`root/...`).
   Replaces `#\"^root(/|$)\"`."
  [path root]
  (boolean (and (string? path) (string? root)
                (or (= path root) (str/starts-with? path (str root "/"))))))

;;; ===========================================================================
;;; Case and order
;;; ===========================================================================

(defn- ascii-lower
  "`s` with only A-Z lowered: exactly the folding Java's `(?i)` does without
   `(?u)`. `str/lower-case` would also fold non-ASCII letters."
  [s]
  (apply str (map (fn [c] (if (and (>= (int c) 65) (<= (int c) 90))
                            (char (+ (int c) 32))
                            c))
                  s)))

(defn includes-ci?
  "True when `s` contains `needle`, ASCII letters compared without case.
   Replaces `#\"(?i)needle\"`."
  [s needle]
  (boolean (and (string? s) (string? needle)
                (str/includes? (ascii-lower s) (ascii-lower needle)))))

(defn- in-order-in? [line needles]
  (loop [from 0 [n & more :as ns] (seq needles)]
    (if-not ns
      true
      (if-let [i (str/index-of line n from)]
        (recur (+ i (count n)) more)
        false))))

(defn in-order-on-a-line?
  "True when `needles` occur in `s` in order, without overlap, on ONE line.
   Replaces `#\"a.*b.*c\"`, whose `.` does not cross a line terminator."
  [s needles]
  (boolean (and (string? s)
                (some #(in-order-in? % needles) (str/split-lines s)))))

;;; ===========================================================================
;;; Strips and collapses
;;; ===========================================================================

(defn strip-prefix
  "`s` without a leading `prefix`. Replaces `(str/replace s #\"^prefix\" \"\")`."
  [s prefix]
  (if (and (string? s) (str/starts-with? s prefix)) (subs s (count prefix)) s))

(defn strip-suffix
  "`s` without a trailing `suffix`. Replaces `(str/replace s #\"suffix$\" \"\")`."
  [s suffix]
  (if (and (string? s) (str/ends-with? s suffix))
    (subs s 0 (- (count s) (count suffix)))
    s))

(defn trim-leading-char
  "`s` without its leading run of `ch`. Replaces `#\"^:+\"`."
  [s ch]
  (if (string? s)
    (let [n (count (take-while #(= ch %) s))] (subs s n))
    s))

(defn trim-trailing-char
  "`s` without its trailing run of `ch`. Replaces `#\"/+$\"`."
  [s ch]
  (if (string? s)
    (let [n (count (take-while #(= ch %) (reverse s)))] (subs s 0 (- (count s) n)))
    s))

(def ascii-whitespace
  "The characters Java's `\\s` matches: space, tab, newline, vertical tab, form
   feed, carriage return. ASCII only, unlike regal's `:whitespace`."
  #{\space \tab \newline \u000B \formfeed \return})

(defn collapse-whitespace
  "`s` with every run of `ascii-whitespace` replaced by one space.
   Replaces `(str/replace s #\"\\s+\" \" \")`."
  [s]
  (if (string? s)
    (let [sb #?(:clj (StringBuilder.) :cljs (array))]
      (loop [cs (seq s) in-ws? false]
        (if-not cs
          #?(:clj (str sb) :cljs (.join sb ""))
          (let [c (first cs) ws? (contains? ascii-whitespace c)]
            (cond
              (and ws? in-ws?) (recur (next cs) true)
              ws?              (do #?(:clj (.append sb \space) :cljs (.push sb " ")) (recur (next cs) true))
              :else            (do #?(:clj (.append sb c) :cljs (.push sb c)) (recur (next cs) false)))))))
    s))
