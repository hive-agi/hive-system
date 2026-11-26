(ns hive-system.path
  "Path algebra over strings: no filesystem, no environment, no Result.

     (absolute? \"/a\")                => true
     (join \"/ws/\" \"../x\")            => \"/ws/../x\"
     (resolve \"/ws\" \"/opt/x\")         => \"/opt/x\"
     (normalize \"/a/./b/../c//\")     => \"/a/c\"
     (under? \"/w/a\" \"/w\")            => true
     (expand-tilde \"~/x\" \"/home/u\")  => \"/home/u/x\"

   Layout: value objects (malli), flavor methods (`separator`, `separator?`,
   `root`, `absolute-flavor?`, `split`: one defmethod per flavor), the pure
   core (total fns reading `*flavor*` at CALL time), contracts.

   A flavor is an open keyword: `:posix` and `:windows` ship, and a new flavor
   is a new defmethod of each flavor multimethod. Every core fn is total: a
   non-string subject answers false, or comes back unchanged.

   Requires only clojure.string and malli, so it loads under babashka."
  (:refer-clojure :exclude [resolve])
  (:require [clojure.string :as str]
            [malli.core :as m]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

;;; =============================================================================
;;; Value objects
;;; =============================================================================

(def Flavor
  "The path flavors this namespace ships methods for."
  [:enum :posix :windows])

(def PathString
  "A path as a string: absolute or relative, normalized or not."
  [:string {:gen/schema [:vector {:max 8} [:enum "/" "//" "a" "bc" "." ".." "x.y" "~" "s_1"]]
            :gen/fmap   (fn [parts] (apply str parts))}])

(def Segment
  "One non-empty path component holding no POSIX separator."
  [:and
   [:string {:min 1 :gen/schema [:enum "a" "bc" "." ".." "x.y" "~" "s_1" "-v"]}]
   [:fn {:error/message "a segment holds no separator"}
    (fn [s] (not (str/includes? s "/")))]])

(def Segments
  "Path components, in order."
  [:vector Segment])

;;; =============================================================================
;;; Flavor methods
;;; =============================================================================

(def ^:dynamic *flavor*
  "The flavor every core fn uses. Read at CALL time; rebind to change it."
  :posix)

(defmulti separator
  "The separator string FLAVOR writes between segments."
  (fn [flavor] flavor))

(defmethod separator :posix [_] "/")
(defmethod separator :windows [_] "\\")

(defmulti separator?
  "True when character C separates segments under FLAVOR."
  (fn [flavor _c] flavor))

(defmethod separator? :posix [_ c] (= c \/))
(defmethod separator? :windows [_ c] (or (= c \\) (= c \/)))

(defn- drive-letter? [c]
  (let [i (int c)]
    (or (<= 65 i 90) (<= 97 i 122))))

(defmulti root
  "The root prefix of string P under FLAVOR; \"\" when P has none."
  (fn [flavor _p] flavor))

(defmethod root :posix [_ p]
  (if (str/starts-with? p "/") "/" ""))

(defmethod root :windows [flavor p]
  (cond
    (and (>= (count p) 2) (drive-letter? (nth p 0)) (= \: (nth p 1)))
    (if (and (>= (count p) 3) (separator? flavor (nth p 2))) (subs p 0 3) (subs p 0 2))

    (and (seq p) (separator? flavor (nth p 0)))
    (subs p 0 1)

    :else ""))

(defmulti absolute-flavor?
  "True when string P is absolute under FLAVOR."
  (fn [flavor _p] flavor))

(defmethod absolute-flavor? :posix [_ p]
  (str/starts-with? p "/"))

(defmethod absolute-flavor? :windows [flavor p]
  (let [r (root flavor p)]
    (boolean (and (seq r) (separator? flavor (last r))))))

(defn- split-on
  "The non-empty runs of S between the characters SEP? accepts."
  [sep? s]
  (let [flush (fn [out cur] (if (seq cur) (conj out (apply str cur)) out))]
    (loop [cs (seq s) cur [] out []]
      (if-let [c (first cs)]
        (if (sep? c)
          (recur (next cs) [] (flush out cur))
          (recur (next cs) (conj cur c) out))
        (flush out cur)))))

(defmulti split
  "The non-empty segments of string S under FLAVOR, in order. Empty runs
   between separators are dropped; the root is not a segment."
  (fn [flavor _s] flavor))

(defmethod split :posix [flavor s] (split-on (fn [c] (separator? flavor c)) s))
(defmethod split :windows [flavor s] (split-on (fn [c] (separator? flavor c)) s))

;;; =============================================================================
;;; Pure core
;;; =============================================================================

(defn absolute?
  "True when P is a string that is absolute under `*flavor*`."
  [p]
  (boolean (and (string? p) (absolute-flavor? *flavor* p))))

(defn relative?
  "True when P is a string that is not absolute under `*flavor*`."
  [p]
  (boolean (and (string? p) (not (absolute-flavor? *flavor* p)))))

(defn- trim-separators
  "S without its leading (side :left) or trailing (side :right) separators."
  [s side]
  (let [sep? (fn [c] (separator? *flavor* c))]
    (case side
      :left  (subs s (count (take-while sep? s)))
      :right (subs s 0 (- (count s) (count (take-while sep? (reverse s)))))))) 

(defn join
  "P appended to BASE with exactly one separator between them.

   A plain join, no canonicalization: `.` and `..` survive as written, and
   separators inside BASE or P are kept. A nil or empty BASE answers P; a nil
   or empty P answers BASE. More arguments join left to right."
  ([base p]
   (cond
     (not (and (string? base) (seq base))) p
     (not (and (string? p) (seq p)))       base
     :else (str (trim-separators base :right)
                (separator *flavor*)
                (trim-separators p :left))))
  ([base p & more]
   (reduce join (join base p) more)))

(defn resolve
  "P against BASE: P itself when it is absolute, else `(join base p)`."
  [base p]
  (if (absolute? p) p (join base p)))

(defn segments
  "The non-empty segments of P after its root, in order; [] for a non-string."
  [p]
  (if (string? p)
    (split *flavor* (subs p (count (root *flavor* p))))
    []))

(defn- fold-segment [absolute stack seg]
  (cond
    (= "." seg) stack
    (and (= ".." seg) (seq stack) (not= ".." (peek stack))) (pop stack)
    (and (= ".." seg) absolute) stack
    :else (conj stack seg)))

(defn normalize
  "P with `.` segments dropped, each `..` folded into the segment before it,
   repeated and trailing separators removed, without touching the disk. A `..`
   above an absolute root is dropped; above a relative path it is kept. An
   empty relative result is \".\". A non-string comes back unchanged.
   Idempotent."
  [p]
  (if (string? p)
    (let [r     (root *flavor* p)
          abs   (absolute-flavor? *flavor* p)
          segs  (reduce (fn [st s] (fold-segment abs st s)) [] (segments p))
          body  (str/join (separator *flavor*) segs)
          out   (str r body)]
      (if (= "" out) "." out))
    p))

(defn normal?
  "True when P is a string that `normalize` leaves unchanged."
  [p]
  (boolean (and (string? p) (= p (normalize p)))))

(defn under?
  "True when P is ROOT or lies under it: ROOT followed by a separator.
   Lexical: neither string is normalized, so \"/w/../x\" is under \"/w\", and
   ROOT \"/\" covers only \"/\" itself (\"/\" then a separator is \"//\")."
  [p root]
  (boolean (and (string? p) (string? root)
                (or (= p root)
                    (str/starts-with? p (str root (separator *flavor*)))))))

(defn expand-tilde
  "P with a leading `~` (alone, or followed by a separator) replaced by HOME.
   HOME is an argument: this fn never reads the environment. `~user` forms, a
   nil or blank HOME and a non-string P all come back unchanged."
  [p home]
  (cond
    (not (and (string? p) (string? home) (not (str/blank? home)))) p
    (= "~" p) home
    (and (>= (count p) 2) (= \~ (nth p 0)) (separator? *flavor* (nth p 1)))
    (join home (subs p 2))
    :else p))

;;; =============================================================================
;;; Contracts
;;; =============================================================================

(m/=> absolute? [:=> [:cat :any] :boolean])
(m/=> relative? [:=> [:cat :any] :boolean])
(m/=> join [:function
            [:=> [:cat [:maybe :string] [:maybe :string]] [:maybe :string]]
            [:=> [:cat [:maybe :string] [:maybe :string] [:+ [:maybe :string]]] [:maybe :string]]])
(m/=> resolve [:=> [:cat [:maybe :string] :string] [:maybe :string]])
(m/=> segments [:=> [:cat :any] [:vector :string]])
(m/=> normalize [:=> [:cat :any] :any])
(m/=> normal? [:=> [:cat :any] :boolean])
(m/=> under? [:=> [:cat :any :any] :boolean])
(m/=> expand-tilde [:=> [:cat :any :any] :any])
