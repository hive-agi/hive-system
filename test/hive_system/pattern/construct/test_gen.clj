(ns hive-system.pattern.construct.test-gen
  "A generator of Constructs, shared by every suite that needs one.

   It lives here rather than inside one test namespace because two suites now
   draw from it — the property suite and the rg differential — and a second
   copy would drift from the first the moment a new op is added.

   ## The honest domain

   Measured on regal 0.1.175: `regal.generator` has no method for
   `:lookahead`, `:negative-lookahead`, `:lookbehind`, `:negative-lookbehind`
   or `:atomic`, and refuses `:start` in non-initial position. This generator
   therefore emits none of them, and `generable?` is DERIVED from
   `required-capabilities` rather than hand-maintained, so a construct that
   sneaks a lookaround in cannot silently enter a corpus."
  (:require [clojure.set :as set]
            [clojure.test.check.generators :as gen]
            [hive-system.pattern.construct.core :as cc]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(def ungenerable
  "Capabilities regal's generator has no method for."
  #{:lookaround :atomic})

(defn generable?
  "Can regal generate strings for CONSTRUCT? Derived from the capability
   analysis, so it cannot drift from what the constructs actually contain."
  [construct]
  (empty? (set/intersection ungenerable (cc/required-capabilities construct))))

;;; =============================================================================
;;; A generator of generable constructs
;;; =============================================================================

(def class-tokens
  [:digit :non-digit :word :non-word :whitespace :non-whitespace])

(def gen-range
  (gen/fmap (fn [[a b]] (if (<= (int a) (int b)) [a b] [b a]))
            (gen/tuple gen/char-alpha gen/char-alpha)))

(def gen-class-entry
  (gen/one-of [gen/char-alphanumeric gen-range (gen/elements class-tokens)]))

(def gen-leaf
  ;; A NEGATED class is built from characters and ranges only. Allowing tokens
  ;; there lets a class draw both :word and :non-word, and `[^\w\W]` is the
  ;; empty language — regal's generator then starves ("couldn't satisfy
  ;; such-that"), which is the generator reporting an unsatisfiable regex, not
  ;; a defect in the emitter.
  (gen/one-of
   [(gen/fmap #(hash-map :construct/op :literal :construct/text %) gen/string-ascii)
    (gen/fmap #(hash-map :construct/op :token :construct/token %)
              (gen/elements (into [:any :newline :return :tab] class-tokens)))
    (gen/fmap (fn [es] #:construct{:op :class :negated? false :entries (vec es)})
              (gen/vector gen-class-entry 1 3))
    (gen/fmap (fn [es] #:construct{:op :class :negated? true :entries (vec es)})
              (gen/vector (gen/one-of [gen/char-alphanumeric gen-range]) 1 3))]))

(def gen-construct
  ;; Every `:repeat` drawn here is BOUNDED. An unbounded one composes
  ;; multiplicatively under nesting, and regal's generator then draws strings
  ;; long enough to hang a suite on the unlucky seed — an intermittent hang is
  ;; worse than a shape this corpus does not reach. `{n,}` is covered instead by
  ;; `core-test/an-unbounded-repeat-is-not-an-exact-one`, deterministically.
  (gen/recursive-gen
   (fn [inner]
     (gen/one-of
      [(gen/fmap #(hash-map :construct/op :cat :construct/args (vec %)) (gen/vector inner 1 3))
       (gen/fmap #(hash-map :construct/op :alt :construct/args (vec %)) (gen/vector inner 1 3))
       (gen/fmap #(hash-map :construct/op :capture :construct/args [%]) inner)
       (gen/fmap (fn [[c op lazy?]] #:construct{:op op :args [c] :lazy? lazy?})
                 (gen/tuple inner (gen/elements [:* :+ :?]) gen/boolean))
       (gen/fmap (fn [[c a b lazy?]]
                   #:construct{:op :repeat :arg c
                               :min (min a b) :max (max a b) :lazy? lazy?})
                 (gen/tuple inner (gen/choose 0 3) (gen/choose 0 3) gen/boolean))]))
   gen-leaf))
