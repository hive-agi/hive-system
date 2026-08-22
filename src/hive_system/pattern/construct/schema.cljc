(ns hive-system.pattern.construct.schema
  "Malli value objects for regex CONSTRUCTS — a regex expression reified as data.

   ## Two forms, one language

   A construct is AUTHORED in lambdaisland/regal's vector syntax — `[:cat \"a\"
   [:alt \"b\" \"c\"]]` — and NORMALIZED into the recursive map value object this
   namespace defines. The authored form is what callers write; the normalized
   form is what carries contracts, generators and tests. `construct.core`
   promotes one into the other and projects back.

   The split is forced: malli refuses a `:ref` reachable inside a sequence
   schema (`::m/potentially-recursive-seqex`), and regal's head-plus-variadic
   vector IS a sequence schema.

   ## Capabilities

   A `Capability` names a regex feature whose availability differs across target
   languages. A `Dialect` declares the set it PROVIDES; a construct's required
   set is computed from its shape. Support is a set-difference, decidable before
   emission — never a `try`/`catch` around a compile.

   These schemas are the single source: they drive the `m/=>` contracts and the
   synthesized property/mutation tests."
  (:require [malli.core :as m]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

;;; =============================================================================
;;; Capabilities
;;; =============================================================================

(def Capability
  "A regex feature a dialect may or may not provide.

   :lookaround       (?=…) (?!…) (?<=…) (?<!…)
   :atomic           (?>…) — a group that does not backtrack
   :lazy             *? +? ?? {n,m}? — reluctant quantifiers
   :perl-class       \\d \\w \\s and complements
   :capture          a group whose INDEX is promised. POSIX ERE has only one
                     grouping syntax, so every structural group it emits also
                     captures and shifts the numbering — a dialect that cannot
                     group without capturing cannot honour `:match/groups`.
   :control-escape   \\t \\n \\r \\f \\a \\e \\0 \\v — naming a control character
                     rather than embedding the byte. ERE has no such spelling,
                     and `grep -E '\\t'` matches a literal `t`.
   :collation-range  a bracket range by CODE POINT. POSIX bracket ranges are
                     ordered by the runtime locale's collation, so a range
                     whose ends are not both upper, both lower or both digit
                     denotes a different set per locale — or none at all.

   Every member is PRODUCIBLE: some Construct requires it, so the refusal
   property has a case for each. A feature no construct can express does not
   belong here until one can — a capability with no producer makes its own
   test vacuous."
  [:enum :lookaround :atomic :lazy :perl-class :capture :control-escape
   :collation-range])

(def Capabilities
  "A set of capabilities: what a dialect provides, or what a construct needs."
  [:set Capability])

;;; =============================================================================
;;; Leaves
;;; =============================================================================

(def Token
  "A construct with no arguments: an anchor, a character-class shorthand, or a
   literal control character. Spelled exactly as regal spells it."
  [:enum :any :start :end
   :digit :non-digit :word :non-word :whitespace :non-whitespace
   :newline :return :tab :form-feed :alert :escape :null
   :vertical-whitespace :vertical-tab :line-break])

(def Range
  "An inclusive character range inside a class. START must not exceed END —
   `Pattern/compile` rejects a reversed range, so the invariant belongs here
   rather than in a caller's head."
  [:and
   [:tuple char? char?]
   [:fn {:error/message "a class range must not be reversed: start > end"}
    (fn [[lo hi]] (<= (int lo) (int hi)))]])

(def ClassEntry
  "One member of a character class: a literal character, a range, or a
   shorthand token."
  [:or char? Range Token])

;;; =============================================================================
;;; Operators
;;; =============================================================================

(def QuantifierOp
  "An n-ary operator that additionally carries `:construct/lazy?`. Kept out of
   `NAryOp` so the generator cannot mint a quantifier in non-quantifier shape."
  [:enum :* :+ :?])

(def NAryOp
  "An operator over one or more sub-constructs, in `:construct/args`, with no
   further keys."
  [:enum :cat :alt :capture :atomic
   :lookahead :negative-lookahead :lookbehind :negative-lookbehind])

(def Op
  "Every construct head. `:literal`, `:token`, `:class`, `:repeat` and the
   quantifiers carry shape-specific keys; everything else is plain n-ary."
  (into [:enum :literal :token :class :repeat] (concat (rest QuantifierOp) (rest NAryOp))))

;;; =============================================================================
;;; Construct — the recursive value object
;;; =============================================================================

(def Construct
  "A normalized regex expression.

   Dispatches on `:construct/op`. Every branch is `:closed` — an unrecognized
   key is a defect, not an extension point; extension happens through the
   dialect registry.

     :literal  {:construct/text \"abc\"}                    matched verbatim
     :token    {:construct/token :digit}
     :class    {:construct/negated? false
                :construct/entries [[\\a \\z] \\_ :digit]}
     :repeat   {:construct/arg C :construct/min 2
                :construct/max 4 :construct/lazy? false}   :max absent = unbounded
     <n-ary>   {:construct/args [C …]}                     :cat :alt :* :+ :? …

   A quantifier (`:*` `:+` `:?`) carries `:construct/lazy?`; every other n-ary
   op omits it."
  [:schema
   {:registry
    {::construct
     [:multi {:dispatch :construct/op}

      [:literal
       [:map {:closed true}
        [:construct/op [:= :literal]]
        [:construct/text :string]]]

      [:token
       [:map {:closed true}
        [:construct/op [:= :token]]
        [:construct/token Token]]]

      [:class
       [:map {:closed true}
        [:construct/op [:= :class]]
        [:construct/negated? :boolean]
        [:construct/entries [:vector {:min 1} ClassEntry]]]]

      [:repeat
       [:and
        [:map {:closed true}
         [:construct/op [:= :repeat]]
         [:construct/arg [:ref ::construct]]
         [:construct/min [:int {:min 0}]]
         [:construct/max {:optional true} [:int {:min 0}]]
         [:construct/lazy? :boolean]]
        [:fn {:error/message "a repeat bound must not be inverted: min > max"}
         (fn [{:construct/keys [min max]}] (or (nil? max) (<= min max)))]]]

      [:* [:ref ::quantifier]]
      [:+ [:ref ::quantifier]]
      [:? [:ref ::quantifier]]

      [::m/default
       [:map {:closed true}
        [:construct/op NAryOp]
        [:construct/args [:vector {:min 1} [:ref ::construct]]]]]]

     ::quantifier
     [:map {:closed true}
      [:construct/op [:enum :* :+ :?]]
      [:construct/args [:vector {:min 1} [:ref ::construct]]]
      [:construct/lazy? :boolean]]}}
   ::construct])

(def RawConstruct
  "What a caller may hand in: regal's authored vector syntax, or an already
   normalized Construct. Deliberately permissive — `core/normalize` is the gate,
   and it reports WHY a form was refused."
  :any)

;;; =============================================================================
;;; Dialects
;;; =============================================================================

(def DialectId
  "Stable keyword naming a registered dialect (:java, :ecma, :re2)."
  :keyword)

(def Dialect
  "A regex target language, as data.

   `:dialect/capabilities` is what the target PROVIDES. Emitting a construct
   that needs anything outside it is refused — never approximated, because an
   approximation is a different language that still runs.

   `:dialect/flavor` is the regal flavor used to render the residual construct
   once the gate has passed."
  [:map {:closed true}
   [:dialect/id DialectId]
   [:dialect/capabilities Capabilities]
   [:dialect/flavor :keyword]
   [:dialect/doc {:optional true} :string]])

(def DialectIndex
  "id -> Dialect. The registry's value; passed explicitly to pure resolvers."
  [:map-of :keyword Dialect])
