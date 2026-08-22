(ns hive-system.pattern.construct.core-test
  "PROMOTE layer: normalization, refusal, projection, capability analysis.

   `required-capabilities` is checked against an INDEPENDENT oracle — a flat
   tree-seq walk written differently from the structured recursion under test —
   so the relation has teeth instead of restating the implementation."
  (:require [clojure.test :refer [deftest is testing are]]
            [hive-dsl.result :as r]
            [hive-schemas.test :as st]
            [hive-system.pattern.construct.core :as cc]
            [hive-system.pattern.construct.schema :as cs]
            [hive-test.mutation :as mut]
            [malli.core :as m]
            [malli.generator :as mg]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(def ^:private perl-tokens
  #{:digit :non-digit :word :non-word :whitespace :non-whitespace
    :vertical-whitespace :line-break})

(def ^:private control-tokens
  "Tokens that name a control character instead of embedding the byte."
  #{:newline :return :tab :form-feed :alert :escape :null :vertical-tab})

(defn- cross-class-range?
  "An independent re-derivation: a range is code-point-only when its ends are
   NOT both upper, both lower or both digit."
  [entry]
  (and (vector? entry)
       (let [[lo hi] entry]
         (not (or (every? #(Character/isUpperCase ^char %) [lo hi])
                  (every? #(Character/isLowerCase ^char %) [lo hi])
                  (every? #(Character/isDigit ^char %)     [lo hi]))))))

(defn- node-demand
  "What ONE node demands, ignoring its children."
  [{:construct/keys [op token entries lazy?]}]
  (cond-> #{}
    (#{:lookahead :negative-lookahead :lookbehind :negative-lookbehind} op) (conj :lookaround)
    (= :atomic op)                                                          (conj :atomic)
    (= :capture op)                                                         (conj :capture)
    (and lazy? (not= :literal op))                                          (conj :lazy)
    (perl-tokens token)                                                     (conj :perl-class)
    (some perl-tokens entries)                                              (conj :perl-class)
    (control-tokens token)                                                  (conj :control-escape)
    (some control-tokens entries)                                           (conj :control-escape)
    (some cross-class-range? entries)                                       (conj :collation-range)))

(defn- capabilities-via-walk
  "Independent oracle for `required-capabilities`: flatten the whole construct
   with tree-seq and union every node's own demand. Shares no code path with
   the subject."
  [construct]
  (into #{}
        (comp (filter #(and (map? %) (contains? % :construct/op)))
              (mapcat node-demand))
        (tree-seq coll? seq construct)))

(defn- norm [form] (cc/normalize form))
(defn- norm! [form] (:ok (cc/normalize form)))
(defn- reason [form] (:error (cc/normalize form)))

;;; =============================================================================
;;; Normalization
;;; =============================================================================

(deftest normalizes-the-authored-forms
  (are [form expected] (= expected (norm! form))
    "abc"    #:construct{:op :literal :text "abc"}
    \x       #:construct{:op :literal :text "x"}
    :digit   #:construct{:op :token :token :digit}

    [:cat "a" "b"]
    #:construct{:op :cat :args [#:construct{:op :literal :text "a"}
                                #:construct{:op :literal :text "b"}]}

    [:class [\a \z] \_ :digit]
    #:construct{:op :class :negated? false :entries [[\a \z] \_ :digit]}

    [:not [\a \z]]
    #:construct{:op :class :negated? true :entries [[\a \z]]}

    [:repeat "ab" 2 4]
    #:construct{:op :repeat :arg #:construct{:op :literal :text "ab"}
                :min 2 :max 4 :lazy? false}

    ;; ONE bound is regal's EXACT repeat, `{2}`. It must carry :max, or it is
    ;; the same value as the unbounded `[:repeat "ab" 2 nil]` below and every
    ;; emitter renders one of the two wrongly.
    [:repeat "ab" 2]
    #:construct{:op :repeat :arg #:construct{:op :literal :text "ab"}
                :min 2 :max 2 :lazy? false}

    [:repeat "ab" 2 nil]
    #:construct{:op :repeat :arg #:construct{:op :literal :text "ab"}
                :min 2 :lazy? false}

    [:lazy-repeat "ab" 1 3]
    #:construct{:op :repeat :arg #:construct{:op :literal :text "ab"}
                :min 1 :max 3 :lazy? true}

    [:*? :word]
    #:construct{:op :* :args [#:construct{:op :token :token :word}] :lazy? true}))

(deftest an-unbounded-repeat-is-not-an-exact-one
  ;; `[:repeat x 3]` and `[:repeat x 3 nil]` used to normalize to the SAME value
  ;; — `:construct/max` absent — and `->regal` then projected that value back as
  ;; the one-bound form, which regal reads as EXACT. Every dialect therefore
  ;; emitted `{3}` for a construct the schema documents as unbounded.
  ;;
  ;; The emission half of this claim lives in dialect-test; this layer owns only
  ;; normalization and projection.
  (let [exact     (norm! [:repeat "ab" 3])
        unbounded (norm! [:repeat "ab" 3 nil])]
    (testing "normalize keeps them apart"
      (is (= 3 (:construct/max exact)))
      (is (not (contains? unbounded :construct/max)))
      (is (not= exact unbounded)))

    (testing "->regal projects each back to the spelling regal reads the same way"
      (is (= [:repeat "ab" 3]     (cc/->regal exact)))
      (is (= [:repeat "ab" 3 nil] (cc/->regal unbounded))))

    (testing "and an absent :max never projects to a bare one-bound form"
      (is (= 4 (count (cc/->regal unbounded)))
          "dropping the nil turns unbounded into exact"))))

(deftest lazy-spellings-differ-only-in-lazy?
  (are [greedy lazy op] (and (= false (:construct/lazy? (norm! greedy)))
                             (= true  (:construct/lazy? (norm! lazy)))
                             (= op (:construct/op (norm! greedy)))
                             (= op (:construct/op (norm! lazy))))
    [:* "a"] [:*? "a"] :*
    [:+ "a"] [:+? "a"] :+
    [:? "a"] [:?? "a"] :?))

(deftest an-already-normalized-construct-passes-through
  (let [c (norm! [:cat "a" [:alt "b" "c"]])]
    (is (= c (norm! c)))
    (is (r/ok? (norm c)))))

(deftest normalize-is-idempotent-over-generated-constructs
  (let [xs (mapcat #(mg/sample cs/Construct {:size 12 :seed %}) (range 6))]
    (is (every? #(= % (norm! %)) xs))))

(deftest every-generated-construct-normalizes-and-validates
  (let [xs (mapcat #(mg/sample cs/Construct {:size 12 :seed %}) (range 6))]
    (is (pos? (count xs)))
    (is (every? #(m/validate cs/Construct %) xs))
    (is (every? #(r/ok? (norm %)) xs))))

;;; =============================================================================
;;; Refusal — each rejection names its own reason
;;; =============================================================================

(deftest refuses-with-a-distinct-reason
  (are [form expected] (= expected (reason form))
    [:totally-made-up "x"] :construct/unknown-op
    [:cat]                 :construct/empty-args
    [:class]               :construct/empty-class
    [:class [\z \a]]       :construct/reversed-range
    [:class 42]            :construct/bad-class-entry
    [:repeat "a" 5 2]      :construct/inverted-repeat
    [:repeat "a" -1]       :construct/bad-repeat-bound
    42                     :construct/unrecognized
    nil                    :construct/unrecognized))

(deftest refusal-reasons-are-all-distinct
  (let [forms [[:totally-made-up "x"] [:cat] [:class] [:class [\z \a]]
               [:class 42] [:repeat "a" 5 2] [:repeat "a" -1] 42]]
    (is (= (count forms) (count (distinct (map reason forms))))
        "a shared reason cannot tell a caller which fence it hit")))

(deftest a-nested-refusal-propagates
  (is (= :construct/unknown-op (reason [:cat "a" [:alt "b" [:nope "c"]]])))
  (is (= :construct/reversed-range (reason [:cat "a" [:class [\z \a]]]))))

(deftest an-invalid-normalized-map-is-refused-not-repaired
  (is (= :construct/invalid (reason #:construct{:op :literal})))
  (is (= :construct/invalid (reason #:construct{:op :* :args [#:construct{:op :literal :text "a"}]})))
  (is (= :construct/invalid (reason #:construct{:op :class :negated? false :entries []}))))

;;; =============================================================================
;;; Projection — ->regal is a left inverse of normalize
;;; =============================================================================

(deftest round-trips-through-the-authored-form
  (let [xs (mapcat #(mg/sample cs/Construct {:size 12 :seed %}) (range 10))]
    (is (pos? (count xs)))
    (is (every? (fn [c] (= c (norm! (cc/->regal c)))) xs)
        "normalize(->regal(c)) must be c for every generated construct")))

(deftest projects-back-to-the-spelling-a-caller-wrote
  (are [form] (= form (cc/->regal (norm! form)))
    "abc"
    :digit
    [:cat "a" [:alt "b" "c"]]
    [:class [\a \z] \_ :digit]
    [:not [\a \z]]
    [:repeat "ab" 2 4]
    [:repeat "ab" 2]
    [:*? :word]
    [:capture [:+ :digit]]))

;;; =============================================================================
;;; Capability analysis
;;; =============================================================================

(deftest required-capabilities-of-known-shapes
  (are [form expected] (= expected (cc/required-capabilities (norm! form)))
    [:cat "a" "b"]            #{}
    [:class [\a \z]]          #{}
    [:class [\A \Z]]          #{}
    [:class [\0 \9]]          #{}
    [:+ :any]                 #{}
    [:lookahead "x"]          #{:lookaround}
    [:negative-lookbehind "x"] #{:lookaround}
    [:atomic "x"]             #{:atomic}
    [:*? "x"]                 #{:lazy}
    [:lazy-repeat "x" 1 2]    #{:lazy}
    [:+ :digit]               #{:perl-class}
    [:class :whitespace]      #{:perl-class}
    [:capture "x"]            #{:capture}
    [:cat :tab "x"]           #{:control-escape}
    [:class :newline]         #{:control-escape}
    ;; a range that crosses classes is ordered by locale collation, not by
    ;; code point — GNU grep rejects [A-a] and mis-answers [0-A]
    [:class [\A \a]]          #{:collation-range}
    [:class [\0 \A]]          #{:collation-range}
    [:not [\A \z]]            #{:collation-range}
    [:class [\a \z] [\A \Z]]  #{}
    [:cat [:atomic "a"] [:*? :digit]] #{:atomic :lazy :perl-class}
    [:capture [:cat :tab :digit]]     #{:capture :control-escape :perl-class}))

(deftest capability-demand-is-collected-from-every-depth
  (is (= #{:lookaround :capture}
         (cc/required-capabilities
          (norm! [:cat "a" [:alt "b" [:capture [:+ [:lookahead "deep"]]]]])))
      "a demand nested four levels down must still be seen, and the :capture on
       the way down must not be swallowed by it"))

(st/deftrifecta-from-schema required-capabilities
  hive-system.pattern.construct.core/required-capabilities
  ;; `(m/schema ...)`, not the raw form: hive-schemas.test re-schemas a form
  ;; through the DEFAULT registry, which does not carry Construct's local
  ;; `:registry` — so the raw form resolves ::construct to nil.
  {:in (m/schema cs/Construct)
   :out cs/Capabilities
   :rel (fn [c out] (= out (capabilities-via-walk c)))
   :mutation false
   :num-tests 200})

;;; =============================================================================
;;; Mutation — each mutant must be caught by the tests above
;;; =============================================================================

(defn- capability-assertions []
  (doseq [[form expected] {[:cat "a" "b"]                    #{}
                           [:lookahead "x"]                  #{:lookaround}
                           [:atomic "x"]                     #{:atomic}
                           [:*? "x"]                         #{:lazy}
                           [:+ :digit]                       #{:perl-class}
                           [:class :whitespace]              #{:perl-class}
                           [:lazy-repeat "x" 1 2]            #{:lazy}
                           [:cat "a" [:alt "b" [:lookahead "deep"]]] #{:lookaround}
                           [:cat [:atomic "a"] [:*? :digit]] #{:atomic :lazy :perl-class}}]
    (is (= expected (cc/required-capabilities (norm! form)))
        (str "required-capabilities " form))))

(mut/deftest-mutations required-capabilities-mutants-are-caught
  hive-system.pattern.construct.core/required-capabilities
  [["ignores-children"
    (fn [c] (node-demand c))]
   ["ignores-own-demand"
    (fn [c] (into #{} (mapcat cc/required-capabilities)
                  (cond-> (vec (:construct/args c))
                    (:construct/arg c) (conj (:construct/arg c)))))]
   ["blind-to-lazy"
    (fn [c] (disj (capabilities-via-walk c) :lazy))]
   ["blind-to-class-entries"
    (fn [c] (if (= :class (:construct/op c)) #{} (capabilities-via-walk c)))]
   ["always-empty"
    (fn [_] #{})]
   ["always-everything"
    (fn [_] #{:lookaround :atomic :lazy :perl-class})]]
  capability-assertions)

(defn- normalize-assertions []
  (is (= #:construct{:op :literal :text "abc"} (norm! "abc")))
  (is (= true (:construct/lazy? (norm! [:*? "a"]))))
  (is (= false (:construct/lazy? (norm! [:* "a"]))))
  (is (= true (:construct/negated? (norm! [:not [\a \z]]))))
  (is (= false (:construct/negated? (norm! [:class [\a \z]]))))
  (is (= :construct/unknown-op (reason [:totally-made-up "x"])))
  (is (= :construct/empty-args (reason [:cat])))
  (is (= :construct/reversed-range (reason [:class [\z \a]])))
  (is (= :construct/inverted-repeat (reason [:repeat "a" 5 2]))))

(mut/deftest-mutations normalize-mutants-are-caught
  hive-system.pattern.construct.core/normalize
  [["lazy-collapses-to-greedy"
    (fn [form] (let [res (@#'cc/normalize form)]
                 (if (r/ok? res)
                   (r/ok (clojure.walk/postwalk
                          (fn [x] (if (and (map? x) (contains? x :construct/lazy?))
                                    (assoc x :construct/lazy? false) x))
                          (:ok res)))
                   res)))]
   ["negation-is-dropped"
    (fn [form] (let [res (@#'cc/normalize form)]
                 (if (r/ok? res)
                   (r/ok (clojure.walk/postwalk
                          (fn [x] (if (and (map? x) (contains? x :construct/negated?))
                                    (assoc x :construct/negated? false) x))
                          (:ok res)))
                   res)))]
   ["unknown-op-is-guessed-as-cat"
    (fn [form] (let [res (@#'cc/normalize form)]
                 (if (r/ok? res) res
                     (if (vector? form)
                       (r/ok #:construct{:op :cat :args [#:construct{:op :literal :text (str form)}]})
                       res))))]]
  normalize-assertions)
