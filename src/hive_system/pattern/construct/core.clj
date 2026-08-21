(ns hive-system.pattern.construct.core
  "PROMOTE layer: lift authored regal syntax into a validated Construct, project
   it back, and say what a Construct requires of its target.

   Everything here is pure and total — a malformed form yields a Result
   describing why, never an exception and never a silent repair.

     (normalize [:cat \"a\" [:alt \"b\" \"c\"]])  => {:ok {…}}
     (->regal   normalized)                    => [:cat \"a\" [:alt \"b\" \"c\"]]
     (required-capabilities normalized)        => #{}

   `required-capabilities` is what makes dialect support a set-difference
   decidable BEFORE emission rather than a `try`/`catch` around a compile."
  (:require [hive-dsl.result :as r]
            [hive-system.pattern.construct.schema :as cs]
            [malli.core :as m]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

;;; =============================================================================
;;; Vocabulary — the authored form's surface, as data
;;; =============================================================================

(def ^:private tokens
  (into #{} (rest cs/Token)))

(def ^:private quantifier-ops
  "Authored quantifier head -> [op lazy?]. The lazy spellings are regal's."
  {:*  [:* false] :*? [:* true]
   :+  [:+ false] :+? [:+ true]
   :?  [:? false] :?? [:? true]})

(def ^:private nary-ops
  (into #{} (rest cs/NAryOp)))

(def ^:private token->capability
  "A token that only exists in a Perl-ish dialect."
  (zipmap [:digit :non-digit :word :non-word :whitespace :non-whitespace
           :vertical-whitespace :line-break]
          (repeat :perl-class)))

(def ^:private op->capability
  {:lookahead           :lookaround
   :negative-lookahead  :lookaround
   :lookbehind          :lookaround
   :negative-lookbehind :lookaround
   :atomic              :atomic})

;;; =============================================================================
;;; Normalize — authored form -> Construct
;;; =============================================================================

(declare normalize)

(defn- normalize-all
  "Result<vector<Construct>> for FORMS, failing on the first that will not
   normalize. Refuses an empty argument list: `[:cat]` names no language."
  [op forms]
  (if (empty? forms)
    (r/err :construct/empty-args {:op op})
    (reduce (fn [acc form]
              (r/let-ok [done acc
                         one  (normalize form)]
                        (r/ok (conj done one))))
            (r/ok [])
            forms)))

(defn- normalize-class-entry
  "Result<ClassEntry>. A range arrives as a 2-vector of characters."
  [entry]
  (cond
    (char? entry)    (r/ok entry)
    (tokens entry)   (r/ok entry)
    (and (vector? entry) (= 2 (count entry)) (every? char? entry))
    (if (<= (int (first entry)) (int (second entry)))
      (r/ok entry)
      (r/err :construct/reversed-range {:range entry}))
    :else            (r/err :construct/bad-class-entry {:entry entry})))

(defn- normalize-class
  [op entries]
  (if (empty? entries)
    (r/err :construct/empty-class {:op op})
    (r/let-ok [done (reduce (fn [acc e]
                              (r/let-ok [xs acc, x (normalize-class-entry e)]
                                        (r/ok (conj xs x))))
                            (r/ok [])
                            entries)]
              (r/ok #:construct{:op :class
                                :negated? (= op :not)
                                :entries done}))))

(defn- normalize-repeat
  [[_ form & bounds]]
  (let [[lo hi] bounds]
    (cond
      (not (and (int? lo) (nat-int? lo)))
      (r/err :construct/bad-repeat-bound {:bound lo})

      (and (some? hi) (not (nat-int? hi)))
      (r/err :construct/bad-repeat-bound {:bound hi})

      (and (some? hi) (> lo hi))
      (r/err :construct/inverted-repeat {:min lo :max hi})

      :else
      (r/let-ok [arg (normalize form)]
                (r/ok (cond-> #:construct{:op :repeat :arg arg :min lo :lazy? false}
                        (some? hi) (assoc :construct/max hi)))))))

(defn- normalize-vector
  [[op & args :as form]]
  (cond
    (contains? quantifier-ops op)
    (let [[base lazy?] (quantifier-ops op)]
      (r/let-ok [xs (normalize-all op args)]
                (r/ok #:construct{:op base :args xs :lazy? lazy?})))

    (#{:class :not} op)      (normalize-class op args)
    (= :repeat op)           (normalize-repeat form)
    (= :lazy-repeat op)      (r/let-ok [c (normalize-repeat (cons :repeat args))]
                                       (r/ok (assoc c :construct/lazy? true)))
    (nary-ops op)            (r/let-ok [xs (normalize-all op args)]
                                       (r/ok #:construct{:op op :args xs}))
    :else                    (r/err :construct/unknown-op
                                    {:op op :form form :known (sort (into nary-ops (keys quantifier-ops)))})))

(defn normalize
  "Result<Construct> for FORM, which may be regal's authored syntax or an
   already-normalized Construct.

   Total: every rejection names its reason (`:construct/unknown-op`,
   `:construct/empty-args`, `:construct/reversed-range`, …) instead of throwing
   or guessing."
  [form]
  (cond
    (string? form)  (r/ok #:construct{:op :literal :text form})
    (char? form)    (r/ok #:construct{:op :literal :text (str form)})
    (tokens form)   (r/ok #:construct{:op :token :token form})

    (and (map? form) (contains? form :construct/op))
    (if (m/validate cs/Construct form)
      (r/ok form)
      (r/err :construct/invalid {:form form
                                 :explain (m/explain cs/Construct form)}))

    (and (vector? form) (seq form)) (normalize-vector form)
    :else (r/err :construct/unrecognized {:form form})))

(m/=> normalize [:=> [:cat cs/RawConstruct] :any])

;;; =============================================================================
;;; Project back — Construct -> authored regal form
;;; =============================================================================

(def ^:private lazy-spelling
  {[:* true] :*? [:+ true] :+? [:? true] :??})

(defn ->regal
  "The regal form for CONSTRUCT. Inverse of `normalize` up to the authored
   form's redundancy (`[:not …]` normalizes into a negated `:class` and comes
   back as `[:not …]`)."
  [{:construct/keys [op text token args entries negated? arg min max lazy?]
    :as construct}]
  (case op
    :literal text
    :token   token
    :class   (into [(if negated? :not :class)] entries)
    :repeat  (cond-> [(if lazy? :lazy-repeat :repeat) (->regal arg) min]
               (some? max) (conj max))
    (:* :+ :?) (into [(get lazy-spelling [op (boolean lazy?)] op)] (map ->regal) args)
    (into [op] (map ->regal) args)))

(m/=> ->regal [:=> [:cat cs/Construct] :any])

;;; =============================================================================
;;; Capability analysis
;;; =============================================================================

(defn- sub-constructs
  "Immediate children of CONSTRUCT."
  [{:construct/keys [args arg]}]
  (cond-> (vec args) (some? arg) (conj arg)))

(defn required-capabilities
  "The set of Capabilities CONSTRUCT needs of its target dialect.

   A dialect supports it exactly when this set is a subset of the dialect's
   own — no compile, no exception, decided from the shape alone."
  [{:construct/keys [op token entries lazy?] :as construct}]
  (into (cond-> #{}
          (op->capability op)              (conj (op->capability op))
          (and lazy? (not= op :literal))   (conj :lazy)
          (token->capability token)        (conj (token->capability token))
          (seq entries)                    (into (keep token->capability entries)))
        (mapcat required-capabilities)
        (sub-constructs construct)))

(m/=> required-capabilities [:=> [:cat cs/Construct] cs/Capabilities])
