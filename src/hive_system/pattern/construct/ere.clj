(ns hive-system.pattern.construct.ere
  "POSIX ERE — the dialect `grep -E` speaks, rendered without regal.

   ## Why this emitter is hand-written

   regal has no ERE flavor, and its `:java`/`:ecma` output is not ERE: a nested
   alternation comes out as `(?:a|b)`, which POSIX ERE has no syntax for. So
   this is the one dialect that renders from the Construct directly. It is
   small because ERE is small — literals, classes, alternation, greedy
   quantifiers, anchors, and one grouping syntax.

   ## Why the gate matters more here than anywhere else

   `rg` rejects what it cannot do: an unsupported pattern exits 2 with a
   message. GNU grep 3.11 does not. Measured:

     grep -E '\\d+'      matches a literal `d`  — no warning, exit 0
     grep -E '(?:a|b)c'  matches `abc`          — a warning, exit 0
     grep -E 'ab*?'      greedy                 — silently not lazy
     grep -E '(?=x)'     never matches          — a warning, exit 1

   Every one of those is a DIFFERENT LANGUAGE that still runs and still returns
   hits. For rg the capability gate converts a stderr parse into data; for grep
   it converts a silently wrong answer into a named refusal, which is the
   stronger reason the gate exists at all.

   ## What `:posix-ere` therefore provides: nothing

   Its capability set is empty. `\\d` must be written `[:class [\\0 \\9]]`,
   which renders `[0-9]`; a tab must be a literal tab inside a `:literal`, not
   `:tab`; a `:capture` is refused because ERE's only group is a capturing one,
   so any structural group this emitter needs would shift the very index
   `:match/groups` promises.

   Everything the gate lets through is rendered exactly, or not at all."
  (:require [clojure.string :as str]
            [hive-dsl.result :as r]
            [hive-system.pattern.construct.dialect :as dial]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

;;; =============================================================================
;;; The profile
;;; =============================================================================

(def posix-ere
  "POSIX Extended Regular Expressions, as accepted by `grep -E`.

   `:dialect/flavor` is `:posix-ere` and names THIS emitter rather than a regal
   flavor — regal has none to name."
  #:dialect{:id :posix-ere
            :capabilities #{}
            :flavor :posix-ere
            :doc "POSIX ERE — the dialect of `grep -E`. No \\d, no lazy, no lookaround, no non-capturing group."})

;;; =============================================================================
;;; Escaping
;;; =============================================================================

(def ^:private meta-chars
  "Characters ERE reads as syntax outside a bracket expression."
  #{\. \[ \] \\ \( \) \* \+ \? \{ \} \| \^ \$})

(defn- escape-literal
  "TEXT as an ERE literal: every metacharacter backslash-escaped."
  [text]
  (str/escape text (into {} (map (juxt identity #(str \\ %))) meta-chars)))

(defn- escape-class-char
  "CH inside a bracket expression.

   Bracket expressions have their own, much smaller, syntax: only `]`, `^`, `-`
   and `\\` can be misread, and POSIX has no escape inside them. Position is
   the only tool — `]` first, `-` last — so `entries` orders them rather than
   escaping them."
  [ch]
  (str ch))

;;; =============================================================================
;;; Rendering
;;; =============================================================================

(def ^:private token->ere
  "The only tokens ERE can spell. Every other token demands a capability
   `:posix-ere` does not provide, so the gate refuses it before this is read."
  {:any "." :start "^" :end "$"})

(declare render)

(defn- atomic?
  "Can CONSTRUCT carry a quantifier without being grouped first?

   ERE quantifies the single preceding atom, so `ab*` is `a` then `b*`. Only a
   one-character literal, a bracket expression and a token are atoms."
  [{:construct/keys [op text]}]
  (or (= op :class)
      (= op :token)
      (and (= op :literal) (= 1 (count text)))))

(defn- as-atom
  "CONSTRUCT rendered so a quantifier may follow it, grouping when it must.

   The group is `(…)`, which also captures — harmless precisely because
   `:capture` is refused, so nothing downstream is counting groups."
  [construct]
  (let [s (render construct)]
    (if (atomic? construct) s (str "(" s ")"))))

(defn- render-class
  [{:construct/keys [negated? entries]}]
  (let [ch?     (fn [e] (char? e))
        range?  (fn [e] (and (vector? e) (= 2 (count e))))
        ;; `]` must lead and `-` must trail, or the bracket expression ends
        ;; early or spells a range. There is no escape inside one to fall
        ;; back on.
        chars   (filter ch? entries)
        bracket (some #{\]} chars)
        dash    (some #{\-} chars)
        others  (remove #{\] \-} chars)
        ranges  (filter range? entries)]
    (str "["
         (when negated? "^")
         (when bracket "]")
         (str/join (map escape-class-char others))
         (str/join (map (fn [[lo hi]] (str lo "-" hi)) ranges))
         (when dash "-")
         "]")))

(defn- render-repeat
  [{:construct/keys [arg min max]}]
  (str (as-atom arg)
       (cond
         (and (= min 0) (nil? max)) "*"
         (and (= min 1) (nil? max)) "+"
         (nil? max)                 (str "{" min ",}")
         (= min max)                (str "{" min "}")
         :else                      (str "{" min "," max "}"))))

(defn- render
  "CONSTRUCT as ERE source. Total over everything the gate admits."
  [{:construct/keys [op text token args] :as construct}]
  (case op
    :literal (escape-literal text)
    :token   (token->ere token)
    :class   (render-class construct)
    :cat     (str/join (map (fn [c]
                              ;; alternation binds looser than concatenation
                              (if (= :alt (:construct/op c))
                                (str "(" (render c) ")")
                                (render c)))
                            args))
    :alt     (str/join "|" (map render args))
    :repeat  (render-repeat construct)
    (:* :+ :?) (str (as-atom (first args)) (name op))))

;;; =============================================================================
;;; The emitter
;;; =============================================================================

(defrecord EREEmitter [profile]
  dial/IConstructEmitter
  (dialect [_] profile)
  (-render [_ construct]
    (r/ok (render construct))))

(defn make-emitter
  "An emitter rendering POSIX ERE for PROFILE."
  ([] (make-emitter posix-ere))
  ([profile] (->EREEmitter profile)))

(defn register-built-in!
  "Register the `:posix-ere` emitter. Returns the Result."
  []
  (dial/register-emitter! (make-emitter)))

(def ^:private bootstrap
  "Registers the emitter on load.

   `def`, not `defonce`, for the reason `construct.regal/bootstrap` gives:
   reloading recompiles `EREEmitter`, and an instance minted before the
   recompile no longer satisfies the protocol."
  (register-built-in!))
