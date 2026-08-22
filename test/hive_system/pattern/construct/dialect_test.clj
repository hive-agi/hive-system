(ns hive-system.pattern.construct.dialect-test
  "The substitutability contract: a dialect REFUSES what it cannot express.

   The refusal-completeness test is the executable form of that law — for every
   registered dialect and every capability it does not declare, emitting a
   witness construct that needs it must fail, naming the capability."
  (:require [clojure.test :refer [deftest is testing are use-fixtures]]
            [hive-dsl.result :as r]
            [hive-system.pattern.construct.core :as cc]
            [hive-system.pattern.construct.dialect :as dial]
            [hive-system.pattern.construct.regal :as creg]
            [hive-system.pattern.construct.schema :as cs]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(def ^:private all-capabilities (set (rest cs/Capability)))

(def ^:private witness
  "A construct that needs exactly the named capability. Every Capability has
   one — a capability with no witness would make its refusal test vacuous."
  {:lookaround      [:lookahead "x"]
   :atomic          [:atomic "x"]
   :lazy            [:*? "x"]
   :perl-class      [:+ :digit]
   :capture         [:capture "x"]
   :control-escape  [:cat :tab "x"]
   :collation-range [:class [\A \a]]})

(defn- norm! [form] (:ok (cc/normalize form)))

(defn- restore-registry
  "The emitter registry is process-wide; a test that registers must put it back."
  [f]
  (let [before (dial/registered-emitters)]
    (try (f)
         (finally
           (doseq [id (keys (dial/registered-emitters))] (dial/unregister-emitter! id))
           (doseq [e (vals before)] (dial/register-emitter! e))))))

(use-fixtures :each restore-registry)

;;; =============================================================================
;;; Every capability has a witness — the non-vacuity guard
;;; =============================================================================

(deftest every-capability-has-a-witness
  (is (= all-capabilities (set (keys witness)))
      "a capability with no witness construct cannot be refusal-tested")
  (doseq [[cap form] witness]
    (is (contains? (cc/required-capabilities (norm! form)) cap)
        (str "witness for " cap " must actually require it"))))

;;; =============================================================================
;;; The gate
;;; =============================================================================

(deftest missing-capabilities-is-a-set-difference
  (are [dialect form expected] (= expected (set (dial/missing-capabilities dialect (norm! form))))
    creg/java [:lookahead "x"]  #{}
    creg/java [:atomic "x"]     #{}
    creg/ecma [:lookahead "x"]  #{}
    creg/ecma [:atomic "x"]     #{:atomic}
    creg/re2  [:lookahead "x"]  #{:lookaround}
    creg/re2  [:atomic "x"]     #{:atomic}
    creg/re2  [:*? "x"]         #{}
    creg/re2  [:cat [:atomic "a"] [:lookahead "b"]] #{:atomic :lookaround}))

(deftest supports?-agrees-with-missing-capabilities
  (doseq [d [creg/java creg/ecma creg/re2]
          f (vals witness)]
    (let [c (norm! f)]
      (is (= (empty? (dial/missing-capabilities d c)) (dial/supports? d c))))))

(deftest the-gate-decides-without-compiling
  (testing "support is answered from the shape, so an unsupported construct never reaches a compiler"
    (is (false? (dial/supports? creg/re2 (norm! [:lookahead "x"]))))
    (is (true?  (dial/supports? creg/java (norm! [:lookahead "x"]))))))

;;; =============================================================================
;;; Refusal completeness — the law, made executable
;;; =============================================================================

(deftest every-dialect-refuses-every-capability-it-lacks
  (let [cases (for [[id emitter] (dial/registered-emitters)
                    :let [d (dial/dialect emitter)]
                    cap (sort (remove (:dialect/capabilities d) all-capabilities))]
                [id cap])]
    (is (seq cases) "no dialect lacks anything — this test would be vacuous")
    (doseq [[id cap] cases]
      (let [res (r/let-ok [c (cc/normalize (witness cap))] (dial/emit-as id c))]
        (is (r/err? res) (str id " must refuse " cap))
        (is (= :construct/unsupported (:error res)))
        (is (contains? (set (:missing res)) cap)
            (str id " must NAME " cap " as missing, not fail generically"))))))

(deftest a-supported-construct-is-emitted-not-refused
  (doseq [[id emitter] (dial/registered-emitters)
          :let [d (dial/dialect emitter)]
          cap (:dialect/capabilities d)]
    (let [res (r/let-ok [c (cc/normalize (witness cap))] (dial/emit-as id c))]
      (is (r/ok? res) (str id " declares " cap " and must emit it"))
      (is (string? (:ok res))))))

(deftest refusal-reports-what-the-dialect-does-provide
  (let [res (r/let-ok [c (cc/normalize [:lookahead "x"])] (dial/emit-as :re2 c))]
    (is (= :re2 (:dialect res)))
    (is (= [:lookaround] (vec (:missing res))))
    (is (= [:capture :collation-range :control-escape :lazy :perl-class]
           (vec (:provides res)))
        "a refusal that does not say what IS available is not actionable")))

;;; =============================================================================
;;; LSP — an implementation cannot opt out of the gate
;;; =============================================================================

(defrecord RogueEmitter [profile]
  dial/IConstructEmitter
  (dialect [_] profile)
  (-render [_ _] (r/ok "I RENDER ANYTHING")))

(deftest an-emitter-cannot-bypass-the-gate
  (let [profile #:dialect{:id :rogue :capabilities #{} :flavor :java9}
        rogue   (->RogueEmitter profile)]
    (dial/register-emitter! rogue)
    (testing "the rogue would happily render a lookahead, but emit never asks it to"
      (is (= (r/ok "I RENDER ANYTHING") (dial/-render rogue (norm! [:lookahead "x"]))))
      (let [res (dial/emit rogue (norm! [:lookahead "x"]))]
        (is (r/err? res))
        (is (= :construct/unsupported (:error res)))))
    (testing "what it declares nothing about, it still renders"
      (is (r/ok? (dial/emit rogue (norm! [:cat "a" "b"])))))))

;;; =============================================================================
;;; DIP — the swap point
;;; =============================================================================

(deftest a-new-dialect-needs-no-change-above
  (let [strict #:dialect{:id :strict-subset :capabilities #{} :flavor :ecma
                         :doc "literals, classes and greedy quantifiers only"}]
    (dial/register-emitter! (creg/make-emitter strict))
    (is (contains? (dial/registered-emitters) :strict-subset))
    (is (r/ok? (dial/emit-as :strict-subset (norm! [:cat "a" [:alt "b" "c"]]))))
    (is (r/err? (dial/emit-as :strict-subset (norm! [:*? "x"]))))
    (testing "registering a dialect does not disturb the others"
      (is (r/ok? (dial/emit-as :java (norm! [:*? "x"])))))))

(deftest an-invalid-profile-is-refused-not-stored
  (let [bad (->RogueEmitter {:dialect/id :bad})]
    (is (r/err? (dial/register-emitter! bad)))
    (is (not (contains? (dial/registered-emitters) :bad))
        "a profile that fails the Dialect schema must never reach the registry")))

(deftest an-unknown-dialect-is-an-error-not-a-default
  (let [res (dial/emit-as :klingon (norm! "a"))]
    (is (r/err? res))
    (is (= :dialect/unknown (:error res)))))

;;; =============================================================================
;;; What the shipped dialects actually emit
;;; =============================================================================

(deftest shipped-dialects-emit-known-strings
  (are [id form expected] (= (r/ok expected) (dial/emit-as id (norm! form)))
    :java [:cat :start [:+ :digit] :end]  "^\\d+$"
    :java [:cat "a" [:alt "b" "c"]]       "a(?:b|c)"
    :java [:atomic "ab"]                  "(?>ab)"
    :java [:class [\a \z] \_]             "[a-z_]"
    :java [:not [\a \z]]                  "[^a-z]"
    :java [:repeat "ab" 2 4]              "(?:ab){2,4}"
    :java "a.b*c"                         "a\\.b\\*c"
    :ecma [:cat "a" [:alt "b" "c"]]       "a(?:b|c)"
    :re2  [:*? :word]                     "\\w*?"))

(deftest an-unbounded-repeat-emits-differently-from-an-exact-one
  ;; The emission half of core-test/an-unbounded-repeat-is-not-an-exact-one.
  (let [exact     (norm! [:repeat "ab" 3])
        unbounded (norm! [:repeat "ab" 3 nil])]
    (are [dialect-id exact-expr unbounded-expr]
         (and (= exact-expr     (:ok (dial/emit-as dialect-id exact)))
              (= unbounded-expr (:ok (dial/emit-as dialect-id unbounded))))
      :java "(?:ab){3}" "(?:ab){3,}"
      :ecma "(?:ab){3}" "(?:ab){3,}"
      :re2  "(?:ab){3}" "(?:ab){3,}")

    (testing "and the JVM agrees the two languages differ"
      (let [e (re-pattern (:ok (dial/emit-as :java exact)))
            u (re-pattern (:ok (dial/emit-as :java unbounded)))]
        (is (re-matches e "ababab"))
        (is (nil? (re-matches e "abababab")) "exact must not accept a fourth")
        (is (re-matches u "ababab"))
        (is (re-matches u "abababab") "unbounded must")))))
