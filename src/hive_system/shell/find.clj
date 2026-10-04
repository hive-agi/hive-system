(ns hive-system.shell.find
  "`find` as data: a query map in, the argv that runs it out.

   A query is

     {:roots    [\"src\" \"test\"]   ; default [\".\"]
      :follow?  false              ; -L
      :xdev?    true               ; -xdev
      :maxdepth 3 :mindepth 1
      :expr     [:or [:and [:name \"node_modules\"] [:prune]]
                     [:and [:type :f] [:name \"*.clj\"] [:print]]]}

   and an expression is one of

     [:name g] [:iname g] [:path g] [:ipath g]   glob tests
     [:type t]                                    t in f d l p s b c
     [:size s] [:newer path] [:mtime n] [:mmin n] [:empty] [:true] [:false]
     [:prune] [:print] [:print0]                  actions
     [:and e ...] [:or e ...] [:not e]

   The grammar has no action that runs or writes anything (`-exec`, `-delete`,
   `-fprint`), so every argv `argv` builds is a read-only walk.
   `read-only-argv?` answers the same question for an argv from anywhere."
  (:require [clojure.string :as str]
            [hive-dsl.result :as r]
            [malli.core :as m]
            [malli.error :as me]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

;;; =============================================================================
;;; Value objects
;;; =============================================================================

(def file-types #{:f :d :l :p :s :b :c})

(def Expr
  "A find expression."
  [:schema
   {:registry
    {::expr [:multi {:dispatch first}
             [:name   [:tuple [:= :name] :string]]
             [:iname  [:tuple [:= :iname] :string]]
             [:path   [:tuple [:= :path] :string]]
             [:ipath  [:tuple [:= :ipath] :string]]
             [:type   [:tuple [:= :type] (into [:enum] file-types)]]
             [:size   [:tuple [:= :size] [:re {:gen/elements ["+100M" "-1k" "20" "+2G"]} #"^[+-]?\d+[bcwkMG]?$"]]]
             [:newer  [:tuple [:= :newer] [:string {:min 1}]]]
             [:mtime  [:tuple [:= :mtime] :int]]
             [:mmin   [:tuple [:= :mmin] :int]]
             [:empty  [:tuple [:= :empty]]]
             [:true   [:tuple [:= :true]]]
             [:false  [:tuple [:= :false]]]
             [:prune  [:tuple [:= :prune]]]
             [:print  [:tuple [:= :print]]]
             [:print0 [:tuple [:= :print0]]]
             [:and    [:cat [:= :and] [:+ [:schema [:ref ::expr]]]]]
             [:or     [:cat [:= :or] [:+ [:schema [:ref ::expr]]]]]
             [:not    [:tuple [:= :not] [:ref ::expr]]]]}}
   ::expr])

(def Query
  "A find invocation."
  [:map {:closed true}
   [:roots    {:optional true} [:vector {:min 1} [:string {:min 1}]]]
   [:follow?  {:optional true} :boolean]
   [:xdev?    {:optional true} :boolean]
   [:maxdepth {:optional true} nat-int?]
   [:mindepth {:optional true} nat-int?]
   [:expr     {:optional true} Expr]])

(def write-actions
  "The find primaries that run a command or write a file."
  #{"-exec" "-execdir" "-ok" "-okdir" "-delete" "-fprint" "-fprint0" "-fprintf" "-fls"})

;;; =============================================================================
;;; Promote: expression -> argv tokens (pure)
;;; =============================================================================

(declare expr-argv)

(defn- grouped
  "`e`'s tokens, parenthesised when its operator is in `ops`, so it binds as
   one operand."
  [ops e]
  (let [ts (expr-argv e)]
    (if (ops (first e)) (into ["("] (conj ts ")")) ts)))

(defn expr-argv
  "The argv tokens of expression `e`. Pure; `e` must satisfy `Expr`."
  [e]
  (let [[op & args] e]
    (case op
      (:name :iname :path :ipath :size :newer) [(str "-" (name op)) (first args)]
      :type                                    ["-type" (name (first args))]
      (:mtime :mmin)                           [(str "-" (name op)) (str (first args))]
      (:empty :true :false :prune :print :print0) [(str "-" (name op))]
      :not                                     (into ["!"] (grouped #{:and :or} (first args)))
      :and                                     (vec (mapcat identity (interpose ["-a"] (map #(grouped #{:or} %) args))))
      :or                                      (vec (mapcat identity (interpose ["-o"] (map expr-argv args)))))))

(defn query-argv
  "The argv `query` runs, program name first. Pure; `query` must satisfy `Query`."
  [{:keys [roots follow? xdev? maxdepth mindepth expr]}]
  (cond-> ["find"]
    follow?          (conj "-L")
    true             (into (or roots ["."]))
    xdev?            (conj "-xdev")
    (some? maxdepth) (into ["-maxdepth" (str maxdepth)])
    (some? mindepth) (into ["-mindepth" (str mindepth)])
    expr             (into (expr-argv expr))))

;;; =============================================================================
;;; Facade
;;; =============================================================================

(defn argv
  "Result<vector<string>>: the argv that runs `query`, or an error naming what
   in `query` is not a find invocation."
  [query]
  (if (m/validate Query query)
    (r/ok (query-argv query))
    (r/err :find/invalid-query {:explain (me/humanize (m/explain Query query))})))

(defn read-only-argv?
  "True when the find `argv` runs no command and writes no file: none of
   `write-actions` appears in it. Says nothing about what a pipe downstream
   of it does."
  [argv]
  (not-any? write-actions argv))

;;; =============================================================================
;;; Contracts
;;; =============================================================================

(m/=> expr-argv [:=> [:cat Expr] [:vector :string]])
(m/=> query-argv [:=> [:cat Query] [:vector :string]])
(m/=> read-only-argv? [:=> [:cat [:sequential :string]] :boolean])
