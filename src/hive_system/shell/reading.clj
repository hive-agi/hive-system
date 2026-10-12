(ns hive-system.shell.reading
  "Reading an argv a pattern-taking CLI was given: the inverse of
   `hive-system.shell.search/argv`.

   `search/argv` goes Construct -> argv. `read-argv` goes argv -> `Reading`:
   which operand is the pattern, which are paths, whether the walk recurses,
   and which globs or types narrow it. A `Grammar` states, as data, the facts
   about one program's command line that this needs.

   Pure and total. Nothing is spawned and no path is resolved."
  (:require [clojure.string :as str]
            [hive-dsl.result :as r]
            [malli.core :as m]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

;;; =============================================================================
;;; Value objects
;;; =============================================================================

(def Grammar
  "How one program's argv is read.

   :grammar/id             the `shell.search` ToolId this grammar reads
   :grammar/heads          argv[0] basenames that run this program
   :grammar/short-values   short flags (one char each) that take a value
   :grammar/long-values    long flags that take a value as the NEXT argument
   :grammar/pattern-flags  flags whose value is the pattern, or a file of them
   :grammar/recursive      :always, or the flags that turn recursion on
   :grammar/glob-flags     flags whose value is a file-name glob to keep
   :grammar/type-flags     flags whose value is a named file type to keep"
  [:map {:closed true}
   [:grammar/id :keyword]
   [:grammar/heads [:set :string]]
   [:grammar/short-values [:set char?]]
   [:grammar/long-values [:set :string]]
   [:grammar/pattern-flags [:set :string]]
   [:grammar/recursive [:or [:= :always] [:set :string]]]
   [:grammar/glob-flags [:set :string]]
   [:grammar/type-flags [:set :string]]])

(def Reading
  "What an argv says, by role.

   :reading/tool        the Grammar id that read it
   :reading/patterns    the pattern operands (flag-introduced or positional)
   :reading/paths       the path operands; empty means the working directory
   :reading/recursive?  whether the program walks directories
   :reading/globs       file-name globs the search is narrowed to
   :reading/types       named file types the search is narrowed to"
  [:map {:closed true}
   [:reading/tool :keyword]
   [:reading/patterns [:vector :string]]
   [:reading/paths [:vector :string]]
   [:reading/recursive? :boolean]
   [:reading/globs [:vector :string]]
   [:reading/types [:vector :string]]])

;;; =============================================================================
;;; Profiles
;;; =============================================================================

(def grep
  #:grammar{:id :grep
            :heads #{"grep" "egrep" "fgrep" "rgrep"}
            :short-values #{\e \f \A \B \C \m \d \D}
            :long-values #{"--regexp" "--file" "--include" "--exclude"
                           "--exclude-dir" "--exclude-from" "--max-count"
                           "--after-context" "--before-context" "--context"
                           "--label" "--devices" "--directories" "--binary-files"}
            :pattern-flags #{"-e" "--regexp" "-f" "--file"}
            :recursive #{"-r" "-R" "--recursive" "--dereference-recursive"}
            :glob-flags #{"--include"}
            :type-flags #{}})

(def ripgrep
  #:grammar{:id :rg
            :heads #{"rg" "ripgrep"}
            :short-values #{\e \f \g \t \T \A \B \C \m \j \M \d \E \r}
            :long-values #{"--regexp" "--file" "--glob" "--iglob" "--type"
                           "--type-not" "--type-add" "--max-count" "--max-depth"
                           "--after-context" "--before-context" "--context"
                           "--threads" "--max-columns" "--encoding" "--replace"
                           "--sort" "--sortr" "--color" "--colors" "--engine"
                           "--max-filesize" "--path-separator" "--pre"
                           "--pre-glob" "--ignore-file" "--field-match-separator"
                           "--field-context-separator" "--context-separator"}
            :pattern-flags #{"-e" "--regexp" "-f" "--file"}
            :recursive :always
            :glob-flags #{"-g" "--glob" "--iglob"}
            :type-flags #{"-t" "--type"}})

(def built-in
  "Every grammar this namespace ships."
  [grep ripgrep])

;;; =============================================================================
;;; Registry
;;; =============================================================================

(defonce ^:private grammars* (atom {}))

(defn register!
  "Register GRAMMAR under its id, replacing any prior one. Result<Grammar>."
  [grammar]
  (if (m/validate Grammar grammar)
    (do (swap! grammars* assoc (:grammar/id grammar) grammar)
        (r/ok grammar))
    (r/err :reading/invalid-grammar {:grammar grammar
                                     :explain (m/explain Grammar grammar)})))

(defn unregister!
  "Drop the grammar registered under ID. Returns it, or nil."
  [id]
  (let [g (get @grammars* id)]
    (swap! grammars* dissoc id)
    g))

(defn registered
  "Snapshot of {grammar-id -> Grammar}."
  []
  @grammars*)

(defn grammar-for
  "The registered Grammar whose heads include the basename of HEAD, or nil."
  [head]
  (when (string? head)
    (let [base (subs head (inc (or (str/last-index-of head "/") -1)))]
      (some (fn [g] (when (contains? (:grammar/heads g) base) g))
            (vals @grammars*)))))

;;; =============================================================================
;;; Reading
;;; =============================================================================

(defn- flag-events
  "ARGS (argv without argv[0]) as a vector of events:
     [:flag name value-or-nil]   one flag, short flags spelled `-x`
     [:operand string]           a positional argument"
  [{:grammar/keys [short-values long-values]} args]
  (loop [[a & more] args, acc [], open? true]
    (cond
      (nil? a)                         acc
      (not open?)                      (recur more (conj acc [:operand a]) false)
      (= "--" a)                       (recur more acc false)
      (or (= "-" a) (not (str/starts-with? a "-")))
      (recur more (conj acc [:operand a]) true)

      (str/starts-with? a "--")
      (let [i (str/index-of a "=")]
        (cond
          i                            (recur more (conj acc [:flag (subs a 0 i) (subs a (inc i))]) true)
          (contains? long-values a)    (recur (rest more) (conj acc [:flag a (first more)]) true)
          :else                        (recur more (conj acc [:flag a nil]) true)))

      :else
      ;; a short cluster: `-rn`, `-e pat`, `-A3`, `-rne pat`
      (let [[acc more]
            (loop [[c & cs] (seq (subs a 1)), acc acc]
              (cond
                (nil? c) [acc more]
                (contains? short-values c)
                (if (seq cs)
                  [(conj acc [:flag (str "-" c) (apply str cs)]) more]
                  [(conj acc [:flag (str "-" c) (first more)]) (rest more)])
                :else (recur cs (conj acc [:flag (str "-" c) nil]))))]
        (recur more acc true)))))

(defn read-events
  "A Reading from GRAMMAR and the events of one argv. Pure."
  [{:grammar/keys [id pattern-flags recursive glob-flags type-flags]} events]
  (let [flags     (filter #(= :flag (first %)) events)
        operands  (mapv second (filter #(= :operand (first %)) events))
        valued    (fn [names] (into [] (comp (filter #(contains? names (second %)))
                                             (keep #(nth % 2)))
                                    flags))
        flagged   (valued pattern-flags)
        ;; the first operand is the pattern unless a flag already supplied one
        [pats paths] (if (seq flagged)
                       [flagged operands]
                       [(into [] (take 1) operands) (into [] (drop 1) operands)])]
    {:reading/tool       id
     :reading/patterns   pats
     :reading/paths      paths
     :reading/recursive? (or (= :always recursive)
                             (boolean (some #(contains? recursive (second %)) flags)))
     :reading/globs      (valued glob-flags)
     :reading/types      (valued type-flags)}))

(defn read-argv
  "Result<Reading> for ARGV, whose argv[0] names the program.

   Refuses with :reading/unknown-program when no registered grammar reads
   argv[0], and :reading/empty-argv when there is nothing to read."
  [argv]
  (let [argv (vec argv)]
    (cond
      (empty? argv) (r/err :reading/empty-argv {})
      :else
      (if-let [g (grammar-for (first argv))]
        (r/ok (read-events g (flag-events g (rest argv))))
        (r/err :reading/unknown-program {:head (first argv)
                                         :known (into (sorted-set) (mapcat :grammar/heads) (vals @grammars*))})))))

(defn register-built-in!
  "Register every built-in grammar. Returns the vector of Results."
  []
  (mapv register! built-in))

(def ^:private bootstrap
  (register-built-in!))

(m/=> read-events [:=> [:cat Grammar [:sequential :any]] Reading])
