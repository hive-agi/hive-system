(ns hive-system.crypto.macros
  "Macro sugar for AEAD ceremonies built on `hive-system.crypto.core`.

   Provided as an opt-in convenience layer on top of the fn DSL — required
   only when call sites benefit from compact nested-let composition.

   Use:

     (let-aead [crypto (tink/->tink-crypto)
                key (core/random-key)
                {:keys [ciphertext iv]} (core/aead-seal! crypto key pt aad)]
       (core/aead-open! crypto key ciphertext iv aad))

   `let-aead` short-circuits on the first :error Result — same semantics as
   `hive-dsl.result/let-ok` — but accepts plain (non-Result) values for
   adapter / key construction lines."
  (:require [hive-dsl.result :as r]))

(defmacro let-aead
  "Like clojure.core/let, but bindings whose RHS evaluates to a hive-dsl
   Result short-circuit on :error. Non-Result RHS values bind normally.

   Body returns either a Result or a plain value; values are wrapped via r/ok."
  [bindings & body]
  (assert (vector? bindings) "let-aead requires a vector of bindings")
  (assert (even? (count bindings)) "let-aead requires even-numbered bindings")
  (if (empty? bindings)
    `(let [v# (do ~@body)]
       (if (and (map? v#) (or (contains? v# :ok) (contains? v# :error)))
         v#
         (r/ok v#)))
    (let [[sym expr & more] bindings]
      `(let [r# ~expr]
         (cond
           (and (map? r#) (contains? r# :error)) r#
           (and (map? r#) (contains? r# :ok))
           (let [~sym (:ok r#)]
             (let-aead [~@more] ~@body))
           :else
           (let [~sym r#]
             (let-aead [~@more] ~@body)))))))
