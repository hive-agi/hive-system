(ns hive-system.crypto.macros-test
  (:require [clojure.test :refer [deftest is testing]]
            [hive-dsl.result :as r]
            [hive-system.crypto.core :as crypto]
            [hive-system.crypto.macros :refer [let-aead]]
            [hive-system.crypto.tink :as tink]))

(deftest let-aead-binds-non-result-values
  (let [out (let-aead [c (tink/->tink-crypto)
                       k (crypto/random-key)]
              [c k])]
    (is (r/ok? out))
    (let [[c k] (:ok out)]
      (is (some? c))
      (is (= 32 (alength ^bytes k))))))

(deftest let-aead-unwraps-ok-results
  (let [c (tink/->tink-crypto)
        out (let-aead [k (crypto/random-key)
                       enc (crypto/aead-seal! {:crypto/adapter c
                                               :crypto/key k
                                               :crypto/plaintext (.getBytes "hi" "UTF-8")})]
              (:crypto/ciphertext enc))]
    (is (r/ok? out))
    (is (some? (:ok out)))))

(deftest let-aead-shortcircuits-on-error
  (let [c (tink/->tink-crypto)
        out (let-aead [enc (crypto/aead-seal! {:crypto/adapter c
                                               :crypto/key (byte-array 16)  ;; bad size
                                               :crypto/plaintext (.getBytes "x" "UTF-8")})
                       _ (println "should not reach")]
              :ok)]
    (is (r/err? out))
    (is (= :crypto/bad-key-size (:error out)))))
