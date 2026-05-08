(ns hive-system.crypto.core-test
  "Fn DSL tests — runs across every available ICrypto adapter so the
   surface contract is held identical."
  (:require [clojure.test :refer [deftest is testing]]
            [hive-dsl.result :as r]
            [hive-system.crypto.core :as crypto]
            [hive-system.crypto.tink :as tink]
            [hive-system.crypto.caesium :as caesium]))

(defn- adapters []
  (into [["tink" (tink/->tink-crypto)]]
        (try [["caesium" (caesium/->caesium-crypto)]]
             (catch Throwable _ []))))

(deftest random-key-and-nonce-sizes
  (is (= 32 (alength ^bytes (crypto/random-key))))
  (is (= 24 (alength ^bytes (crypto/random-nonce)))))

(deftest aead-round-trip-across-adapters
  (doseq [[name c] (adapters)]
    (testing name
      (let [k   (crypto/random-key)
            pt  (.getBytes "trip" "UTF-8")
            aad (.getBytes "ctx" "UTF-8")
            enc (crypto/aead-seal! {:crypto/adapter c
                                    :crypto/key k
                                    :crypto/plaintext pt
                                    :crypto/aad aad})]
        (is (r/ok? enc))
        (let [{:crypto/keys [ciphertext iv]} (:ok enc)
              dec (crypto/aead-open! {:crypto/adapter c
                                      :crypto/key k
                                      :crypto/ciphertext ciphertext
                                      :crypto/iv iv
                                      :crypto/aad aad})]
          (is (r/ok? dec))
          (is (= "trip" (String. ^bytes (:crypto/plaintext (:ok dec)) "UTF-8"))))))))

(deftest aead-round-trip-nil-aad
  (doseq [[name c] (adapters)]
    (testing name
      (let [k   (crypto/random-key)
            pt  (.getBytes "no-aad" "UTF-8")
            enc (crypto/aead-seal! {:crypto/adapter c :crypto/key k :crypto/plaintext pt})
            {:crypto/keys [ciphertext iv]} (:ok enc)
            dec (crypto/aead-open! {:crypto/adapter c :crypto/key k
                                    :crypto/ciphertext ciphertext :crypto/iv iv})]
        (is (r/ok? dec))
        (is (= "no-aad" (String. ^bytes (:crypto/plaintext (:ok dec)) "UTF-8")))))))
