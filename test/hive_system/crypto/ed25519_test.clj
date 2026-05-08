(ns hive-system.crypto.ed25519-test
  "Ed25519 sign/verify contract tests for the Tink ICrypto adapter."
  (:require [clojure.test :refer [deftest is testing]]
            [hive-dsl.result :as r]
            [hive-system.crypto.core :as crypto]
            [hive-system.crypto.tink :as tink])
  (:import (java.util Arrays)))

(def ^:private c (tink/->tink-crypto))

(deftest ed25519-keypair-shape
  (let [{:keys [public private]} (crypto/random-ed25519-keypair)]
    (is (= 32 (alength ^bytes public)))
    (is (= 32 (alength ^bytes private)))))

(deftest ed25519-sign-then-verify
  (let [kp   (crypto/random-ed25519-keypair)
        data (.getBytes "sign me" "UTF-8")
        sig-r (crypto/sign! {:crypto/adapter c
                             :crypto/keypair kp
                             :crypto/data data})]
    (is (r/ok? sig-r))
    (is (= 64 (alength ^bytes (:crypto/signature (:ok sig-r)))))
    (let [v-r (crypto/verify {:crypto/adapter c
                              :crypto/pubkey (:public kp)
                              :crypto/data data
                              :crypto/signature (:crypto/signature (:ok sig-r))})]
      (is (r/ok? v-r))
      (is (true? (:crypto/valid? (:ok v-r)))))))

(deftest ed25519-verify-rejects-tampered-data
  (let [kp   (crypto/random-ed25519-keypair)
        data (.getBytes "original" "UTF-8")
        sig  (:crypto/signature (:ok (crypto/sign! {:crypto/adapter c
                                                    :crypto/keypair kp
                                                    :crypto/data data})))
        v-r  (crypto/verify {:crypto/adapter c
                             :crypto/pubkey (:public kp)
                             :crypto/data (.getBytes "tampered" "UTF-8")
                             :crypto/signature sig})]
    (is (r/ok? v-r))
    (is (false? (:crypto/valid? (:ok v-r))))))

(deftest ed25519-verify-rejects-tampered-signature
  (let [kp   (crypto/random-ed25519-keypair)
        data (.getBytes "data" "UTF-8")
        ^bytes sig (:crypto/signature (:ok (crypto/sign! {:crypto/adapter c
                                                          :crypto/keypair kp
                                                          :crypto/data data})))
        copy (Arrays/copyOf sig (alength sig))
        _    (aset-byte copy 0 (unchecked-byte (bit-xor (aget copy 0) 0xFF)))
        v-r  (crypto/verify {:crypto/adapter c
                             :crypto/pubkey (:public kp)
                             :crypto/data data
                             :crypto/signature copy})]
    (is (r/ok? v-r))
    (is (false? (:crypto/valid? (:ok v-r))))))

(deftest ed25519-verify-rejects-wrong-pubkey
  (let [kp-a (crypto/random-ed25519-keypair)
        kp-b (crypto/random-ed25519-keypair)
        data (.getBytes "data" "UTF-8")
        sig  (:crypto/signature (:ok (crypto/sign! {:crypto/adapter c
                                                    :crypto/keypair kp-a
                                                    :crypto/data data})))
        v-r  (crypto/verify {:crypto/adapter c
                             :crypto/pubkey (:public kp-b)
                             :crypto/data data
                             :crypto/signature sig})]
    (is (r/ok? v-r))
    (is (false? (:crypto/valid? (:ok v-r))))))

(deftest ed25519-sign-bad-keypair
  (let [r (crypto/sign! {:crypto/adapter c
                         :crypto/keypair (byte-array 32)  ;; wrong shape
                         :crypto/data (.getBytes "x" "UTF-8")})]
    (is (r/err? r))
    (is (= :crypto/bad-key (:error r)))))

(deftest ed25519-verify-bad-pubkey
  (let [r (crypto/verify {:crypto/adapter c
                          :crypto/pubkey (byte-array 16)
                          :crypto/data (.getBytes "x" "UTF-8")
                          :crypto/signature (byte-array 64)})]
    (is (r/err? r))
    (is (= :crypto/bad-key-size (:error r)))))
