(ns hive-system.crypto.hpke-test
  "HPKE-x25519 contract tests for the Tink ICrypto adapter."
  (:require [clojure.test :refer [deftest is testing]]
            [hive-dsl.result :as r]
            [hive-system.crypto.core :as crypto]
            [hive-system.crypto.tink :as tink]
            [hive-system.protocols :as proto])
  (:import (java.util Arrays)))

(def ^:private c (tink/->tink-crypto))

(deftest random-keypair-shape
  (let [{:keys [public private]} (crypto/random-x25519-keypair)]
    (is (= 32 (alength ^bytes public)))
    (is (= 32 (alength ^bytes private)))))

(deftest hpke-round-trip
  (let [kp  (crypto/random-x25519-keypair)
        pt  (.getBytes "hpke message" "UTF-8")
        aad (.getBytes "ctx-info" "UTF-8")
        enc (crypto/hpke-seal! {:crypto/adapter c
                                :crypto/pubkey (:public kp)
                                :crypto/plaintext pt
                                :crypto/aad aad})]
    (is (r/ok? enc))
    (let [{:crypto/keys [ciphertext]} (:ok enc)
          dec (crypto/hpke-open! {:crypto/adapter c
                                  :crypto/keypair kp
                                  :crypto/ciphertext ciphertext
                                  :crypto/aad aad})]
      (is (r/ok? dec))
      (is (= "hpke message" (String. ^bytes (:crypto/plaintext (:ok dec)) "UTF-8"))))))

(deftest hpke-round-trip-nil-aad
  (let [kp  (crypto/random-x25519-keypair)
        pt  (.getBytes "no-aad" "UTF-8")
        enc (crypto/hpke-seal! {:crypto/adapter c
                                :crypto/pubkey (:public kp)
                                :crypto/plaintext pt})
        dec (crypto/hpke-open! {:crypto/adapter c
                                :crypto/keypair kp
                                :crypto/ciphertext (:crypto/ciphertext (:ok enc))})]
    (is (r/ok? dec))
    (is (= "no-aad" (String. ^bytes (:crypto/plaintext (:ok dec)) "UTF-8")))))

(deftest hpke-tamper-detected
  (let [kp  (crypto/random-x25519-keypair)
        enc (crypto/hpke-seal! {:crypto/adapter c
                                :crypto/pubkey (:public kp)
                                :crypto/plaintext (.getBytes "x" "UTF-8")})
        ^bytes ct (:crypto/ciphertext (:ok enc))
        copy   (Arrays/copyOf ct (alength ct))
        _      (aset-byte copy 32 (unchecked-byte (bit-xor (aget copy 32) 0xFF)))
        dec    (crypto/hpke-open! {:crypto/adapter c
                                   :crypto/keypair kp
                                   :crypto/ciphertext copy})]
    (is (r/err? dec))
    (is (= :crypto/tampered (:error dec)))))

(deftest hpke-aad-mismatch-detected
  (let [kp  (crypto/random-x25519-keypair)
        enc (crypto/hpke-seal! {:crypto/adapter c
                                :crypto/pubkey (:public kp)
                                :crypto/plaintext (.getBytes "x" "UTF-8")
                                :crypto/aad (.getBytes "good" "UTF-8")})
        dec (crypto/hpke-open! {:crypto/adapter c
                                :crypto/keypair kp
                                :crypto/ciphertext (:crypto/ciphertext (:ok enc))
                                :crypto/aad (.getBytes "bad" "UTF-8")})]
    (is (r/err? dec))
    (is (= :crypto/tampered (:error dec)))))

(deftest hpke-wrong-recipient-rejected
  (let [kp-a (crypto/random-x25519-keypair)
        kp-b (crypto/random-x25519-keypair)
        enc  (crypto/hpke-seal! {:crypto/adapter c
                                 :crypto/pubkey (:public kp-a)
                                 :crypto/plaintext (.getBytes "for-a" "UTF-8")})
        dec  (crypto/hpke-open! {:crypto/adapter c
                                 :crypto/keypair kp-b
                                 :crypto/ciphertext (:crypto/ciphertext (:ok enc))})]
    (is (r/err? dec))
    (is (= :crypto/tampered (:error dec)))))

(deftest hpke-bad-pubkey-size
  (let [enc (crypto/hpke-seal! {:crypto/adapter c
                                :crypto/pubkey (byte-array 16)
                                :crypto/plaintext (.getBytes "x" "UTF-8")})]
    (is (r/err? enc))
    (is (= :crypto/bad-key-size (:error enc)))))

(deftest hpke-decrypt-requires-keypair
  (let [kp  (crypto/random-x25519-keypair)
        enc (crypto/hpke-seal! {:crypto/adapter c
                                :crypto/pubkey (:public kp)
                                :crypto/plaintext (.getBytes "x" "UTF-8")})
        ;; Pass just the private bytes (not a keypair map) — should reject
        dec (crypto/hpke-open! {:crypto/adapter c
                                :crypto/keypair (:private kp)
                                :crypto/ciphertext (:crypto/ciphertext (:ok enc))})]
    (is (r/err? dec))
    (is (= :crypto/bad-key (:error dec)))))
