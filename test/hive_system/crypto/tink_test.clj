(ns hive-system.crypto.tink-test
  (:require [clojure.test :refer [deftest is testing]]
            [hive-dsl.result :as r]
            [hive-system.crypto.tink :as tink]
            [hive-system.protocols :as proto])
  (:import (java.util Arrays)))

(defn- random-bytes [n]
  (let [b (byte-array n)]
    (.nextBytes (java.security.SecureRandom.) b)
    b))

(deftest tink-implements-icrypto
  (is (satisfies? proto/ICrypto (tink/->tink-crypto))))

(deftest aead-round-trip
  (let [c   (tink/->tink-crypto)
        k   (random-bytes 32)
        pt  (.getBytes "hello world" "UTF-8")
        aad (.getBytes "context" "UTF-8")
        enc (proto/crypto-encrypt! c {:crypto/algorithm :xchacha20-poly1305
                                      :crypto/key k
                                      :crypto/plaintext pt
                                      :crypto/aad aad})]
    (is (r/ok? enc))
    (let [{:crypto/keys [ciphertext iv]} (:ok enc)
          dec (proto/crypto-decrypt! c {:crypto/algorithm :xchacha20-poly1305
                                        :crypto/key k
                                        :crypto/ciphertext ciphertext
                                        :crypto/iv iv
                                        :crypto/aad aad})]
      (is (r/ok? dec))
      (is (= "hello world" (String. ^bytes (:crypto/plaintext (:ok dec)) "UTF-8"))))))

(deftest aead-tamper-detected
  (let [c   (tink/->tink-crypto)
        k   (random-bytes 32)
        pt  (.getBytes "x" "UTF-8")
        enc (proto/crypto-encrypt! c {:crypto/algorithm :xchacha20-poly1305
                                      :crypto/key k :crypto/plaintext pt})
        {:crypto/keys [^bytes ciphertext iv]} (:ok enc)
        copy (Arrays/copyOf ciphertext (alength ciphertext))]
    (aset-byte copy 0 (unchecked-byte (bit-xor (aget copy 0) 0xFF)))
    (let [dec (proto/crypto-decrypt! c {:crypto/algorithm :xchacha20-poly1305
                                        :crypto/key k
                                        :crypto/ciphertext copy
                                        :crypto/iv iv})]
      (is (r/err? dec))
      (is (= :crypto/tampered (:error dec))))))

(deftest aead-aad-mismatch-detected
  (let [c   (tink/->tink-crypto)
        k   (random-bytes 32)
        pt  (.getBytes "x" "UTF-8")
        enc (proto/crypto-encrypt! c {:crypto/algorithm :xchacha20-poly1305
                                      :crypto/key k :crypto/plaintext pt
                                      :crypto/aad (.getBytes "good" "UTF-8")})
        {:crypto/keys [ciphertext iv]} (:ok enc)
        dec (proto/crypto-decrypt! c {:crypto/algorithm :xchacha20-poly1305
                                      :crypto/key k
                                      :crypto/ciphertext ciphertext
                                      :crypto/iv iv
                                      :crypto/aad (.getBytes "bad" "UTF-8")})]
    (is (r/err? dec))
    (is (= :crypto/tampered (:error dec)))))

(deftest aead-bad-key-size
  (let [c   (tink/->tink-crypto)
        enc (proto/crypto-encrypt! c {:crypto/algorithm :xchacha20-poly1305
                                      :crypto/key (byte-array 16)
                                      :crypto/plaintext (byte-array 0)})]
    (is (r/err? enc))
    (is (= :crypto/bad-key-size (:error enc)))))

(deftest aead-unsupported-algo
  (let [c   (tink/->tink-crypto)
        enc (proto/crypto-encrypt! c {:crypto/algorithm :aes-gcm
                                      :crypto/key (byte-array 32)
                                      :crypto/plaintext (byte-array 0)})]
    (is (r/err? enc))
    (is (= :crypto/unsupported (:error enc)))))

(deftest sha256-hash
  (let [c (tink/->tink-crypto)
        h (proto/crypto-hash c {:crypto/algorithm :sha256
                                :crypto/data (.getBytes "abc" "UTF-8")})]
    (is (r/ok? h))
    (is (= 32 (alength ^bytes (:crypto/hash (:ok h)))))
    (is (= :sha256 (:crypto/algorithm (:ok h))))))
