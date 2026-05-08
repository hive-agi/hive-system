(ns hive-system.crypto.caesium-test
  "Caesium ICrypto adapter tests. Auto-skipped when libsodium native
   library is unavailable (caesium throws at construction)."
  (:require [clojure.test :refer [deftest is testing]]
            [hive-dsl.result :as r]
            [hive-system.crypto.caesium :as caesium]
            [hive-system.protocols :as proto])
  (:import (java.util Arrays)))

(defn- random-bytes [n]
  (let [b (byte-array n)]
    (.nextBytes (java.security.SecureRandom.) b)
    b))

(defn- try-construct []
  (try (caesium/->caesium-crypto)
       (catch Throwable _ nil)))

(when-let [c (try-construct)]

  (deftest caesium-implements-icrypto
    (is (satisfies? proto/ICrypto c)))

  (deftest caesium-aead-round-trip
    (let [k   (random-bytes 32)
          pt  (.getBytes "hello caesium" "UTF-8")
          aad (.getBytes "context" "UTF-8")
          enc (proto/crypto-encrypt! c {:crypto/algorithm :xchacha20-poly1305
                                        :crypto/key k :crypto/plaintext pt
                                        :crypto/aad aad})]
      (is (r/ok? enc))
      (let [{:crypto/keys [ciphertext iv]} (:ok enc)
            dec (proto/crypto-decrypt! c {:crypto/algorithm :xchacha20-poly1305
                                          :crypto/key k :crypto/ciphertext ciphertext
                                          :crypto/iv iv :crypto/aad aad})]
        (is (r/ok? dec))
        (is (= "hello caesium" (String. ^bytes (:crypto/plaintext (:ok dec)) "UTF-8"))))))

  (deftest caesium-aead-tamper-detected
    (let [k   (random-bytes 32)
          pt  (.getBytes "x" "UTF-8")
          enc (proto/crypto-encrypt! c {:crypto/algorithm :xchacha20-poly1305
                                        :crypto/key k :crypto/plaintext pt})
          {:crypto/keys [^bytes ciphertext iv]} (:ok enc)
          copy (Arrays/copyOf ciphertext (alength ciphertext))]
      (aset-byte copy 0 (unchecked-byte (bit-xor (aget copy 0) 0xFF)))
      (let [dec (proto/crypto-decrypt! c {:crypto/algorithm :xchacha20-poly1305
                                          :crypto/key k :crypto/ciphertext copy
                                          :crypto/iv iv})]
        (is (r/err? dec))
        (is (= :crypto/tampered (:error dec))))))

  (deftest caesium-aead-aad-mismatch-detected
    (let [k   (random-bytes 32)
          pt  (.getBytes "x" "UTF-8")
          enc (proto/crypto-encrypt! c {:crypto/algorithm :xchacha20-poly1305
                                        :crypto/key k :crypto/plaintext pt
                                        :crypto/aad (.getBytes "good" "UTF-8")})
          {:crypto/keys [ciphertext iv]} (:ok enc)
          dec (proto/crypto-decrypt! c {:crypto/algorithm :xchacha20-poly1305
                                        :crypto/key k :crypto/ciphertext ciphertext
                                        :crypto/iv iv
                                        :crypto/aad (.getBytes "bad" "UTF-8")})]
      (is (r/err? dec))
      (is (= :crypto/tampered (:error dec))))))
