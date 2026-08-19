(ns hive-system.crypto.ed25519-der-test
  "The PKCS#8 / X.509 path: that it signs, and that it agrees byte-for-byte
   with the raw-key Tink path over the same key."
  (:require [clojure.test :refer [deftest is testing]]
            [hive-dsl.result :as r]
            [hive-system.crypto.ed25519-der :as der]
            [hive-system.crypto.tink :as tink]
            [hive-system.protocols :as proto])
  (:import (java.util Arrays)))

(def ^:private c (tink/->tink-crypto))

(def ^:private data (.getBytes "canonical licence bytes" "UTF-8"))

(defn- raw-tail
  "The 32 bytes of Ed25519 key material a DER encoding wraps."
  ^bytes [^bytes der-bytes]
  (Arrays/copyOfRange der-bytes (- (alength der-bytes) 32) (alength der-bytes)))

(deftest der-keypair-shape
  (let [{:keys [public private]} (der/generate-keypair)]
    (is (= 44 (alength ^bytes public))  "X.509 SubjectPublicKeyInfo")
    (is (= 48 (alength ^bytes private)) "PKCS#8 PrivateKeyInfo")))

(deftest der-sign-then-verify
  (let [{:keys [public private]} (der/generate-keypair)
        sig-r (der/sign {:crypto/key private :crypto/data data})]
    (is (r/ok? sig-r))
    (is (true? (:crypto/valid?
                (:ok (der/verify {:crypto/pubkey public
                                  :crypto/data data
                                  :crypto/signature (:crypto/signature (:ok sig-r))})))))))

(deftest a-tampered-payload-is-invalid-not-an-error
  (let [{:keys [public private]} (der/generate-keypair)
        sig (:crypto/signature (:ok (der/sign {:crypto/key private :crypto/data data})))
        res (der/verify {:crypto/pubkey public
                         :crypto/data (.getBytes "different bytes" "UTF-8")
                         :crypto/signature sig})]
    (is (r/ok? res) "a mismatch is a verdict, not a failure")
    (is (false? (:crypto/valid? (:ok res))))))

(deftest malformed-key-material-is-an-error
  (testing "a non-byte-array key is refused rather than coerced"
    (is (r/err? (der/sign {:crypto/key "not-bytes" :crypto/data data})))
    (is (r/err? (der/verify {:crypto/pubkey "not-bytes"
                             :crypto/data data
                             :crypto/signature (byte-array 64)}))))
  (testing "bytes that are not a valid encoding fail closed"
    (is (r/err? (der/sign {:crypto/key (byte-array 48) :crypto/data data})))))

(deftest icrypto-dispatches-on-key-encoding
  (let [{:keys [public private]} (der/generate-keypair)
        raw-pub  (raw-tail public)
        raw-priv (raw-tail private)
        via-der  (proto/crypto-sign!
                  c {:crypto/algorithm :ed25519 :crypto/key-encoding :der
                     :crypto/key private :crypto/data data})
        via-raw  (proto/crypto-sign!
                  c {:crypto/algorithm :ed25519
                     :crypto/keypair {:public raw-pub :private raw-priv}
                     :crypto/data data})]
    (testing "both encodings are accepted by the same adapter"
      (is (r/ok? via-der))
      (is (r/ok? via-raw)))
    (testing "and produce the same signature, so the paths are interchangeable"
      (is (Arrays/equals ^bytes (:crypto/signature (:ok via-der))
                         ^bytes (:crypto/signature (:ok via-raw)))))
    (testing "each verifies what the other signed"
      (is (true? (:crypto/valid?
                  (:ok (proto/crypto-verify
                        c {:crypto/algorithm :ed25519 :crypto/key-encoding :der
                           :crypto/pubkey public :crypto/data data
                           :crypto/signature (:crypto/signature (:ok via-raw))})))))
      (is (true? (:crypto/valid?
                  (:ok (proto/crypto-verify
                        c {:crypto/algorithm :ed25519
                           :crypto/pubkey raw-pub :crypto/data data
                           :crypto/signature (:crypto/signature (:ok via-der))}))))))))
