(ns hive-system.crypto.caesium-pwhash-test
  "Argon2id password-hash tests for the caesium ICrypto adapter.
   Auto-skipped when libsodium native library is unavailable
   (caesium throws at construction).

   No byte-exact KAT — libsodium's `crypto_pwhash` wraps Argon2id with
   parallelism fixed at 1 and a libsodium-specific (ops, mem) → (t, m)
   mapping, so RFC 9106 vectors don't apply. We pin behaviour instead:
   determinism, password-sensitivity, salt-sensitivity, output length."
  (:require [clojure.test :refer [deftest is testing]]
            [hive-dsl.result :as r]
            [hive-system.crypto.caesium :as caesium]
            [hive-system.protocols :as proto])
  (:import (java.security SecureRandom)
           (java.util Arrays)))

(defn- random-bytes [n]
  (let [b (byte-array n)]
    (.nextBytes (SecureRandom.) b)
    b))

(defn- try-construct []
  (try (caesium/->caesium-crypto) (catch Throwable _ nil)))

;; Conservative cost — keep CI fast. Real callers pick higher costs.
(def ^:private test-ops-limit 2)
(def ^:private test-mem-limit (* 64 1024 1024))

(when-let [c (try-construct)]

  (deftest caesium-pwhash-deterministic
    (testing "same (password,salt,params) → byte-identical hash"
      (let [pw   (.getBytes "correct horse battery staple" "UTF-8")
            salt (random-bytes 16)
            args {:crypto/algorithm :argon2id
                  :crypto/password  pw
                  :crypto/salt      salt
                  :crypto/ops-limit test-ops-limit
                  :crypto/mem-limit test-mem-limit
                  :crypto/length    32}
            r1   (proto/crypto-password-hash c args)
            r2   (proto/crypto-password-hash c args)]
        (is (r/ok? r1))
        (is (r/ok? r2))
        (let [h1 (:crypto/hash (:ok r1))
              h2 (:crypto/hash (:ok r2))]
          (is (= 32 (alength ^bytes h1)))
          (is (Arrays/equals ^bytes h1 ^bytes h2))
          (is (= :argon2id (:crypto/algorithm (:ok r1))))))))

  (deftest caesium-pwhash-password-sensitive
    (testing "different password (same salt) → different hash"
      (let [salt (random-bytes 16)
            base {:crypto/algorithm :argon2id
                  :crypto/salt      salt
                  :crypto/ops-limit test-ops-limit
                  :crypto/mem-limit test-mem-limit
                  :crypto/length    32}
            h1   (:crypto/hash (:ok (proto/crypto-password-hash
                                     c (assoc base :crypto/password
                                              (.getBytes "alpha" "UTF-8")))))
            h2   (:crypto/hash (:ok (proto/crypto-password-hash
                                     c (assoc base :crypto/password
                                              (.getBytes "bravo" "UTF-8")))))]
        (is (not (Arrays/equals ^bytes h1 ^bytes h2))))))

  (deftest caesium-pwhash-salt-sensitive
    (testing "different salt (same password) → different hash"
      (let [pw   (.getBytes "shared password" "UTF-8")
            base {:crypto/algorithm :argon2id
                  :crypto/password  pw
                  :crypto/ops-limit test-ops-limit
                  :crypto/mem-limit test-mem-limit
                  :crypto/length    32}
            h1   (:crypto/hash (:ok (proto/crypto-password-hash
                                     c (assoc base :crypto/salt (random-bytes 16)))))
            h2   (:crypto/hash (:ok (proto/crypto-password-hash
                                     c (assoc base :crypto/salt (random-bytes 16)))))]
        (is (not (Arrays/equals ^bytes h1 ^bytes h2))))))

  (deftest caesium-pwhash-bad-salt-size
    (testing "wrong salt size → :crypto/bad-salt-size"
      (let [out (proto/crypto-password-hash
                 c {:crypto/algorithm :argon2id
                    :crypto/password  (.getBytes "x" "UTF-8")
                    :crypto/salt      (byte-array 8)
                    :crypto/ops-limit test-ops-limit
                    :crypto/mem-limit test-mem-limit
                    :crypto/length    32})]
        (is (r/err? out))
        (is (= :crypto/bad-salt-size (:error out)))))))
