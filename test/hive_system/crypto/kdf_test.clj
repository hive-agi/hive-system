(ns hive-system.crypto.kdf-test
  "Known-answer tests for HKDF-SHA256 against RFC 5869 §A test vectors.

   Exercises (a) the pure-Java `hive-system.crypto.kdf/hkdf-sha256` impl
   and (b) the `crypto-derive-key` ICrypto method on Tink. Caesium's
   `crypto-derive-key` is byte-equivalent (shares the kdf ns) and is
   covered by a cross-adapter equality test guarded on libsodium
   availability."
  (:require [clojure.test :refer [deftest is testing]]
            [hive-dsl.result :as r]
            [hive-system.crypto.caesium :as caesium]
            [hive-system.crypto.core :as hcrypto]
            [hive-system.crypto.kdf :as kdf]
            [hive-system.crypto.tink :as tink]
            [hive-system.protocols :as proto])
  (:import (java.util Arrays HexFormat)))

(defn- hex->bytes ^bytes [^String s]
  (.parseHex (HexFormat/of) s))

(defn- bytes->hex ^String [^bytes b]
  (.formatHex (HexFormat/of) b))

;; RFC 5869 §A.1 — Test Case 1 (basic, SHA-256)
(def ^:private rfc-tc1
  {:ikm    (hex->bytes "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
   :salt   (hex->bytes "000102030405060708090a0b0c")
   :info   (hex->bytes "f0f1f2f3f4f5f6f7f8f9")
   :length 42
   :prk    (hex->bytes (str "077709362c2e32df0ddc3f0dc47bba63"
                            "90b6c73bb50f9c3122ec844ad7c2b3e5"))
   :okm    (hex->bytes (str "3cb25f25faacd57a90434f64d0362f2a"
                            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                            "34007208d5b887185865"))})

;; RFC 5869 §A.2 — Test Case 2 (longer inputs/outputs)
(def ^:private rfc-tc2
  {:ikm    (hex->bytes (str "000102030405060708090a0b0c0d0e0f"
                            "101112131415161718191a1b1c1d1e1f"
                            "202122232425262728292a2b2c2d2e2f"
                            "303132333435363738393a3b3c3d3e3f"
                            "404142434445464748494a4b4c4d4e4f"))
   :salt   (hex->bytes (str "606162636465666768696a6b6c6d6e6f"
                            "707172737475767778797a7b7c7d7e7f"
                            "808182838485868788898a8b8c8d8e8f"
                            "909192939495969798999a9b9c9d9e9f"
                            "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"))
   :info   (hex->bytes (str "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                            "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                            "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                            "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"))
   :length 82
   :prk    (hex->bytes (str "06a6b88c5853361a06104c9ceb35b45c"
                            "ef760014904671014a193f40c15fc244"))
   :okm    (hex->bytes (str "b11e398dc80327a1c8e7f78c596a4934"
                            "4f012eda2d4efad8a050cc4c19afa97c"
                            "59045a99cac7827271cb41c65e590e09"
                            "da3275600c2f09b8367793a9aca3db71"
                            "cc30c58179ec3e87c14c01d5c1f3434f"
                            "1d87"))})

;; RFC 5869 §A.3 — Test Case 3 (zero-length salt + info)
(def ^:private rfc-tc3
  {:ikm    (hex->bytes "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
   :salt   nil
   :info   nil
   :length 42
   :prk    (hex->bytes (str "19ef24a32c717b167f33a91d6f648bdf"
                            "96596776afdb6377ac434c1c293ccb04"))
   :okm    (hex->bytes (str "8da4e775a563c18f715f802a063c5a31"
                            "b8a11f5c5ee1879ec3454e5f3c738d2d"
                            "9d201395faa4b61a96c8"))})

(defn- assert-kat-pure [tc]
  (let [{:keys [ikm salt info length okm]} tc
        out (kdf/hkdf-sha256 salt ikm info length)]
    (is (Arrays/equals ^bytes out ^bytes okm)
        (str "RFC 5869 KAT mismatch — expected "
             (bytes->hex okm) " got " (bytes->hex out)))))

(deftest hkdf-sha256-rfc-5869-pure
  (testing "pure-Java HKDF byte-exact against RFC 5869 vectors"
    (testing "TC1 (basic)"           (assert-kat-pure rfc-tc1))
    (testing "TC2 (longer)"          (assert-kat-pure rfc-tc2))
    (testing "TC3 (empty salt+info)" (assert-kat-pure rfc-tc3))))

(defn- assert-kat-steps [tc]
  (let [{:keys [ikm salt info length prk okm]} tc
        out-prk (kdf/hkdf-extract salt ikm)
        out-okm (kdf/hkdf-expand out-prk info length)]
    (is (Arrays/equals ^bytes out-prk ^bytes prk)
        (str "RFC 5869 PRK mismatch — expected "
             (bytes->hex prk) " got " (bytes->hex out-prk)))
    (is (Arrays/equals ^bytes out-okm ^bytes okm)
        (str "RFC 5869 OKM mismatch — expected "
             (bytes->hex okm) " got " (bytes->hex out-okm)))))

;; The two RFC steps are public API: consumers (General's zk-crypto KAT suite)
;; pin the intermediate PRK to the Appendix A vectors. This test is also their
;; in-repo caller, so an unused-public-var sweep cannot privatize them again.
(deftest hkdf-extract-then-expand-rfc-5869
  (testing "extract yields the RFC PRK, expand of that PRK yields the RFC OKM"
    (testing "TC1 (basic)"           (assert-kat-steps rfc-tc1))
    (testing "TC2 (longer)"          (assert-kat-steps rfc-tc2))
    (testing "TC3 (empty salt+info)" (assert-kat-steps rfc-tc3))))

(deftest hkdf-expand-rejects-bad-input
  (testing "a PRK shorter than HashLen"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"shorter than HashLen"
          (kdf/hkdf-expand (byte-array 16) nil 32))))
  (testing "a nil PRK"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"shorter than HashLen"
          (kdf/hkdf-expand nil nil 32))))
  (testing "length over 255*HashLen"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"exceeds 255\*HashLen"
          (kdf/hkdf-expand (byte-array 32) nil (inc kdf/MAX_LENGTH))))))

(defn- assert-kat-adapter [adapter tc]
  (let [{:keys [ikm salt info length okm]} tc
        result (hcrypto/kdf-hkdf-sha256
                {:crypto/adapter adapter
                 :crypto/ikm     ikm
                 :crypto/salt    salt
                 :crypto/info    info
                 :crypto/length  length})]
    (is (r/ok? result)
        (str "kdf-hkdf-sha256 returned err: " result))
    (is (Arrays/equals ^bytes (:crypto/key (:ok result))
                       ^bytes okm))
    (is (= :hkdf-sha256 (:crypto/algorithm (:ok result))))))

(deftest hkdf-via-tink-adapter
  (testing "TinkCrypto crypto-derive-key matches RFC 5869"
    (let [t (tink/->tink-crypto)]
      (assert-kat-adapter t rfc-tc1)
      (assert-kat-adapter t rfc-tc2)
      (assert-kat-adapter t rfc-tc3))))

(defn- try-caesium []
  (try (caesium/->caesium-crypto) (catch Throwable _ nil)))

(when-let [c (try-caesium)]
  (deftest hkdf-via-caesium-adapter-matches-tink
    (testing "CaesiumCrypto crypto-derive-key matches Tink byte-for-byte"
      (let [t (tink/->tink-crypto)
            ikm (hex->bytes "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
            args {:crypto/ikm ikm
                  :crypto/salt (hex->bytes "000102030405060708090a0b0c")
                  :crypto/info (hex->bytes "f0f1f2f3f4f5f6f7f8f9")
                  :crypto/length 42}
            t-out (hcrypto/kdf-hkdf-sha256 (assoc args :crypto/adapter t))
            c-out (hcrypto/kdf-hkdf-sha256 (assoc args :crypto/adapter c))]
        (is (r/ok? t-out))
        (is (r/ok? c-out))
        (is (Arrays/equals ^bytes (:crypto/key (:ok t-out))
                           ^bytes (:crypto/key (:ok c-out))))))))

(deftest hkdf-rejects-bad-input
  (let [t (tink/->tink-crypto)]
    (testing "non-byte-array ikm"
      (is (r/err? (hcrypto/kdf-hkdf-sha256
                   {:crypto/adapter t :crypto/ikm "not bytes" :crypto/length 16}))))
    (testing "non-positive length"
      (is (r/err? (hcrypto/kdf-hkdf-sha256
                   {:crypto/adapter t :crypto/ikm (byte-array 16) :crypto/length 0}))))
    (testing "length over 255*HashLen"
      (is (r/err? (hcrypto/kdf-hkdf-sha256
                   {:crypto/adapter t :crypto/ikm (byte-array 16)
                    :crypto/length (inc (* 255 32))}))))))

(deftest tink-pwhash-returns-unsupported
  (testing "Tink has no Argon2id; pwhash returns :crypto/unsupported"
    (let [t (tink/->tink-crypto)
          out (hcrypto/pwhash-argon2id
               {:crypto/adapter t
                :crypto/password (.getBytes "pw" "UTF-8")
                :crypto/salt (byte-array 16)
                :crypto/ops-limit 2
                :crypto/mem-limit (* 64 1024 1024)
                :crypto/length 32})]
      (is (r/err? out))
      (is (= :crypto/unsupported (:error out))))))
