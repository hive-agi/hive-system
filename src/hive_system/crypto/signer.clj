(ns hive-system.crypto.signer
  "An `hive-spi.crypto.ports/ISigner` backed by this system's ICrypto.

   The port speaks base64 text — PKCS#8 private, X.509 public, base64
   signature — while ICrypto speaks bytes. This namespace is that translation
   and nothing else: it decodes, delegates with `:crypto/key-encoding :der`,
   and re-encodes.

   Installing it makes hive-license sign through whichever ICrypto a host has
   already built, instead of hive-license's own JDK adapter. Signatures are
   byte-identical either way, so licences issued before and after an install
   verify against the same public key."
  (:require [hive-dsl.result :as r]
            [hive-spi.crypto.ports :as ports]
            [hive-system.protocols :as proto]))

;; SPDX-License-Identifier: MIT

(defn- decode64 ^bytes [^String s]
  (.decode (java.util.Base64/getDecoder) s))

(defn- encode64 ^String [^bytes b]
  (.encodeToString (java.util.Base64/getEncoder) b))

(defrecord SystemSigner [crypto]
  ports/ISigner
  (sign-detached [_ private-b64 payload]
    (let [res (proto/crypto-sign! crypto {:crypto/algorithm    :ed25519
                                          :crypto/key-encoding :der
                                          :crypto/key          (decode64 private-b64)
                                          :crypto/data         payload})]
      (if (r/ok? res)
        (encode64 (:crypto/signature (:ok res)))
        (throw (ex-info "licence signing failed"
                        {:hive-system/error (:error res)})))))

  (verify-detached [_ public-b64 payload signature-b64]
    (boolean
     (try
       (let [res (proto/crypto-verify crypto {:crypto/algorithm    :ed25519
                                              :crypto/key-encoding :der
                                              :crypto/pubkey       (decode64 public-b64)
                                              :crypto/data         payload
                                              :crypto/signature    (decode64 signature-b64)})]
         (and (r/ok? res) (:crypto/valid? (:ok res))))
       (catch Exception _ false))))

  (signer-algorithm [_] :ed25519))

(defn ->system-signer
  "An ISigner delegating to CRYPTO, an `hive-system.protocols/ICrypto`."
  [crypto]
  (->SystemSigner crypto))
