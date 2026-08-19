(ns hive-system.crypto.ed25519-der
  "Ed25519 over PKCS#8 / X.509 DER encodings, via the JDK provider (Java 15+).

   The Tink path in `hive-system.crypto.tink` consumes RAW 32-byte key
   material. Keyrings and key files in this ecosystem store the JDK encodings
   instead — PKCS#8 for a private key, X.509 for a public one — which is what
   KeyFactory consumes. Both encodings wrap the same 32 bytes and yield
   byte-identical RFC 8032 signatures, so the two paths are interchangeable
   over one key.

   Selected with `:crypto/key-encoding :der`; `:raw`, the default, keeps the
   Tink path. Signing takes the PKCS#8 private key as `:crypto/key` — the
   public half is derived from it, so no keypair need be assembled."
  (:require [hive-dsl.result :as r]))

;; SPDX-License-Identifier: MIT

(def ^:private algorithm "Ed25519")

(defn- private-key ^java.security.PrivateKey [^bytes pkcs8]
  (.generatePrivate (java.security.KeyFactory/getInstance algorithm)
                    (java.security.spec.PKCS8EncodedKeySpec. pkcs8)))

(defn- public-key ^java.security.PublicKey [^bytes x509]
  (.generatePublic (java.security.KeyFactory/getInstance algorithm)
                   (java.security.spec.X509EncodedKeySpec. x509)))

(defn sign
  "Detached signature over `:crypto/data` with the PKCS#8 `:crypto/key`.
   Returns Result<{:crypto/signature ^bytes}>."
  [{:crypto/keys [key data]}]
  (cond
    (not (bytes? key))
    (r/err :crypto/bad-key {:reason :not-byte-array :encoding :der})

    (not (bytes? data))
    (r/err :crypto/bad-input {:reason :data-not-byte-array})

    :else
    (try
      (let [sig (java.security.Signature/getInstance algorithm)]
        (.initSign sig (private-key key))
        (.update sig ^bytes data)
        (r/ok {:crypto/signature (.sign sig)}))
      (catch Throwable t
        (r/err :crypto/sign-threw {:message (.getMessage t)})))))

(defn verify
  "Check `:crypto/signature` over `:crypto/data` against the X.509
   `:crypto/pubkey`. Returns Result<{:crypto/valid? boolean}> — a signature
   that simply does not match is `false`, not an error."
  [{:crypto/keys [pubkey data signature]}]
  (cond
    (not (bytes? pubkey))
    (r/err :crypto/bad-key {:reason :not-byte-array :encoding :der})

    (or (not (bytes? data)) (not (bytes? signature)))
    (r/err :crypto/bad-input {:reason :data-and-signature-must-be-byte-arrays})

    :else
    (try
      (let [sig (java.security.Signature/getInstance algorithm)]
        (.initVerify sig (public-key pubkey))
        (.update sig ^bytes data)
        (r/ok {:crypto/valid? (.verify sig ^bytes signature)}))
      (catch java.security.GeneralSecurityException _
        (r/ok {:crypto/valid? false}))
      (catch Throwable t
        (r/err :crypto/verify-threw {:message (.getMessage t)})))))

(defn generate-keypair
  "Fresh Ed25519 keypair as {:public <X.509 bytes> :private <PKCS#8 bytes>}."
  []
  (let [kp (.generateKeyPair (java.security.KeyPairGenerator/getInstance algorithm))]
    {:public  (.getEncoded (.getPublic kp))
     :private (.getEncoded (.getPrivate kp))}))
