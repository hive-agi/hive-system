(ns hive-system.crypto.tink
  "Tink-backed implementation of `hive-system.protocols/ICrypto`.

   See `hive-system.protocols/ICrypto` for the parameter-object contract —
   every op receives a single map keyed under `:crypto/*`.

   Algorithms supported:
     :xchacha20-poly1305  — symmetric AEAD (subtle.XChaCha20Poly1305)
     :hpke-x25519         — RFC 9180 single-shot HPKE
                            (DHKEM-X25519 + HKDF-SHA256 + ChaCha20-Poly1305)
     :sha256              — message digest"
  (:require [hive-dsl.result :as r]
            [hive-system.protocols :as proto])
  (:import (com.google.crypto.tink HybridDecrypt HybridEncrypt InsecureSecretKeyAccess
                                   KeysetHandle PublicKeySign PublicKeyVerify)
           (com.google.crypto.tink.hybrid HpkeParameters HpkeParameters$AeadId
                                          HpkeParameters$KdfId HpkeParameters$KemId
                                          HpkeParameters$Variant HpkePrivateKey HpkePublicKey
                                          HybridConfig)
           (com.google.crypto.tink.signature Ed25519Parameters Ed25519Parameters$Variant
                                             Ed25519PrivateKey Ed25519PublicKey
                                             SignatureConfig)
           (com.google.crypto.tink.subtle XChaCha20Poly1305)
           (com.google.crypto.tink.util Bytes SecretBytes)
           (java.security MessageDigest)
           (java.util Arrays)
           (javax.crypto AEADBadTagException)))

(def ^:private xchacha-key-size 32)
(def ^:private xchacha-nonce-size 24)
(def ^:private x25519-key-size 32)

(defn- byte-array? [x]
  (and (some? x) (= (Class/forName "[B") (class x))))

;; -----------------------------------------------------------------------------
;; XChaCha20-Poly1305 (symmetric AEAD)

(defn- check-key [k]
  (cond
    (not (byte-array? k))         (r/err :crypto/bad-key {:reason :not-byte-array})
    (not= xchacha-key-size (alength ^bytes k))
    (r/err :crypto/bad-key-size {:expected xchacha-key-size :actual (alength ^bytes k)})
    :else (r/ok k)))

(defn- check-nonce [n]
  (cond
    (not (byte-array? n))         (r/err :crypto/bad-nonce {:reason :not-byte-array})
    (not= xchacha-nonce-size (alength ^bytes n))
    (r/err :crypto/bad-nonce-size {:expected xchacha-nonce-size :actual (alength ^bytes n)})
    :else (r/ok n)))

(defn- join-tink-ct [^bytes nonce ^bytes body]
  (let [out (byte-array (+ (alength nonce) (alength body)))]
    (System/arraycopy nonce 0 out 0 (alength nonce))
    (System/arraycopy body 0 out (alength nonce) (alength body))
    out))

(defn- xchacha-encrypt [{:crypto/keys [key plaintext aad]}]
  (r/let-ok [_ (check-key key)]
   (try
     (let [aead    (XChaCha20Poly1305. ^bytes key)
           tink-ct (.encrypt aead ^bytes plaintext ^bytes (or aad (byte-array 0)))
           nonce   (Arrays/copyOfRange ^bytes tink-ct 0 xchacha-nonce-size)
           body    (Arrays/copyOfRange ^bytes tink-ct xchacha-nonce-size (alength ^bytes tink-ct))]
       (r/ok {:crypto/ciphertext body :crypto/iv nonce}))
     (catch Throwable t
       (r/err :crypto/encrypt-threw {:message (.getMessage t)})))))

(defn- xchacha-decrypt [{:crypto/keys [key ciphertext iv aad]}]
  (r/let-ok [_ (check-key key)
             _ (check-nonce iv)]
   (try
     (let [aead    (XChaCha20Poly1305. ^bytes key)
           tink-ct (join-tink-ct iv ciphertext)
           pt      (.decrypt aead ^bytes tink-ct ^bytes (or aad (byte-array 0)))]
       (r/ok {:crypto/plaintext pt}))
     (catch AEADBadTagException _
       (r/err :crypto/tampered {:reason :bad-tag}))
     (catch Throwable t
       (r/err :crypto/decrypt-threw {:message (.getMessage t)})))))

;; -----------------------------------------------------------------------------
;; SHA-256

(defn- sha256 [{:crypto/keys [data]}]
  (try
    (r/ok {:crypto/hash      (.digest (MessageDigest/getInstance "SHA-256") ^bytes data)
           :crypto/algorithm :sha256})
    (catch Throwable t
      (r/err :crypto/hash-threw {:message (.getMessage t)}))))

;; -----------------------------------------------------------------------------
;; HPKE — DHKEM-X25519-HKDF-SHA256 + ChaCha20-Poly1305

(HybridConfig/register)

(def ^:private hpke-params
  (-> (HpkeParameters/builder)
      (.setVariant HpkeParameters$Variant/NO_PREFIX)
      (.setKemId HpkeParameters$KemId/DHKEM_X25519_HKDF_SHA256)
      (.setKdfId HpkeParameters$KdfId/HKDF_SHA256)
      (.setAeadId HpkeParameters$AeadId/CHACHA20_POLY1305)
      .build))

(defn- check-x25519-pubkey [k]
  (cond
    (not (byte-array? k))
    (r/err :crypto/bad-key {:reason :not-byte-array})
    (not= x25519-key-size (alength ^bytes k))
    (r/err :crypto/bad-key-size {:expected x25519-key-size :actual (alength ^bytes k)})
    :else (r/ok k)))

(defn- ^KeysetHandle pub-handle [^bytes pub-bytes]
  (let [pub-key (HpkePublicKey/create hpke-params (Bytes/copyFrom pub-bytes) nil)]
    (-> (KeysetHandle/newBuilder)
        (.addEntry (-> (KeysetHandle/importKey pub-key)
                       .makePrimary
                       .withRandomId))
        .build)))

(defn- ^KeysetHandle priv-handle [^bytes pub-bytes ^bytes priv-bytes]
  (let [pub-key  (HpkePublicKey/create hpke-params (Bytes/copyFrom pub-bytes) nil)
        priv-key (HpkePrivateKey/create
                  pub-key
                  (SecretBytes/copyFrom priv-bytes (InsecureSecretKeyAccess/get)))]
    (-> (KeysetHandle/newBuilder)
        (.addEntry (-> (KeysetHandle/importKey priv-key)
                       .makePrimary
                       .withRandomId))
        .build)))

(defn- hpke-encrypt [{:crypto/keys [pubkey plaintext aad]}]
  (r/let-ok [_ (check-x25519-pubkey pubkey)]
   (try
     (let [enc (.getPrimitive (pub-handle pubkey) HybridEncrypt)
           ct  (.encrypt enc ^bytes plaintext ^bytes (or aad (byte-array 0)))]
       (r/ok {:crypto/ciphertext ct}))
     (catch Throwable t
       (r/err :crypto/encrypt-threw {:message (.getMessage t)})))))

(defn- hpke-decrypt [{:crypto/keys [keypair ciphertext aad]}]
  (let [pub  (:public keypair)
        priv (:private keypair)]
    (cond
      (or (not (byte-array? pub)) (not (byte-array? priv)))
      (r/err :crypto/bad-key {:reason :hpke-keypair-required
                              :hint   "pass {:public <32-bytes> :private <32-bytes>}"})
      (or (not= x25519-key-size (alength ^bytes pub))
          (not= x25519-key-size (alength ^bytes priv)))
      (r/err :crypto/bad-key-size {:expected x25519-key-size})
      :else
      (try
        (let [dec-prim (.getPrimitive (priv-handle pub priv) HybridDecrypt)
              pt       (.decrypt dec-prim ^bytes ciphertext ^bytes (or aad (byte-array 0)))]
          (r/ok {:crypto/plaintext pt}))
        (catch Throwable t
          (if (instance? java.security.GeneralSecurityException t)
            (r/err :crypto/tampered {:reason :hpke-decrypt-fail
                                     :message (.getMessage t)})
            (r/err :crypto/decrypt-threw {:message (.getMessage t)})))))))

(defn generate-x25519-keypair
  "Generate a fresh DHKEM-X25519 key pair. Returns {:public 32-bytes :private 32-bytes}."
  []
  (let [handle   (KeysetHandle/generateNew hpke-params)
        priv-key (-> handle (.getAt 0) .getKey)
        pub-key  (.getPublicKey priv-key)
        pub-b    (.toByteArray (.getPublicKeyBytes pub-key))
        priv-b   (.toByteArray (.getPrivateKeyBytes priv-key)
                               (InsecureSecretKeyAccess/get))]
    {:public pub-b :private priv-b}))

;; -----------------------------------------------------------------------------
;; Ed25519 — issuer signature (RFC 8032)

(SignatureConfig/register)

(def ^:private ed25519-params
  (Ed25519Parameters/create Ed25519Parameters$Variant/NO_PREFIX))

(def ^:private ed25519-key-size 32)

(defn- check-ed25519-pubkey [k]
  (cond
    (not (byte-array? k))
    (r/err :crypto/bad-key {:reason :not-byte-array})
    (not= ed25519-key-size (alength ^bytes k))
    (r/err :crypto/bad-key-size {:expected ed25519-key-size :actual (alength ^bytes k)})
    :else (r/ok k)))

(defn- ^KeysetHandle ed25519-priv-handle [^bytes pub-bytes ^bytes priv-bytes]
  (let [pub-key  (Ed25519PublicKey/create Ed25519Parameters$Variant/NO_PREFIX
                                          (Bytes/copyFrom pub-bytes) nil)
        priv-key (Ed25519PrivateKey/create
                  pub-key
                  (SecretBytes/copyFrom priv-bytes (InsecureSecretKeyAccess/get)))]
    (-> (KeysetHandle/newBuilder)
        (.addEntry (-> (KeysetHandle/importKey priv-key)
                       .makePrimary
                       .withRandomId))
        .build)))

(defn- ^KeysetHandle ed25519-pub-handle [^bytes pub-bytes]
  (let [pub-key (Ed25519PublicKey/create Ed25519Parameters$Variant/NO_PREFIX
                                         (Bytes/copyFrom pub-bytes) nil)]
    (-> (KeysetHandle/newBuilder)
        (.addEntry (-> (KeysetHandle/importKey pub-key)
                       .makePrimary
                       .withRandomId))
        .build)))

(defn- ed25519-sign [{:crypto/keys [keypair data]}]
  (let [pub  (:public keypair)
        priv (:private keypair)]
    (cond
      (or (not (byte-array? pub)) (not (byte-array? priv)))
      (r/err :crypto/bad-key {:reason :ed25519-keypair-required
                              :hint   "pass {:public <32B> :private <32B>}"})
      (or (not= ed25519-key-size (alength ^bytes pub))
          (not= ed25519-key-size (alength ^bytes priv)))
      (r/err :crypto/bad-key-size {:expected ed25519-key-size})
      :else
      (try
        (let [signer (.getPrimitive (ed25519-priv-handle pub priv) PublicKeySign)
              sig    (.sign signer ^bytes data)]
          (r/ok {:crypto/signature sig}))
        (catch Throwable t
          (r/err :crypto/sign-threw {:message (.getMessage t)}))))))

(defn- ed25519-verify [{:crypto/keys [pubkey data signature]}]
  (r/let-ok [_ (check-ed25519-pubkey pubkey)]
   (try
     (.verify (.getPrimitive (ed25519-pub-handle pubkey) PublicKeyVerify)
              ^bytes signature ^bytes data)
     (r/ok {:crypto/valid? true})
     (catch java.security.GeneralSecurityException _
       (r/ok {:crypto/valid? false}))
     (catch Throwable t
       (r/err :crypto/verify-threw {:message (.getMessage t)})))))

(defn generate-ed25519-keypair
  "Generate a fresh Ed25519 keypair. Returns {:public 32-bytes :private 32-bytes}."
  []
  (let [handle   (KeysetHandle/generateNew ed25519-params)
        priv-key (-> handle (.getAt 0) .getKey)
        pub-key  (.getPublicKey priv-key)
        pub-b    (.toByteArray (.getPublicKeyBytes pub-key))
        priv-b   (.toByteArray (.getPrivateKeyBytes priv-key)
                               (InsecureSecretKeyAccess/get))]
    {:public pub-b :private priv-b}))

;; -----------------------------------------------------------------------------
;; Protocol implementation — dispatch on :crypto/algorithm

(defrecord TinkCrypto []
  proto/ICrypto
  (crypto-hash [_ {:crypto/keys [algorithm] :as op}]
    (case algorithm
      :sha256 (sha256 op)
      (r/err :crypto/unsupported {:algorithm algorithm :op :hash})))
  (crypto-sign! [_ {:crypto/keys [algorithm] :as op}]
    (case algorithm
      :ed25519 (ed25519-sign op)
      (r/err :crypto/unsupported {:algorithm algorithm :op :sign})))
  (crypto-verify [_ {:crypto/keys [algorithm] :as op}]
    (case algorithm
      :ed25519 (ed25519-verify op)
      (r/err :crypto/unsupported {:algorithm algorithm :op :verify})))
  (crypto-encrypt! [_ {:crypto/keys [algorithm] :as op}]
    (case algorithm
      :xchacha20-poly1305 (xchacha-encrypt op)
      :hpke-x25519        (hpke-encrypt op)
      (r/err :crypto/unsupported {:algorithm algorithm :op :encrypt})))
  (crypto-decrypt! [_ {:crypto/keys [algorithm] :as op}]
    (case algorithm
      :xchacha20-poly1305 (xchacha-decrypt op)
      :hpke-x25519        (hpke-decrypt op)
      (r/err :crypto/unsupported {:algorithm algorithm :op :decrypt}))))

(defn ->tink-crypto
  "Construct a Tink-backed ICrypto."
  [] (->TinkCrypto))
