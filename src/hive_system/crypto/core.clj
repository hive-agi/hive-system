(ns hive-system.crypto.core
  "Plain-fn DSL over `hive-system.protocols/ICrypto`. Parameter-object style:
   every fn takes a single map keyed under `:crypto/*`.

   Callers depend on this ns + ICrypto, never on a concrete adapter
   (Tink / caesium / ...). Java interop stays inside the adapters.

   Surface (key prefix `:crypto/*`):

     (aead-seal! {:crypto/adapter c :crypto/key k :crypto/plaintext pt :crypto/aad aad})
       => Result<{:crypto/ciphertext ^bytes :crypto/iv ^bytes}>

     (aead-open! {:crypto/adapter c :crypto/key k :crypto/ciphertext ct
                  :crypto/iv nonce :crypto/aad aad})
       => Result<{:crypto/plaintext ^bytes}>

     (hpke-seal! {:crypto/adapter c :crypto/pubkey pub
                  :crypto/plaintext pt :crypto/aad aad})
       => Result<{:crypto/ciphertext ^bytes}>

     (hpke-open! {:crypto/adapter c :crypto/keypair kp
                  :crypto/ciphertext ct :crypto/aad aad})
       => Result<{:crypto/plaintext ^bytes}>

     (sha256 {:crypto/adapter c :crypto/data ^bytes})
       => Result<{:crypto/hash ^bytes :crypto/algorithm :sha256}>

     (random-key)              -> 32-byte ^bytes  (XChaCha20 key)
     (random-nonce)             -> 24-byte ^bytes  (XChaCha20 nonce)
     (random-x25519-keypair)    -> {:public 32B :private 32B}

   Default `:crypto/algorithm` keys are filled in by each fn (caller may
   override via the same key in the input map)."
  (:require [hive-system.protocols :as proto])
  (:import (java.security SecureRandom)))

(def ^:private secure-rng (SecureRandom.))

(defn random-key
  "Generate a 32-byte cryptographically-strong random AEAD key."
  ^bytes []
  (let [k (byte-array 32)]
    (.nextBytes secure-rng k)
    k))

(defn random-nonce
  "Generate a 24-byte cryptographically-strong random XChaCha20 nonce."
  ^bytes []
  (let [n (byte-array 24)]
    (.nextBytes secure-rng n)
    n))

(defn random-x25519-keypair
  "Generate a fresh x25519 HPKE keypair. Returns
   `{:public ^bytes :private ^bytes}` (each 32 bytes)."
  []
  ((requiring-resolve 'hive-system.crypto.tink/generate-x25519-keypair)))

(defn random-ed25519-keypair
  "Generate a fresh Ed25519 issuer keypair. Returns
   `{:public ^bytes :private ^bytes}` (each 32 bytes)."
  []
  ((requiring-resolve 'hive-system.crypto.tink/generate-ed25519-keypair)))

;; -----------------------------------------------------------------------------
;; AEAD (symmetric) DSL

(defn aead-seal!
  "Symmetric AEAD seal. See ns docstring for input shape."
  [{:crypto/keys [adapter] :as op}]
  (proto/crypto-encrypt!
   adapter
   (merge {:crypto/algorithm :xchacha20-poly1305} (dissoc op :crypto/adapter))))

(defn aead-open!
  "Symmetric AEAD open. See ns docstring for input shape."
  [{:crypto/keys [adapter] :as op}]
  (proto/crypto-decrypt!
   adapter
   (merge {:crypto/algorithm :xchacha20-poly1305} (dissoc op :crypto/adapter))))

;; -----------------------------------------------------------------------------
;; HPKE (asymmetric / hybrid) DSL

(defn hpke-seal!
  "Hybrid public-key seal. See ns docstring for input shape."
  [{:crypto/keys [adapter] :as op}]
  (proto/crypto-encrypt!
   adapter
   (merge {:crypto/algorithm :hpke-x25519} (dissoc op :crypto/adapter))))

(defn hpke-open!
  "Hybrid public-key open. See ns docstring for input shape."
  [{:crypto/keys [adapter] :as op}]
  (proto/crypto-decrypt!
   adapter
   (merge {:crypto/algorithm :hpke-x25519} (dissoc op :crypto/adapter))))

;; -----------------------------------------------------------------------------
;; Hash

(defn sha256
  "SHA-256 hash. See ns docstring."
  [{:crypto/keys [adapter] :as op}]
  (proto/crypto-hash
   adapter
   (merge {:crypto/algorithm :sha256} (dissoc op :crypto/adapter))))

(defn sign!
  "Ed25519 sign `:crypto/data` with the issuer `:crypto/keypair`
   `{:public ^bytes :private ^bytes}`. Returns Result<{:crypto/signature ^bytes}>."
  [{:crypto/keys [adapter] :as op}]
  (proto/crypto-sign!
   adapter
   (merge {:crypto/algorithm :ed25519} (dissoc op :crypto/adapter))))

(defn verify
  "Ed25519 verify `:crypto/signature` against `:crypto/data` with the issuer
   `:crypto/pubkey` (32-byte ^bytes). Returns Result<{:crypto/valid? boolean}>."
  [{:crypto/keys [adapter] :as op}]
  (proto/crypto-verify
   adapter
   (merge {:crypto/algorithm :ed25519} (dissoc op :crypto/adapter))))

(defn kdf-hkdf-sha256
  "HKDF-SHA256 key derivation (RFC 5869). See ns docstring for op-map shape.

   Required: :crypto/adapter :crypto/ikm :crypto/length.
   Optional: :crypto/salt :crypto/info (each ^bytes-or-nil).

   Returns Result<{:crypto/key ^bytes :crypto/algorithm :hkdf-sha256}>."
  [{:crypto/keys [adapter] :as op}]
  (proto/crypto-derive-key
   adapter
   (merge {:crypto/algorithm :hkdf-sha256} (dissoc op :crypto/adapter))))

(defn pwhash-argon2id
  "Argon2id v1.3 password-hash. See ns docstring for op-map shape.

   Required: :crypto/adapter :crypto/password :crypto/salt
             :crypto/ops-limit :crypto/mem-limit :crypto/length.

   Returns Result<{:crypto/hash ^bytes :crypto/algorithm :argon2id}>.
   May return {:error :crypto/unsupported ...} on adapters without
   native Argon2id (e.g. Tink) — callers must handle that explicitly."
  [{:crypto/keys [adapter] :as op}]
  (proto/crypto-password-hash
   adapter
   (merge {:crypto/algorithm :argon2id} (dissoc op :crypto/adapter))))