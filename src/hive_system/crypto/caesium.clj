(ns hive-system.crypto.caesium
  "Caesium / libsodium-backed implementation of `hive-system.protocols/ICrypto`.

   Uses parameter-object map signatures (`:crypto/*` keys) like the rest of
   the crypto layer. Loads caesium lazily via `requiring-resolve` so absence
   of native libsodium only fails at construction (`->caesium-crypto`).

   Algorithms supported:
     :xchacha20-poly1305  — caesium.crypto.aead/xchacha20poly1305-ietf-{encrypt,decrypt}"
  (:require [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [hive-system.crypto.kdf :as kdf]))

(def ^:private xchacha-key-size 32)
(def ^:private xchacha-nonce-size 24)

(defn- byte-array? [x]
  (and (some? x) (= (Class/forName "[B") (class x))))

(defn- resolve-aead!
  "Returns {:encrypt fn :decrypt fn :keygen fn :nonce-gen fn} or throws."
  []
  (let [load (fn [sym]
               (or (requiring-resolve sym)
                   (throw (ex-info "caesium not on classpath" {:sym sym}))))]
    {:encrypt   (load 'caesium.crypto.aead/xchacha20poly1305-ietf-encrypt)
     :decrypt   (load 'caesium.crypto.aead/xchacha20poly1305-ietf-decrypt)
     :keygen    (load 'caesium.crypto.aead/xchacha20poly1305-ietf-keygen)
     :nonce-gen (load 'caesium.crypto.aead/new-xchacha20poly1305-ietf-nonce)}))

(defn- resolve-pwhash!
  "Returns {:pwhash fn :alg-argon2id13 int :salt-bytes int} or throws."
  []
  (let [load (fn [sym]
               (or (requiring-resolve sym)
                   (throw (ex-info "caesium not on classpath" {:sym sym}))))
        pwhash-var     (load 'caesium.crypto.pwhash/pwhash)
        alg-var        (load 'caesium.crypto.pwhash/alg-argon2id13)
        salt-bytes-var (load 'caesium.crypto.pwhash/saltbytes)]
    {:pwhash         pwhash-var
     :alg-argon2id13 @alg-var
     :salt-bytes     @salt-bytes-var}))

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

(defn- xchacha-encrypt [aead-fns {:crypto/keys [key plaintext aad]}]
  (r/let-ok [_ (check-key key)]
   (try
     (let [^bytes nonce ((:nonce-gen aead-fns))
           ^bytes ct    ((:encrypt aead-fns) plaintext (or aad (byte-array 0)) nonce key)]
       (r/ok {:crypto/ciphertext ct :crypto/iv nonce}))
     (catch Throwable t
       (r/err :crypto/encrypt-threw {:message (.getMessage t)})))))

(defn- xchacha-decrypt [aead-fns {:crypto/keys [key ciphertext iv aad]}]
  (r/let-ok [_ (check-key key)
             _ (check-nonce iv)]
   (try
     (let [^bytes pt ((:decrypt aead-fns) ciphertext (or aad (byte-array 0)) iv key)]
       (r/ok {:crypto/plaintext pt}))
     (catch RuntimeException e
       (r/err :crypto/tampered {:reason :bad-tag :message (.getMessage e)}))
     (catch Throwable t
       (r/err :crypto/decrypt-threw {:message (.getMessage t)})))))

(defn- hkdf-derive
  [{:crypto/keys [ikm salt info length]}]
  (cond
    (not (byte-array? ikm))
    (r/err :crypto/bad-input {:reason :ikm-not-byte-array})

    (and (some? salt) (not (byte-array? salt)))
    (r/err :crypto/bad-input {:reason :salt-not-byte-array})

    (and (some? info) (not (byte-array? info)))
    (r/err :crypto/bad-input {:reason :info-not-byte-array})

    (or (not (integer? length)) (not (pos? length)))
    (r/err :crypto/bad-input {:reason :length-must-be-positive-integer
                              :length length})

    (> length kdf/MAX_LENGTH)
    (r/err :crypto/bad-input {:reason :length-exceeds-hkdf-max
                              :length length :max kdf/MAX_LENGTH})

    :else
    (try
      (r/ok {:crypto/key (kdf/hkdf-sha256 salt ikm info (long length))
             :crypto/algorithm :hkdf-sha256})
      (catch Throwable t
        (r/err :crypto/derive-key-threw {:message (.getMessage t)})))))

(defn- argon2id-hash
  [pwhash-fns {:crypto/keys [password salt ops-limit mem-limit length]}]
  (let [{:keys [pwhash alg-argon2id13 salt-bytes]} pwhash-fns]
    (cond
      (not (byte-array? password))
      (r/err :crypto/bad-input {:reason :password-not-byte-array})

      (not (byte-array? salt))
      (r/err :crypto/bad-input {:reason :salt-not-byte-array})

      (not= salt-bytes (alength ^bytes salt))
      (r/err :crypto/bad-salt-size {:expected salt-bytes
                                    :actual (alength ^bytes salt)})

      (or (not (integer? ops-limit)) (not (pos? ops-limit)))
      (r/err :crypto/bad-input {:reason :ops-limit-must-be-positive-integer})

      (or (not (integer? mem-limit)) (not (pos? mem-limit)))
      (r/err :crypto/bad-input {:reason :mem-limit-must-be-positive-integer})

      (or (not (integer? length)) (not (pos? length)))
      (r/err :crypto/bad-input {:reason :length-must-be-positive-integer})

      :else
      (try
        (let [^bytes h (pwhash (long length) password salt
                               (long ops-limit) (long mem-limit) alg-argon2id13)]
          (r/ok {:crypto/hash h :crypto/algorithm :argon2id}))
        (catch Throwable t
          (r/err :crypto/password-hash-threw {:message (.getMessage t)}))))))

(defrecord CaesiumCrypto [aead-fns pwhash-fns]
  proto/ICrypto
  (crypto-hash [_ {:crypto/keys [algorithm]}]
    (r/err :crypto/unsupported {:algorithm algorithm :op :hash
                                :note "use TinkCrypto or caesium.crypto.generichash directly"}))
  (crypto-sign! [_ {:crypto/keys [algorithm]}]
    (r/err :crypto/unsupported {:algorithm algorithm :op :sign}))
  (crypto-verify [_ {:crypto/keys [algorithm]}]
    (r/err :crypto/unsupported {:algorithm algorithm :op :verify}))
  (crypto-encrypt! [_ {:crypto/keys [algorithm] :as op}]
    (case algorithm
      :xchacha20-poly1305 (xchacha-encrypt aead-fns op)
      (r/err :crypto/unsupported {:algorithm algorithm :op :encrypt})))
  (crypto-decrypt! [_ {:crypto/keys [algorithm] :as op}]
    (case algorithm
      :xchacha20-poly1305 (xchacha-decrypt aead-fns op)
      (r/err :crypto/unsupported {:algorithm algorithm :op :decrypt})))
  (crypto-derive-key [_ {:crypto/keys [algorithm] :as op}]
    (case algorithm
      :hkdf-sha256 (hkdf-derive op)
      (r/err :crypto/unsupported {:algorithm algorithm :op :derive-key})))
  (crypto-password-hash [_ {:crypto/keys [algorithm] :as op}]
    (case algorithm
      :argon2id (argon2id-hash pwhash-fns op)
      (r/err :crypto/unsupported {:algorithm algorithm :op :password-hash}))))

(defn ->caesium-crypto
  "Construct a caesium-backed ICrypto. Throws if caesium / libsodium not
   available on the classpath / native lib path. Resolves both AEAD and
   pwhash (Argon2id) primitives at construction; HKDF is pure-Java and
   needs no native binding."
  []
  (->CaesiumCrypto (resolve-aead!) (resolve-pwhash!)))