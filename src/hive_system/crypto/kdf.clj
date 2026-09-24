(ns hive-system.crypto.kdf
  "Pure-Java HKDF-SHA256 (RFC 5869). Shared by ICrypto adapters so that
   `crypto-derive-key` returns byte-identical bytes regardless of which
   adapter resolves the call.

   Public surface: `hkdf-sha256` (extract-then-expand) and its two RFC
   steps, `hkdf-extract` (§2.2) and `hkdf-expand` (§2.3). The steps are
   public because callers pin them to the RFC 5869 Appendix A vectors,
   which state the intermediate PRK as well as the OKM.

   Composed from `javax.crypto.Mac` HMAC-SHA256 — no native dependency."
  (:import (javax.crypto Mac)
           (javax.crypto.spec SecretKeySpec)))

(def ^:private ^:const HASH_LEN 32)
(def ^:const MAX_LENGTH (* 255 HASH_LEN))

(defn- hmac-sha256 ^bytes [^bytes k ^bytes m]
  (let [^Mac mac (Mac/getInstance "HmacSHA256")]
    (.init mac (SecretKeySpec. k "HmacSHA256"))
    (.doFinal mac m)))

(defn hkdf-extract
  "RFC 5869 §2.2 — PRK = HMAC-SHA256(salt, IKM).
   nil or zero-length salt ⇒ HashLen zero bytes (RFC 5869 default).
   HMAC-SHA256 rejects empty keys outright, so we substitute the default.

   Public so a caller can check the intermediate PRK against the RFC 5869
   Appendix A vectors, and can expand one PRK into several OKMs with
   `hkdf-expand` without extracting again."
  ^bytes [salt ikm]
  (let [salt (if (or (nil? salt) (zero? (alength ^bytes salt)))
               (byte-array HASH_LEN)
               salt)
        ikm  (or ikm (byte-array 0))]
    (hmac-sha256 salt ikm)))

(defn hkdf-expand
  "RFC 5869 §2.3 — OKM expansion. length ≤ 255 * HashLen.
   `prk` is a pseudorandom key of at least HashLen bytes, normally the
   output of `hkdf-extract`; a shorter one is rejected, as the RFC requires."
  ^bytes [^bytes prk info ^long length]
  (when (or (nil? prk) (< (alength prk) HASH_LEN))
    (throw (ex-info "HKDF PRK shorter than HashLen"
                    {:prk-length (some-> prk alength) :min HASH_LEN})))
  (when (> length MAX_LENGTH)
    (throw (ex-info "HKDF length exceeds 255*HashLen"
                    {:length length :max MAX_LENGTH})))
  (let [info     (or info (byte-array 0))
        info-len (alength ^bytes info)
        out      (byte-array length)
        n        (long (Math/ceil (/ (double length) (double HASH_LEN))))]
    (loop [i 1 prev (byte-array 0) pos 0]
      (if (> i n)
        out
        (let [prev-len (alength ^bytes prev)
              data     (byte-array (+ prev-len info-len 1))]
          (System/arraycopy prev 0 data 0 prev-len)
          (System/arraycopy info 0 data prev-len info-len)
          (aset-byte data (+ prev-len info-len) (unchecked-byte i))
          (let [t        (hmac-sha256 prk data)
                copy-len (min HASH_LEN (- length pos))]
            (System/arraycopy t 0 out pos copy-len)
            (recur (inc i) t (+ pos copy-len))))))))

(defn hkdf-sha256
  "RFC 5869 full HKDF-SHA256 = extract-then-expand."
  ^bytes [salt ikm info ^long length]
  (hkdf-expand (hkdf-extract salt ikm) info length))
