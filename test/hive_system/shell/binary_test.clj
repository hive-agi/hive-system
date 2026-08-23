(ns hive-system.shell.binary-test
  "Binary identity, and the property the extraction exists to buy.

   `shell.tools` and `shell.search` both used to assert what a program is
   called. The fd/fdfind rename was therefore a bug in both, and got two
   unrelated fixes in one sitting. The tests that matter here are not the
   accessors — they are the COUPLING ones: correct a name once and both
   registries must follow, drop it once and both must refuse together. A pair
   that can disagree is the defect coming back.

   The host is reached through `IProgramProbe`, so every test below injects a
   stub record rather than redefining somebody's var. That also buys the
   ordering assertions: a RECORDING decorator can say which names were probed
   and in what order, which a redef of `which` cannot."
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.test.check.generators :as gen]
            [malli.generator :as mg]
            [hive-schemas.test :refer [deftrifecta-from-schema]]
            [hive-test.mutation :refer [deftest-mutations]]
            [hive-test.properties :refer [defprop-total]]
            [hive-dsl.result :as r]
            [hive-system.shell.binary :as binary :refer [-probe]]
            [hive-system.shell.search :as search]
            [hive-system.shell.tools :as tools]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

;;; =============================================================================
;;; Stubs — the port, not the concretion
;;; =============================================================================

(defrecord PresentProbe [present]
  binary/IProgramProbe
  (-probe [_ n]
    (if (contains? present n)
      (r/ok {:path (str "/hive-test/" n) :program n})
      (r/err :shell/not-found {:program n}))))

(defrecord RecordingProbe [inner log]
  binary/IProgramProbe
  (-probe [_ n]
    (swap! log conj n)
    (-probe inner n)))

(defn- present
  "A probe answering for exactly these program names."
  [& names]
  (->PresentProbe (set names)))

(defn- with-binary
  "Register B for the duration of F, restoring whatever was there."
  [b f]
  (let [id   (:binary/id b)
        prev (binary/lookup id)]
    (try
      (binary/register! b)
      (f)
      (finally
        (binary/unregister! id)
        (when prev (binary/register! prev))))))

;;; =============================================================================
;;; The coupling — the reason this namespace exists
;;; =============================================================================

(deftest one-correction-reaches-both-registries
  ;; ONE edit to the identity. Both projections must see it, or the fact is
  ;; still stated twice and the next distro rename is still two bugs.
  (with-binary
    #:binary{:id :fd :bin "fd" :alts ["fdfind" "hive-test-fd"]}
    (fn []
      (binding [binary/*probe* (present "hive-test-fd")]
        (testing "shell.tools finds the program under the newly declared name"
          (let [res (tools/require-tool :fd)]
            (is (r/ok? res))
            (is (= "hive-test-fd" (:bin (:ok res))))))
        (testing "shell.search finds it too, from the same declaration"
          (is (= "hive-test-fd" (:ok (search/executable :fd)))))))))

(deftest dropping-the-name-refuses-in-both-registries-identically
  ;; The negative control for the test above. If only one of them went missing,
  ;; the other would be reading a second copy of the name.
  (with-binary
    #:binary{:id :fd :bin "hive-test-absent-fd"}
    (fn []
      (binding [binary/*probe* (present)]
        (let [t (tools/require-tool :fd)
              s (search/executable :fd)]
          (is (r/err? t))
          (is (r/err? s))
          (is (= ["hive-test-absent-fd"] (:tried t)))
          (is (= ["hive-test-absent-fd"] (:tried s))
              "both refusals name the same names, because there is one list"))))))

(deftest the-argv-canonical-name-follows-the-identity-too
  ;; argv[0] in `argv` (as opposed to `spawn-argv`) is the canonical name, and
  ;; it is read through the registry rather than stored on the profile.
  (is (= "rg" (first (:ok (search/argv :rg [:+ :digit] {})))))
  (with-binary
    #:binary{:id :rg :bin "hive-test-rg" :aliases #{:ripgrep}}
    (fn []
      (is (= "hive-test-rg" (first (:ok (search/argv :rg [:+ :digit] {}))))
          "a profile registered before the correction still emits the corrected name")
      (is (= "hive-test-rg" (:ok (search/bin :rg)))))))

;;; =============================================================================
;;; Aliases — the two registries disagree on the ID, and that is allowed
;;; =============================================================================

(deftest an-alias-and-its-canonical-id-are-the-same-identity
  ;; shell.tools keyed ripgrep :ripgrep before shell.search keyed it :rg.
  ;; Unifying the identity did not require either to rename its key.
  (is (= (binary/lookup :rg) (binary/lookup :ripgrep)))
  (is (= "rg" (binary/bin :ripgrep) (binary/bin :rg)))
  (is (= :rg (:binary/id (binary/lookup :ripgrep)))
      "the value always names its own canonical id, whichever key found it"))

(deftest canonical-excludes-alias-keys
  (let [c (binary/canonical)]
    (is (contains? c :rg))
    (is (not (contains? c :ripgrep)))
    (is (every? (fn [[k v]] (= k (:binary/id v))) c))))

(deftest unregistering-drops-every-key-that-pointed-at-it
  (with-binary
    #:binary{:id :hive-test-multi :bin "htm" :aliases #{:hive-test-multi-alias}}
    (fn []
      (is (some? (binary/lookup :hive-test-multi-alias)))))
  (is (nil? (binary/lookup :hive-test-multi)))
  (is (nil? (binary/lookup :hive-test-multi-alias))
      "an alias left behind would resolve to a program nobody declares"))

;;; =============================================================================
;;; Promote — pure, and covered from the schemas the SOURCE already declares
;;; =============================================================================

;; `Binary`, `ProgramNames` and `BinaryKeys` are imported, never restated here.
;; They are the same defs `m/=>` contracts the subjects with, so the generator,
;; the oracle and the mutants cannot drift from what production asserts.

;; `:mutation false` on all three, and it is asked for rather than defaulted:
;; these subjects return a string and vectors of strings, which are
;; structurally mutant-free, so `schema-mutants` derives NOTHING from them and
;; the facet would be a green row asserting nothing. The macro's
;; `-mutants-present` guard says exactly that rather than letting it pass. The
;; teeth here are the `:rel`s below plus `names-of-survives-no-mutant`, which
;; mutates the SUBJECT instead of the output schema.

(deftrifecta-from-schema names-of binary/names-of
  {:in  binary/Binary
   :out binary/ProgramNames
   :mutation false
   :rel (fn [b out]
          (and (= (:binary/bin b) (first out))
               (= (vec (:binary/alts b)) (vec (rest out)))))})

(deftrifecta-from-schema bin-of binary/bin-of
  {:in  binary/Binary
   :out :string
   :mutation false
   :rel (fn [b out] (= (:binary/bin b) out))})

(deftrifecta-from-schema keys-of binary/keys-of
  {:in  binary/Binary
   :out binary/BinaryKeys
   :mutation false
   :rel (fn [b out]
          (and (= (:binary/id b) (first out))
               (= (set (:binary/aliases b)) (set (rest out)))))})

(deftest-mutations names-of-survives-no-mutant
  binary/names-of
  [["canonical-only" (fn [b] [(:binary/bin b)])]
   ["alts-only"      (fn [b] (vec (:binary/alts b)))]
   ["reversed"       (fn [b] (vec (reverse (into [(:binary/bin b)] (:binary/alts b)))))]
   ["deduped-set"    (fn [b] (vec (set (into [(:binary/bin b)] (:binary/alts b)))))]]
  (fn []
    ;; The probe ORDER is the whole contract: upstream first, then each alt in
    ;; the order declared. Every mutant above breaks that and nothing else.
    (let [b #:binary{:id :fd :bin "fd" :alts ["fdfind" "fd-find"]}]
      (is (= ["fd" "fdfind" "fd-find"] (binary/names-of b)))
      (is (= "fd" (first (binary/names-of b)))))))

(deftest the-generator-actually-produces-the-multi-name-case
  ;; Non-vacuity. `:binary/alts` and `:binary/aliases` are OPTIONAL, so a
  ;; generator that never emits them would satisfy every relation above by
  ;; way of the single-element branch alone, and the fd/fdfind case — the one
  ;; this namespace exists for — would go untested while reading as covered.
  (let [sample (gen/sample (mg/generator binary/Binary) 200)]
    (is (some (comp seq :binary/alts) sample)
        "no generated Binary carried alts, so the multi-name branch never ran")
    (is (some (comp seq :binary/aliases) sample)
        "no generated Binary carried aliases, so keys-of only ever saw its id")))

(deftest located-is-nil-for-a-refusal-and-names-the-answering-program
  (is (nil? (binary/located "fd" (r/err :shell/not-found {}))))
  (is (= "fdfind"
         (:bin (:ok (binary/located "fdfind" (r/ok {:path "/usr/bin/fdfind"})))))))

;;; =============================================================================
;;; Boundary
;;; =============================================================================

(deftest locate-probes-upstream-first-and-stops-at-the-first-answer
  (let [log   (atom [])
        probe (->RecordingProbe (present "fd" "fdfind") log)
        res   (binary/locate :fd probe)]
    (is (= "fd" (:bin (:ok res))))
    (is (= ["fd"] @log)
        "the upstream name answered, so the alt must never have been probed")))

(deftest locate-falls-through-to-the-alt-and-reports-it
  (let [log   (atom [])
        probe (->RecordingProbe (present "fdfind") log)
        res   (binary/locate :fd probe)]
    (is (= "fdfind" (:bin (:ok res)))
        "callers spawn this, not the canonical name")
    (is (= ["fd" "fdfind"] @log)
        "and it got there by trying the canonical name first")))

(deftest an-unknown-id-and-an-absent-program-are-different-refusals
  ;; Collapsing these makes \"nobody declared it\" indistinguishable from \"we
  ;; looked and it is gone\".
  (let [unknown (binary/locate :hive-no-such-identity (present))
        absent  (binary/locate :fd (present))]
    (is (= :binary/unknown (:error unknown)))
    (is (seq (:known unknown)))
    (is (= :binary/not-installed (:error absent)))
    (is (= ["fd" "fdfind"] (:tried absent))))
  (is (nil? (binary/bin :hive-no-such-identity)))
  (is (nil? (binary/names :hive-no-such-identity))))

(deftest an-invalid-identity-is-refused-not-stored
  (let [res (binary/register! #:binary{:id :hive-test-bad :bin 42})]
    (is (r/err? res))
    (is (= :binary/invalid (:error res)))
    (is (nil? (binary/lookup :hive-test-bad))))
  (testing "and an undeclared key is refused rather than silently dropped"
    (let [res (binary/register! #:binary{:id :hive-test-extra :bin "x" :install "brew"})]
      (is (r/err? res))
      (is (nil? (binary/lookup :hive-test-extra))))))

;;; =============================================================================
;;; Non-vacuity
;;; =============================================================================

(deftest the-alts-machinery-has-a-producer
  ;; Every assertion about alt-name resolution above is worthless if no
  ;; built-in identity actually declares one.
  (let [with-alts (filter (comp seq :binary/alts val) (binary/canonical))]
    (is (seq with-alts)
        "some built-in must carry :binary/alts, or the alt path is never exercised")
    (is (contains? (set (map key with-alts)) :fd)))
  (testing "and the alias machinery has one too"
    (is (seq (filter (comp seq :binary/aliases val) (binary/canonical))))))

;;; =============================================================================
;;; Properties
;;; =============================================================================

(defprop-total locate-total-over-registered-ids
  (fn [id] (binary/locate id (present "fd" "rg")))
  (gen/elements (vec (keys (binary/registered))))
  {:num-tests 50
   :pred (fn [r] (or (r/ok? r) (r/err? r)))})

(defprop-total names-total-over-registered-ids
  binary/names
  (gen/elements (vec (keys (binary/registered))))
  {:num-tests 50
   :pred (fn [ns] (and (vector? ns) (seq ns) (every? string? ns)))})
