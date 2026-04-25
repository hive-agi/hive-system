(ns hive-system.deps.protocols-test
  "Smoke tests for the protocol surface — that the protocols are
   defined, that they expose the documented method names, and that
   reify-based fakes can satisfy them.

   Behavioural tests live in `core_test`; this file just locks down
   the API shape so a future refactor can't silently delete a method."
  (:require [clojure.test :refer [deftest is testing]]
            [hive-dsl.result :as r]
            [hive-system.deps.protocols :as proto]))

;; =============================================================================
;; IDistroDetector
;; =============================================================================

(deftest idistrodetector-exists
  (testing "IDistroDetector protocol is defined"
    (is (some? (resolve 'hive-system.deps.protocols/IDistroDetector)))))

(deftest idistrodetector-detect-distro
  (testing "a reify can satisfy IDistroDetector and detect-distro returns Result"
    (let [d (reify proto/IDistroDetector
              (detect-distro [_] (r/ok :apt)))
          result (proto/detect-distro d)]
      (is (r/ok? result))
      (is (= :apt (:ok result))))))

;; =============================================================================
;; IPackageInstaller
;; =============================================================================

(deftest ipackageinstaller-exists
  (testing "IPackageInstaller protocol is defined"
    (is (some? (resolve 'hive-system.deps.protocols/IPackageInstaller)))))

(deftest ipackageinstaller-methods
  (testing "a reify can satisfy IPackageInstaller and expose family + install!"
    (let [calls (atom [])
          inst (reify proto/IPackageInstaller
                 (installer-family [_] :apt)
                 (install! [_ pkg]
                   (swap! calls conj pkg)
                   (r/ok {:pkg pkg :installer :apt :stdout "" :stderr ""})))]
      (is (= :apt (proto/installer-family inst)))
      (let [result (proto/install! inst "ssh")]
        (is (r/ok? result))
        (is (= "ssh" (get-in result [:ok :pkg])))
        (is (= ["ssh"] @calls))))))

;; =============================================================================
;; IDependencyEnsurer
;; =============================================================================

(deftest idependencyensurer-exists
  (testing "IDependencyEnsurer protocol is defined"
    (is (some? (resolve 'hive-system.deps.protocols/IDependencyEnsurer)))))

(deftest idependencyensurer-ensure-bang
  (testing "a reify can satisfy IDependencyEnsurer and ensure! returns Result"
    (let [e (reify proto/IDependencyEnsurer
              (ensure! [_ specs]
                (r/ok {:installed []
                       :already-present (mapv :cmd specs)
                       :failed []})))
          result (proto/ensure! e [{:cmd "ssh"} {:cmd "git"}])]
      (is (r/ok? result))
      (is (= ["ssh" "git"] (get-in result [:ok :already-present]))))))
