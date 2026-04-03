(ns hive-system.protocols-test
  "Protocol definition tests — verify protocols are loadable and satisfiable."
  (:require [clojure.test :refer [deftest is testing]]
            [hive-system.protocols :as proto]))

(deftest protocols-loadable
  (testing "All protocols are defined and resolve"
    (is (some? proto/IJournal))
    (is (some? proto/IProcess))
    (is (some? proto/INetwork))
    (is (some? proto/IFilesystem))
    (is (some? proto/IShell))
    (is (some? proto/ICrypto))))
