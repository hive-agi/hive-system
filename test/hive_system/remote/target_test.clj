(ns hive-system.remote.target-test
  "argv built from a HostTarget: pinned cases, a property over generated
   targets, and mutants the property must kill."
  (:require [clojure.test :refer [deftest is]]
            [clojure.test.check.generators :as gen]
            [hive-system.remote.target :as t]
            [hive-test.trifecta :refer [deftrifecta]]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(defn exec-argv*
  "Unary port over `t/exec-argv` for the trifecta."
  [[target cmd]]
  (t/exec-argv target cmd))

(def ^:private gen-name
  (gen/fmap #(apply str "h" %) (gen/vector gen/char-alphanumeric 1 8)))

(def ^:private gen-target
  (gen/let [host gen-name
            user (gen/one-of [(gen/return nil) gen-name])
            port (gen/one-of [(gen/return nil) (gen/choose 1 65535)])
            idf  (gen/one-of [(gen/return nil) (gen/fmap #(str "/k/" %) gen-name)])]
    (cond-> {:host host}
      user (assoc :user user)
      port (assoc :port port)
      idf  (assoc :identity-file idf))))

(def ^:private gen-cmd
  (gen/one-of [(gen/vector (gen/elements ["echo" "a b" "it's" "$HOME" "x;y"]) 1 4)
               (gen/return "uname -a")]))

(defn- well-formed?
  "argv invariant: ssh first, BatchMode on, `--` then destination then the
   remote command, and the port flag iff a port is given."
  [[target cmd] argv]
  (let [n (count argv)]
    (and (= "ssh" (first argv))
         (some #{"BatchMode=yes"} argv)
         (= "--" (nth argv (- n 3)))
         (= (t/destination target) (nth argv (- n 2)))
         (= (t/remote-command cmd) (peek argv))
         (= (boolean (:port target))
            (boolean (some #{"-p"} (butlast (butlast (butlast argv)))))))))

(deftrifecta exec-argv-shape
  hive-system.remote.target-test/exec-argv*
  {:cases {[{:host "h"} ["true"]]
           ["ssh" "-o" "BatchMode=yes" "--" "h" "true"]

           [{:host "h" :user "u" :port 2222 :identity-file "/k/id"} ["echo" "a b"]]
           ["ssh" "-o" "BatchMode=yes" "-i" "/k/id" "-p" "2222" "--" "u@h" "echo 'a b'"]

           [{:host "h" :connect-timeout-s 5 :options {"StrictHostKeyChecking" "accept-new"}} "uname -a"]
           ["ssh" "-o" "BatchMode=yes" "-o" "ConnectTimeout=5"
            "-o" "StrictHostKeyChecking=accept-new" "--" "h" "uname -a"]}
   :gen (gen/tuple gen-target gen-cmd)
   :pred (fn [argv] (vector? argv))
   :num-tests 200})

(deftest exec-argv-property-holds-for-generated-targets
  (doseq [input (gen/sample (gen/tuple gen-target gen-cmd) 200)]
    (is (well-formed? input (exec-argv* input)) (pr-str input))))

(deftest exec-argv-invariant-kills-mutants
  (let [input [{:host "h" :user "u" :port 22} ["echo" "a b"]]
        good  (exec-argv* input)]
    (is (well-formed? input good))
    (is (not (well-formed? input (vec (remove #{"--"} good)))) "drops the option terminator")
    (is (not (well-formed? input (conj (pop good) "echo a b"))) "unquoted argv")
    (is (not (well-formed? input (vec (remove #{"-p" "22"} good)))) "drops the port")
    (is (not (well-formed? input (vec (remove #{"BatchMode=yes" "-o"} good)))) "interactive prompts allowed")))

(deftest scp-argv-uses-capital-P-and-host-colon-path
  (is (= ["scp" "-o" "BatchMode=yes" "-P" "2222" "--" "/l/a.jar" "u@h:/r/a.jar"]
         (t/put-argv {:host "h" :user "u" :port 2222} "/l/a.jar" "/r/a.jar")))
  (is (= ["scp" "-o" "BatchMode=yes" "--" "h:/r/log" "/l/log"]
         (t/get-argv {:host "h"} "/r/log" "/l/log"))))

(deftest forward-argv-binds-loopback-and-fails-loudly
  (is (= ["ssh" "-o" "BatchMode=yes" "-N" "-o" "ExitOnForwardFailure=yes"
          "-L" "127.0.0.1:17888:127.0.0.1:7888" "--" "h"]
         (t/forward-argv {:host "h"} 17888 7888 "127.0.0.1"))))
