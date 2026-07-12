(ns build
  (:require [clojure.tools.build.api :as b]
            [clojure.string :as str]))

(def lib 'io.github.hive-agi/hive-system)
(def version (str/trim (slurp "VERSION")))
(def class-dir "target/classes")
(def jar-file (format "target/%s-%s.jar" (name lib) version))
(def basis (delay (b/create-basis {:project "deps.edn"})))

(def pom-data
  [[:description
    (str "Temporal execution fabric and systems-programming foundation for Clojure: "
         "Datahike-backed journaling of operations with a ROP Result ADT, plus "
         "protocol-based wrappers for process, shell, network, filesystem, crypto, "
         "secrets and GPU.")]
   [:url "https://github.com/hive-agi/hive-system"]
   [:licenses
    [:license
     [:name "MIT"]
     [:url "https://opensource.org/license/mit"]]]
   [:scm
    [:url "https://github.com/hive-agi/hive-system"]
    [:connection "scm:git:git://github.com/hive-agi/hive-system.git"]
    [:developerConnection "scm:git:ssh://git@github.com/hive-agi/hive-system.git"]
    [:tag (str "v" version)]]
   [:developers
    [:developer
     [:name "Pedro G. Branquinho"]]]])

(defn clean [_]
  (b/delete {:path "target"}))

(defn jar
  "Build the library thin jar + pom for Clojars/Maven consumption."
  [_]
  (clean nil)
  (b/write-pom {:class-dir class-dir
                :lib lib
                :version version
                :basis @basis
                :src-dirs ["src"]
                :pom-data pom-data})
  (b/copy-dir {:src-dirs ["src"]
               :target-dir class-dir})
  (b/jar {:class-dir class-dir
          :jar-file jar-file})
  (println (str "Built " jar-file)))

(defn deploy
  "Deploy the library jar to Clojars. Requires CLOJARS_USERNAME + CLOJARS_PASSWORD
   (a Clojars deploy token) in the environment."
  [_]
  (jar nil)
  ((requiring-resolve 'deps-deploy.deps-deploy/deploy)
   {:installer :remote
    :artifact  jar-file
    :pom-file  (b/pom-path {:lib lib :class-dir class-dir})})
  (println (str "Deployed " lib " " version " to Clojars")))
