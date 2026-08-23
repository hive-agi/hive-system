(ns hive-system.shell.tools
  "Tool provisioning: descriptions and install hints per package manager.

   (require-tool :ripgrep) => (ok {:path \"/usr/bin/rg\"})
                            or (err :tool/missing {:hints [...]})

   What a tool is CALLED is not stated here — it is one fact, owned by
   `shell.binary`, which `shell.search` reads too. This namespace answers
   \"is it here, and how do I install it\"; that one answers \"what is it
   called\"."
  (:require [hive-system.shell.binary :as binary]
            [hive-system.shell.detect :as detect]
            [hive-dsl.result :as r]
            [clojure.string :as str]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(def ^:private tool-registry
  "Known tools with their descriptions and install commands per package manager.

   A tool's BINARY NAMES are not here. They live in `shell.binary`, keyed by
   the same id (aliases included, so `:ripgrep` resolves), and every consumer
   that needs a name asks for one rather than reading it off this map."
  {:ripgrep    {:desc "Fast recursive grep"
                :install {:brew "brew install ripgrep"
                          :apt "sudo apt install ripgrep"
                          :cargo "cargo install ripgrep"
                          :pacman "sudo pacman -S ripgrep"
                          :nix "nix-env -iA nixpkgs.ripgrep"}}
   ;; The apt hint names a package that does not put an `fd` on PATH — Debian
   ;; installs it as `fdfind`. That rename is `shell.binary`'s `:binary/alts`.
   :fd         {:desc "Fast find alternative"
                :install {:brew "brew install fd"
                          :apt "sudo apt install fd-find"
                          :cargo "cargo install fd-find"
                          :pacman "sudo pacman -S fd"
                          :nix "nix-env -iA nixpkgs.fd"}}
   :jq         {:desc "JSON processor"
                :install {:brew "brew install jq"
                          :apt "sudo apt install jq"
                          :pacman "sudo pacman -S jq"
                          :nix "nix-env -iA nixpkgs.jq"}}
   :tree       {:desc "Directory tree listing"
                :install {:brew "brew install tree"
                          :apt "sudo apt install tree"
                          :pacman "sudo pacman -S tree"}}
   :fzf        {:desc "Fuzzy finder"
                :install {:brew "brew install fzf"
                          :apt "sudo apt install fzf"
                          :cargo "cargo install skim"
                          :pacman "sudo pacman -S fzf"}}
   ;; The apt hint has fd's shape for the same reason: Debian installs this as
   ;; `batcat`, the `bat` name belonging to bacula-console-qt.
   :bat        {:desc "Cat with syntax highlighting"
                :install {:brew "brew install bat"
                          :apt "sudo apt install bat"
                          :cargo "cargo install bat"
                          :pacman "sudo pacman -S bat"}}
   :delta      {:desc "Better git diff viewer"
                :install {:brew "brew install git-delta"
                          :apt "sudo apt install git-delta"
                          :cargo "cargo install git-delta"}}
   :htop       {:desc "Interactive process viewer"
                :install {:brew "brew install htop"
                          :apt "sudo apt install htop"
                          :pacman "sudo pacman -S htop"}}
   :dust       {:desc "Intuitive disk usage (du alternative)"
                :install {:brew "brew install dust"
                          :cargo "cargo install du-dust"}}
   :procs      {:desc "Modern process viewer (ps alternative)"
                :install {:brew "brew install procs"
                          :cargo "cargo install procs"}}
   :sd         {:desc "Intuitive find-and-replace (sed alternative)"
                :install {:brew "brew install sd"
                          :cargo "cargo install sd"}}
   :tokei      {:desc "Code statistics (cloc alternative)"
                :install {:brew "brew install tokei"
                          :cargo "cargo install tokei"}}
   :kubectl    {:desc "Kubernetes CLI"
                :install {:brew "brew install kubectl"
                          :apt "sudo snap install kubectl --classic"}}
   :cloudflared {:desc "Cloudflare tunnel client"
                 :install {:brew "brew install cloudflared"
                           :apt "see https://pkg.cloudflare.com/"}}
   :tmux       {:desc "Terminal multiplexer"
                :install {:brew "brew install tmux"
                          :apt "sudo apt install tmux"
                          :pacman "sudo pacman -S tmux"}}
   ;; Core system tools (usually present, but check anyway)
   :find       {:desc "File finder"     :install {}}
   :ls         {:desc "List directory"  :install {}}
   :grep       {:desc "Pattern matcher" :install {}}
   :ps         {:desc "Process status"  :install {}}
   :git        {:desc "Version control"
                :install {:brew "brew install git"
                          :apt "sudo apt install git"}}})

(defn- install-hints
  "Generate install hints for a tool based on available package managers."
  [tool-key available-mgrs]
  (let [tool (get tool-registry tool-key)
        installs (:install tool {})]
    (->> available-mgrs
         (keep (fn [[mgr _path]]
                 (when-let [cmd (get installs mgr)]
                   {:manager mgr :command cmd})))
         vec)))

(defn require-tool
  "Check if a tool is available. Returns (ok {:path ... :bin ...})
   or (err :tool/missing {:tool ... :hints ...}).

   The `:bin` in a successful Result is the name that actually ANSWERED, which
   on a distro that renamed the program is not the upstream one — spawn THAT.
   The names probed, and their order, come from `shell.binary`.

   Available package managers are detected once and cached."
  ([tool-key] (require-tool tool-key nil))
  ([tool-key pkg-managers]
   (let [tool  (get tool-registry tool-key)
         found (when tool (binary/locate tool-key))]
     (cond
       (nil? tool)
       (r/err :tool/unknown {:tool tool-key
                             :available (vec (keys tool-registry))})

       (r/ok? found)
       (r/ok (assoc (:ok found) :tool tool-key :desc (:desc tool)))

       :else
       (let [mgrs  (or pkg-managers (detect/detect-pkg-managers))
             hints (install-hints tool-key mgrs)
             tried (or (binary/names tool-key) [])]
         (r/err :tool/missing
                {:tool tool-key
                 :bin (binary/bin tool-key)
                 :tried tried
                 :desc (:desc tool)
                 :hints hints
                 :message (if (seq hints)
                            (str (str/join " / " tried) " not found. Install with: "
                                 (:command (first hints)))
                            (str (str/join " / " tried)
                                 " not found and no known install method available"))}))))))

(defn require-tools
  "Check multiple tools at once. Returns a map of {:available {...} :missing {...}}."
  [tool-keys]
  (let [mgrs (detect/detect-pkg-managers)
        results (into {} (map (fn [k] [k (require-tool k mgrs)]) tool-keys))]
    {:available (into {} (filter (fn [[_ v]] (r/ok? v)) results))
     :missing   (into {} (filter (fn [[_ v]] (r/err? v)) results))}))

(defn list-tools
  "List all registered tools with their availability status.

   `:bin` is the upstream name; `:resolved-bin` is the name that answered here,
   present only when the two differ. Availability is decided by probing every
   name the tool goes by — probing `:bin` alone reported a distro-renamed tool
   as unavailable while `require-tool` found it, so the two disagreed about the
   same machine."
  []
  (mapv (fn [[k {:keys [desc]}]]
          (let [canonical (binary/bin k)
                found     (binary/locate k)
                ok?       (r/ok? found)
                resolved  (when ok? (:bin (:ok found)))]
            (cond-> {:tool k
                     :bin canonical
                     :desc desc
                     :available? ok?
                     :path (when ok? (:path (:ok found)))}
              (and resolved (not= resolved canonical))
              (assoc :resolved-bin resolved))))
        (sort-by key tool-registry)))

(defn register-tool!
  "Dynamically register a new tool. Returns SPEC.

   `:bin` and `:bin-alts` are forwarded to `shell.binary` and are NOT stored
   here, so a name declared through this call is the same fact `shell.search`
   reads. Omit them for a tool whose id is already a registered identity."
  [tool-key {:keys [bin bin-alts desc install] :as spec}]
  (when bin
    (binary/register! (cond-> #:binary{:id tool-key :bin bin}
                        (seq bin-alts) (assoc :binary/alts (vec bin-alts)))))
  (alter-var-root #'tool-registry assoc tool-key {:desc desc :install (or install {})})
  spec)
