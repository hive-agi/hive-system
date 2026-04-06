(ns hive-system.shell.tools
  "Tool registry: maps tool names to their binaries, descriptions,
   and install hints per package manager.

   (require-tool :ripgrep) => (ok {:path \"/usr/bin/rg\"})
                            or (err :tool/missing {:hints [...]})"
  (:require [hive-system.shell.detect :as detect]
            [hive-dsl.result :as r]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: AGPL-3.0-or-later

(def ^:private tool-registry
  "Known tools with their binary names and install commands per package manager."
  {:ripgrep    {:bin "rg"
                :desc "Fast recursive grep"
                :install {:brew "brew install ripgrep"
                          :apt "sudo apt install ripgrep"
                          :cargo "cargo install ripgrep"
                          :pacman "sudo pacman -S ripgrep"
                          :nix "nix-env -iA nixpkgs.ripgrep"}}
   :fd         {:bin "fd"
                :desc "Fast find alternative"
                :install {:brew "brew install fd"
                          :apt "sudo apt install fd-find"
                          :cargo "cargo install fd-find"
                          :pacman "sudo pacman -S fd"
                          :nix "nix-env -iA nixpkgs.fd"}}
   :jq         {:bin "jq"
                :desc "JSON processor"
                :install {:brew "brew install jq"
                          :apt "sudo apt install jq"
                          :pacman "sudo pacman -S jq"
                          :nix "nix-env -iA nixpkgs.jq"}}
   :tree       {:bin "tree"
                :desc "Directory tree listing"
                :install {:brew "brew install tree"
                          :apt "sudo apt install tree"
                          :pacman "sudo pacman -S tree"}}
   :fzf        {:bin "fzf"
                :desc "Fuzzy finder"
                :install {:brew "brew install fzf"
                          :apt "sudo apt install fzf"
                          :cargo "cargo install skim"
                          :pacman "sudo pacman -S fzf"}}
   :bat        {:bin "bat"
                :desc "Cat with syntax highlighting"
                :install {:brew "brew install bat"
                          :apt "sudo apt install bat"
                          :cargo "cargo install bat"
                          :pacman "sudo pacman -S bat"}}
   :delta      {:bin "delta"
                :desc "Better git diff viewer"
                :install {:brew "brew install git-delta"
                          :apt "sudo apt install git-delta"
                          :cargo "cargo install git-delta"}}
   :htop       {:bin "htop"
                :desc "Interactive process viewer"
                :install {:brew "brew install htop"
                          :apt "sudo apt install htop"
                          :pacman "sudo pacman -S htop"}}
   :dust       {:bin "dust"
                :desc "Intuitive disk usage (du alternative)"
                :install {:brew "brew install dust"
                          :cargo "cargo install du-dust"}}
   :procs      {:bin "procs"
                :desc "Modern process viewer (ps alternative)"
                :install {:brew "brew install procs"
                          :cargo "cargo install procs"}}
   :sd         {:bin "sd"
                :desc "Intuitive find-and-replace (sed alternative)"
                :install {:brew "brew install sd"
                          :cargo "cargo install sd"}}
   :tokei      {:bin "tokei"
                :desc "Code statistics (cloc alternative)"
                :install {:brew "brew install tokei"
                          :cargo "cargo install tokei"}}
   :kubectl    {:bin "kubectl"
                :desc "Kubernetes CLI"
                :install {:brew "brew install kubectl"
                          :apt "sudo snap install kubectl --classic"}}
   :cloudflared {:bin "cloudflared"
                 :desc "Cloudflare tunnel client"
                 :install {:brew "brew install cloudflared"
                           :apt "see https://pkg.cloudflare.com/"}}
   :tmux       {:bin "tmux"
                :desc "Terminal multiplexer"
                :install {:brew "brew install tmux"
                          :apt "sudo apt install tmux"
                          :pacman "sudo pacman -S tmux"}}
   ;; Core system tools (usually present, but check anyway)
   :find       {:bin "find"   :desc "File finder" :install {}}
   :ls         {:bin "ls"     :desc "List directory" :install {}}
   :grep       {:bin "grep"   :desc "Pattern matcher" :install {}}
   :ps         {:bin "ps"     :desc "Process status" :install {}}
   :git        {:bin "git"
                :desc "Version control"
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

   Available package managers are detected once and cached."
  ([tool-key] (require-tool tool-key nil))
  ([tool-key pkg-managers]
   (let [tool (get tool-registry tool-key)]
     (if-not tool
       (r/err :tool/unknown {:tool tool-key
                              :available (vec (keys tool-registry))})
       (let [result (detect/which (:bin tool))]
         (if (r/ok? result)
           (r/ok (assoc (:ok result)
                        :tool tool-key
                        :desc (:desc tool)))
           (let [mgrs (or pkg-managers (detect/detect-pkg-managers))
                 hints (install-hints tool-key mgrs)]
             (r/err :tool/missing
                     {:tool tool-key
                      :bin (:bin tool)
                      :desc (:desc tool)
                      :hints hints
                      :message (if (seq hints)
                                 (str (:bin tool) " not found. Install with: "
                                      (:command (first hints)))
                                 (str (:bin tool) " not found and no known install method available"))}))))))))

(defn require-tools
  "Check multiple tools at once. Returns a map of {:available {...} :missing {...}}."
  [tool-keys]
  (let [mgrs (detect/detect-pkg-managers)
        results (into {} (map (fn [k] [k (require-tool k mgrs)]) tool-keys))]
    {:available (into {} (filter (fn [[_ v]] (r/ok? v)) results))
     :missing   (into {} (filter (fn [[_ v]] (r/err? v)) results))}))

(defn list-tools
  "List all registered tools with their availability status."
  []
  (let [mgrs (detect/detect-pkg-managers)]
    (mapv (fn [[k {:keys [bin desc]}]]
            (let [r (detect/which bin)]
              {:tool k
               :bin bin
               :desc desc
               :available? (r/ok? r)
               :path (when (r/ok? r) (get-in r [:ok :path]))}))
          (sort-by key tool-registry))))

(defn register-tool!
  "Dynamically register a new tool. Returns the updated registry entry."
  [tool-key {:keys [bin desc install] :as spec}]
  (alter-var-root #'tool-registry assoc tool-key spec)
  spec)
