#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

detect_default_branch() {
  local repo_dir="$1"
  local br
  br=$(git -C "$repo_dir" symbolic-ref --short -q HEAD || true)
  [[ -z "${br:-}" ]] && br=$(git -C "$repo_dir" branch --show-current || true)
  if [[ -z "${br:-}" ]]; then
    if git -C "$repo_dir" show-ref --verify --quiet refs/heads/main; then br=main; fi
    if [[ -z "${br:-}" ]] && git -C "$repo_dir" show-ref --verify --quiet refs/heads/master; then br=master; fi
  fi
  if [[ -z "${br:-}" ]]; then
    br=$(git -C "$repo_dir" for-each-ref --format='%(refname:short)' refs/heads | head -n1 || true)
  fi
  echo "${br:-}"
}

for d in *.mirror; do
  if [[ ! -d "$d/.git" ]]; then
    echo "!! $d is not a git repo, skipping"
    continue
  fi
  name="${d%.mirror}"
  echo ">>> merging $name from $d"

  if git remote get-url "import-$name" >/dev/null 2>&1; then
    git remote set-url "import-$name" "./$d"
  else
    git remote add "import-$name" "./$d"
  fi

  git fetch "import-$name" --tags

  br="$(detect_default_branch "$d")"
  if [[ -z "$br" ]]; then
    echo "!! could not detect default branch for $d, skipping"
    continue
  fi

  git merge --allow-unrelated-histories "import-$name/$br" -m "Merge $name history into $name/" || {
    echo "!! merge conflict while merging $name. Resolve, commit, then re-run."
    exit 1
  }
done

echo ">>> Done."
