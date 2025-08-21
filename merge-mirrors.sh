# super-repo 루트(= ~/gilgil/sns)에서 실행
set -euo pipefail

# 0) git-filter-repo가 없으면 설치(apt 권장)
if ! command -v git-filter-repo >/dev/null 2>&1; then
  apt update && apt install -y git-filter-repo
fi

# 1) 슈퍼레포에 빈 커밋이 없다면 만들어두기
git rev-parse HEAD >/dev/null 2>&1 || git commit --allow-empty -m "init super-repo" || true

# 2) 모든 *.mirror 처리
for d in *.mirror; do
  [ -d "$d/.git" ] || continue
  name="${d%.mirror}"                # 폴더명에서 .mirror 제거 → 서브디렉토리 이름

  echo ">>> Processing $d -> $name/ ..."

  # 2-1) 이미 서브디렉토리로 이동된 히스토리인지 점검
  last_files=$(git -C "$d" log --name-only -1 --pretty=tformat:)
  if ! echo "$last_files" | grep -q "^$name/"; then
    # 이동 안되어 있으면 이동
    git -C "$d" filter-repo --to-subdirectory-filter "$name"
  fi

  # 2-2) remote 등록(이미 있으면 set-url)
  if git remote get-url "import-$name" >/dev/null 2>&1; then
    git remote set-url "import-$name" "./$d"
  else
    git remote add "import-$name" "./$d"
  fi

  # 2-3) 가져와 병합 (기본브랜치 몰라도 HEAD로 병합 가능)
  git fetch "import-$name" --tags
  git merge --allow-unrelated-histories "import-$name/HEAD" -m "Merge $name history into $name/"

  echo ">>> Done: $name"
done

echo "All mirrors merged."
