cd ~/gilgil/sns

# 혹시 이전 병합이 걸려있다면 정리
git merge --abort 2>/dev/null || true

# 각 레포의 main 또는 master 한 가지만 병합
for name in 1m-block arp-spoof echo-client-server netfilter-test osi-and-tcp pcap-test send-arp sum_nbo tcp-block tls-block vending-machine sum_test; do
  if git show-ref --verify --quiet "refs/remotes/import-$name/main"; then
    echo ">>> merging $name (branch: main)"
    git merge --allow-unrelated-histories "import-$name/main" -m "Merge $name history into $name/"
  elif git show-ref --verify --quiet "refs/remotes/import-$name/master"; then
    echo ">>> merging $name (branch: master)"
    git merge --allow-unrelated-histories "import-$name/master" -m "Merge $name history into $name/"
  else
    echo "!! skip $name: no import-$name/main or master found"
  fi
done

