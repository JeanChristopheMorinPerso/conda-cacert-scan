root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
export SCANNER="${SCANNER:-$root/target/release/cacert-scan}"
export CACERT_SCAN_ROOTS="${CACERT_SCAN_ROOTS:-$root/patterns/roots.pem}"
export CACERT_SCAN_WATCH="${CACERT_SCAN_WATCH:-$root/patterns/watch.pem}"
jobs=${JOBS:-4}
