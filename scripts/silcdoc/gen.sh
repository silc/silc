#!/bin/sh

cat << EOF > tmp.php
  <?php $$page=$2; require "$1"; ?>
EOF
php -f tmp.php >$3
rm -f tmp.php