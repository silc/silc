#!/bin/sh

cat << EOF > tmp.php
<?php \$page="$3"; \$dest="$1"; require "$2"; ?>
EOF
php -f tmp.php >$4.tmp
mv $4.tmp $4
rm -f tmp.php
