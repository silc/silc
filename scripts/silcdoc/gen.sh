#!/bin/sh

cat << EOF > tmp.php
<?php \$page="$4"; \$dest="$1"; \$type="$3"; require "$2"; ?>
EOF
php -f tmp.php >"$5".tmp
mv "$5".tmp "$5"
rm -f tmp.php
