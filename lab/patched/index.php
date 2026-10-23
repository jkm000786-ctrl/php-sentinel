<?php
header('Content-Type: text/plain');
header('X-Powered-By: PHP/' . PHP_VERSION);
echo "PHP Sentinel patched reference service\n";
echo "runtime=" . PHP_VERSION . "\n";
echo "sapi=" . PHP_SAPI . "\n";
