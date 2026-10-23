<?php

header('Content-Type: text/plain');

/*
 * Safe evidence simulation.
 *
 * The runtime is patched, but the response intentionally advertises an older
 * PHP version so PHP Sentinel can demonstrate why a banner alone must not be
 * treated as vulnerability proof.
 */

header('X-Powered-By: PHP/8.5.11');

echo "PHP Sentinel vendor-backport evidence simulation\n";
echo "Actual runtime: " . PHP_VERSION . "\n";
echo "SAPI: " . PHP_SAPI . "\n";
