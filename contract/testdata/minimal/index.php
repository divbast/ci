<?php

// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

declare(strict_types=1);

// The page :8080 serves. PHP_SAPI reads frankenphp only when the server
// runs the script, so the health probe can tell PHP served it.
header('Content-Type: text/plain; charset=utf-8');
echo 'Hello from ' . PHP_SAPI . "\n";
