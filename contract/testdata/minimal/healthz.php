<?php

// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

declare(strict_types=1);

// GET /healthz on :8081. The fixture needs nothing but the server that
// runs this, so the answer is always 200.
header('Content-Type: text/plain; charset=utf-8');
echo "ok\n";
