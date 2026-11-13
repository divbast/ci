<?php

// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

declare(strict_types=1);

// The health-probe-prints mutant's health probe: it passes, and says so.
fwrite(STDOUT, "minimal-health: all is well\n");
exit(0);
