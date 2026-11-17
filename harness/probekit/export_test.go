// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package probekit

// RequestVia is Request over a connection its dial argument makes, so a
// test can hand it one end of a net.Pipe and run the clock in a synctest
// bubble.
var RequestVia = request
