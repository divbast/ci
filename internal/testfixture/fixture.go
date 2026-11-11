// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Package testfixture names the known-good images ci's own tests run real
// containers from: the harness's integration tests and the contract
// suite's. They come from here and nowhere else, so moving to a newer
// image is one edit.
package testfixture

// LibreSpeed is a published ghcr.io/divbast/librespeed, pinned by its
// index digest so it can never move under a test. The index holds amd64
// and arm64, the arches ci's tests run on.
const LibreSpeed = "ghcr.io/divbast/librespeed@sha256:d9ea226a05957bd70876b6b3eb81ca454fefc4365902f061dba82515efb12909"
