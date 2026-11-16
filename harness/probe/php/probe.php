<?php

// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

declare(strict_types=1);

/*
 * The PHP half of divbast's probe, for a PHP app's own subcommands, which
 * must run under the app's own PHP: they read the server's ini, query its
 * schema and seed its users. The harness writes it and the app's app.php
 * into the container's /tmp through that PHP, and runs them as
 *
 *     <php> php-cli probe.php <subcommand> [arguments]
 *
 * Every check the contract makes runs through the Go core probe instead,
 * on a read-only mount at /divbast/probe, so this asserts nothing about
 * confinement. It needs nothing but PHP itself.
 *
 * Output protocol: one tab-separated record per assertion,
 *
 *     ok<TAB>what<TAB>expected<TAB>found
 *     FAIL<TAB>what<TAB>expected<TAB>found
 *
 * A subcommand may instead print what it reads, and assert nothing.
 *
 * Exit status: 0 when every record is ok; 1 when any is FAIL, and a
 * subcommand that throws is recorded as one; 2 for a subcommand or
 * arguments it does not know, or an app.php it cannot load.
 *
 * The app's subcommands are in app.php, beside this file, which returns
 * array<string, callable(list<string>): void>: each subcommand's name and
 * its handler, given the operands. They may use everything defined here:
 * Assertions, readOrThrow(), jsonList() and httpRequest().
 */

const HTTP_TIMEOUT = 10;
// An HTTP field name is a token: RFC 9110, section 5.6.2
const HEADER_LINE = '/\A[!#$%&\'*+.^_`|~0-9A-Za-z-]+:[^\r\n]*\z/';

const APP_FILE = __DIR__ . '/app.php';

/**
 * Collects assertions and renders them in the record format above.
 */
final class Assertions
{
    private static int $failures = 0;

    public static function equals(string $what, string $expected, string $found): void
    {
        self::record($found === $expected, $what, $expected, $found);
    }

    public static function record(bool $ok, string $what, string $expected, string $found): void
    {
        fwrite(STDOUT, sprintf(
            "%s\t%s\t%s\t%s\n",
            $ok ? 'ok' : 'FAIL',
            self::oneLine($what),
            self::oneLine($expected),
            self::oneLine($found),
        ));

        if (!$ok) {
            ++self::$failures;
        }
    }

    public static function failures(): int
    {
        return self::$failures;
    }

    /** Tabs and newlines are the record separators so they can't be present in any field. */
    private static function oneLine(string $text): string
    {
        return trim(strtr($text, ["\t" => ' ', "\n" => ' ', "\r" => ' ']));
    }
}

/**
 * One subcommand: what runs it, and the arguments it takes, named for its
 * usage line. A variadic one takes one or more in place of its last
 * argument, or any number if it names none.
 */
final class Command
{
    /**
     * @param list<string> $arguments
     */
    public function __construct(
        public readonly array $arguments,
        public readonly bool $variadic,
        public readonly Closure $handler,
    ) {
    }

    public function accepts(int $count): bool
    {
        $named = count($this->arguments);

        return $this->variadic ? $count >= $named : $count === $named;
    }

    public function synopsis(): string
    {
        $placeholders = array_map(static fn (string $argument): string => "<$argument>", $this->arguments);
        if ($this->variadic) {
            if ($placeholders === []) {
                return '[arguments...]';
            }
            $placeholders[count($placeholders) - 1] .= '...';
        }

        return implode(' ', $placeholders);
    }
}

function readOrThrow(string $path): string
{
    $contents = @file_get_contents($path);
    if ($contents === false) {
        throw new RuntimeException("cannot read $path");
    }

    return $contents;
}

/**
 * @param list<string> $words
 */
function jsonList(array $words): string
{
    return json_encode($words, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
}

// --- helpers for app.php ------------------------------------------------

/**
 * Sends one request over a bare socket, as a proxy in front of the server
 * would, and prints the status code on the first line and the body after
 * it. It needs no allow_url_fopen. headers holds one "Name: value" per
 * line. A body goes form-encoded. HTTP/1.0 keeps the answer unchunked,
 * ending where the server closes the connection.
 */
function httpRequest(string $method, string $url, string $headers, string $body): void
{
    if (preg_match('/\A[A-Z]+\z/', $method) !== 1) {
        throw new InvalidArgumentException("'$method' is not a method");
    }
    $parts = parse_url($url);
    if ($parts === false || ($parts['scheme'] ?? '') !== 'http' || !isset($parts['host'])) {
        throw new InvalidArgumentException("'$url' is not an http:// URL");
    }
    $host = $parts['host'];
    $port = $parts['port'] ?? 80;
    $target = ($parts['path'] ?? '/') . (isset($parts['query']) ? '?' . $parts['query'] : '');

    $lines = ["$method $target HTTP/1.0", "Host: $host:$port", 'Connection: close'];
    foreach (explode("\n", $headers) as $header) {
        if ($header === '') {
            continue;
        }
        if (preg_match(HEADER_LINE, $header) !== 1) {
            throw new InvalidArgumentException("'$header' is not a header line");
        }
        $lines[] = $header;
    }
    if ($body !== '') {
        $lines[] = 'Content-Type: application/x-www-form-urlencoded';
    }
    if ($body !== '' || $method === 'POST') {
        $lines[] = 'Content-Length: ' . strlen($body);
    }
    $request = implode("\r\n", $lines) . "\r\n\r\n" . $body;

    $errno = 0;
    $errstr = '';
    $socket = @fsockopen($host, $port, $errno, $errstr, HTTP_TIMEOUT);
    if ($socket === false) {
        throw new RuntimeException(sprintf('cannot connect to %s:%d (errno %d: %s)', $host, $port, $errno, $errstr));
    }
    stream_set_timeout($socket, HTTP_TIMEOUT);
    $sent = fwrite($socket, $request);
    $response = stream_get_contents($socket);
    fclose($socket);

    if ($sent !== strlen($request) || $response === false) {
        throw new RuntimeException("the exchange with $host:$port broke off");
    }

    $split = explode("\r\n\r\n", $response, 2);
    if (preg_match('#\AHTTP/\d\.\d (\d{3})#', $split[0], $status) !== 1) {
        throw new RuntimeException('no HTTP status line in the answer: ' . substr($split[0], 0, 80));
    }

    fwrite(STDOUT, $status[1] . "\n" . ($split[1] ?? ''));
}

// --- dispatch ---------------------------------------------------------------

/**
 * The subcommands app.php returns, or none when there is no app.php.
 *
 * @return array<string, Command>
 */
function appCommands(string $file): array
{
    if (!is_file($file)) {
        return [];
    }
    $app = require $file;
    if (!is_array($app)) {
        throw new UnexpectedValueException("$file returns " . get_debug_type($app) . ', not an array of subcommands');
    }

    $commands = [];
    foreach ($app as $name => $handler) {
        if (!is_string($name) || !is_callable($handler)) {
            throw new UnexpectedValueException("$file: subcommand '$name' needs a name and a callable");
        }
        $commands[$name] = new Command([], true, static function (string ...$operands) use ($handler): void {
            $handler(array_values($operands));
        });
    }

    return $commands;
}

/**
 * The app's subcommands, from app.php.
 *
 * @return array<string, Command>
 */
function commands(): array
{
    return appCommands(APP_FILE);
}

/**
 * @param array<string, Command> $commands
 */
function usage(array $commands): string
{
    $lines = ['usage: <php> php-cli probe.php <subcommand> [arguments]', '', 'subcommands:'];

    foreach ($commands as $name => $command) {
        $lines[] = '  ' . rtrim($name . ' ' . $command->synopsis());
    }

    return implode("\n", $lines) . "\n";
}

/**
 * @param list<string> $arguments
 */
function main(array $arguments): int
{
    try {
        $commands = commands();
    } catch (Throwable $problem) {
        fwrite(STDERR, 'cannot load the subcommands: ' . $problem::class . ': ' . $problem->getMessage() . "\n");

        return 2;
    }
    $name = $arguments[0] ?? '';

    if (!isset($commands[$name])) {
        fwrite(STDERR, $name === '' ? "no subcommand given\n" : "unknown subcommand '$name'\n");
        fwrite(STDERR, usage($commands));

        return 2;
    }

    $command = $commands[$name];
    $operands = array_slice($arguments, 1);

    if (!$command->accepts(count($operands))) {
        fwrite(STDERR, sprintf(
            "%s takes %s, got %d\n",
            $name,
            $command->synopsis() === '' ? 'no arguments' : $command->synopsis(),
            count($operands),
        ));

        return 2;
    }

    try {
        ($command->handler)(...$operands);
    } catch (Throwable $problem) {
        Assertions::record(
            false,
            "$name completed",
            'no exception',
            $problem::class . ': ' . $problem->getMessage(),
        );
    }

    return Assertions::failures() === 0 ? 0 : 1;
}

/**
 * $argv exists only when register_argc_argv is on.
 *
 * The subcommand and operands are whatever follows this script's own path.
 * The native CLI puts that path at $argv[0], but FrankenPHP 1.13.0's php-cli
 * put its own binary there and shifted the script to $argv[1]
 * (php/frankenphp#2690, fixed in 1.13.1). Finding the script by identity
 * rather than by position reads both.
 *
 * @return list<string>
 */
function commandLine(): array
{
    $raw = $_SERVER['argv'] ?? null;
    if (!is_array($raw)) {
        return [];
    }

    $arguments = [];
    foreach ($raw as $value) {
        if (is_string($value)) {
            $arguments[] = $value;
        }
    }

    foreach ($arguments as $index => $argument) {
        if (realpath($argument) === __FILE__) {
            return array_slice($arguments, $index + 1);
        }
    }

    fwrite(STDERR, sprintf(
        "%s is not in argv, so there is no telling where the subcommand starts: %s\n",
        __FILE__,
        implode(' ', $arguments),
    ));

    return [];
}

exit(main(commandLine()));
