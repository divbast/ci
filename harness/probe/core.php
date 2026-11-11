<?php

// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

declare(strict_types=1);

/*
 * The probe divbast's harness runs inside a container, as that container's
 * own PHP: frankenphp php-cli core.php <subcommand> [arguments]. The images
 * have no shell, and this needs nothing but PHP itself.
 *
 * Output protocol: one tab-separated record per assertion,
 *
 *     ok<TAB>what<TAB>expected<TAB>found
 *     FAIL<TAB>what<TAB>expected<TAB>found
 *
 * http-request and parse-listeners are the exceptions: they print what they
 * read, and assert nothing.
 *
 * Exit status: 0 when every record is ok; 1 when any is FAIL, and a
 * subcommand that throws is recorded as one; 2 for a subcommand or
 * arguments it does not know, or an app.php it cannot load.
 *
 * An app adds subcommands of its own in app.php, beside this file, which
 * returns array<string, callable(list<string>): void>: each subcommand's
 * name and its handler, given the operands. They may use everything defined
 * here. A name the core already has is an error.
 */

/**
 * The ones most likely to be the target of an intrusion.
 */
const FORBIDDEN_SHELLS = ['/bin/sh', '/bin/bash', '/bin/dash'];

/**
 * Every capability set in /proc/self/status. A process run as uid 65532
 * holds nothing in CapEff or CapPrm whatever the engine grants, since exec
 * clears both for a user other than root without file or ambient
 * capabilities. --cap-drop ALL empties the bounding set, so CapBnd is the
 * one that shows what the engine was told.
 */
const CAPABILITY_SETS = ['CapEff', 'CapPrm', 'CapInh', 'CapBnd', 'CapAmb'];

const NO_CAPABILITIES = '0000000000000000';
const EGRESS_PROBE_HOST = '9.9.9.9';
const EGRESS_PROBE_PORT = 443;
const EGRESS_PROBE_TIMEOUT = 3;
const ROOT_WRITE_PROBE = '/.divbast-write-probe';
const READ_ONLY_ERROR = 'Read-only file system';

/**
 * PID 1's argv, each argument ended by a NUL
 */
const PID1_CMDLINE = '/proc/1/cmdline';

/**
 * The longest name the kernel keeps in comm, which is the executable's
 * file name cut to fit
 */
const COMM_LENGTH = 15;

const HTTP_TIMEOUT = 10;
// An HTTP field name is a token: RFC 9110, section 5.6.2
const HEADER_LINE = '/\A[!#$%&\'*+.^_`|~0-9A-Za-z-]+:[^\r\n]*\z/';

// Every socket in the container's network namespace, one per line after a
// header
const TCP_TABLES = ['/proc/net/tcp', '/proc/net/tcp6'];
const UDP_TABLES = ['/proc/net/udp', '/proc/net/udp6'];

/**
 * One socket in any of those tables: sl, local address:port and remote
 * address:port in hex, the state, five columns, then the socket's inode
 */
const SOCKET_LINE = '/\A\s*\d+:\s+[0-9A-Fa-f]+:([0-9A-Fa-f]{4})\s+[0-9A-Fa-f]+:[0-9A-Fa-f]{4}\s+([0-9A-Fa-f]{2})(?:\s+\S+){5}\s+(\d+)\s/';
const TCP_LISTEN = '0A';

/**
 * What readlink(2) gives for a descriptor that is a socket
 */
const SOCKET_TARGET = '/\Asocket:\[(\d+)\]\z/';

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

// --- subcommands ------------------------------------------------------------

/**
 * PID 1's whole argv, as the kernel keeps it, against the one given. A
 * supervisor, an init the engine added, or a bootstrap that never handed
 * over to the server all leave something else there.
 */
function assertPid1(string ...$expected): void
{
    $expected = array_values($expected);
    Assertions::equals(
        'PID 1 comm',
        substr(basename($expected[0] ?? ''), 0, COMM_LENGTH),
        trim(readOrThrow('/proc/1/comm')),
    );

    $raw = readOrThrow(PID1_CMDLINE);
    $found = explode("\0", str_ends_with($raw, "\0") ? substr($raw, 0, -1) : $raw);
    Assertions::equals('PID 1 argv', jsonList($expected), jsonList($found));
}

/**
 * Extract capability mask from /proc/self/status as a value.
 */
function capabilityMask(string $status, string $field): string
{
    $pattern = '/^' . preg_quote($field, '/') . ':[ \t]*([0-9a-fA-F]+)[ \t]*$/m';

    if (preg_match($pattern, $status, $matches) !== 1) {
        throw new RuntimeException("/proc/self/status has no well-formed $field line");
    }

    return $matches[1];
}

function assertCaps(): void
{
    $status = readOrThrow('/proc/self/status');

    foreach (CAPABILITY_SETS as $field) {
        $mask = capabilityMask($status, $field);
        Assertions::record(
            ltrim($mask, '0') === '',
            "$field, every capability bit clear",
            NO_CAPABILITIES,
            $mask,
        );
    }
}

function assertNoShell(): void
{
    foreach (FORBIDDEN_SHELLS as $path) {
        clearstatcache(true, $path);
        $present = file_exists($path) || is_link($path);

        Assertions::record(
            !$present,
            "$path is absent from the image",
            'absent',
            $present ? 'present' : 'absent',
        );
    }
}

/**
 * The kernel answers a create on a read-only mount with EROFS before it
 * checks permissions on the directory, so the error names the mount. A root
 * that was merely owned by root would answer "Permission denied" instead,
 * and this would fail.
 */
function assertReadOnly(): void
{
    error_clear_last();
    $written = @file_put_contents(ROOT_WRITE_PROBE, "probe\n");
    $error = error_get_last()['message'] ?? 'no error';

    if ($written !== false) {
        @unlink(ROOT_WRITE_PROBE);
    }

    Assertions::record(
        $written === false && str_contains($error, READ_ONLY_ERROR),
        'writing ' . ROOT_WRITE_PROBE . ' fails because / is read-only',
        READ_ONLY_ERROR,
        $written === false ? $error : "wrote $written bytes",
    );
}

/**
 * Measures from inside the container.
 */
function probeEgress(): void
{
    $errno = 0;
    $errstr = '';
    $socket = @fsockopen(
        EGRESS_PROBE_HOST,
        EGRESS_PROBE_PORT,
        $errno,
        $errstr,
        EGRESS_PROBE_TIMEOUT,
    );

    $connected = $socket !== false;
    if ($socket !== false) {
        fclose($socket);
    }

    Assertions::record(
        !$connected,
        'outbound TCP to ' . EGRESS_PROBE_HOST . ':' . EGRESS_PROBE_PORT . ' is refused',
        'no connection',
        $connected ? 'CONNECTED' : sprintf('no connection (errno %d: %s)', $errno, $errstr),
    );
}

/**
 * What every open descriptor of every process in the container points at.
 * A process this one may not look into, or one gone meanwhile, adds
 * nothing.
 *
 * @return list<string>
 */
function descriptorTargets(): array
{
    $targets = [];
    foreach (glob('/proc/[0-9]*/fd/*') ?: [] as $fd) {
        $target = @readlink($fd);
        if (is_string($target)) {
            $targets[] = $target;
        }
    }

    return $targets;
}

/**
 * The inode of every socket among the descriptor targets given.
 *
 * @param list<string> $targets
 * @return array<int, true>
 */
function socketInodes(array $targets): array
{
    $held = [];
    foreach ($targets as $target) {
        if (preg_match(SOCKET_TARGET, $target, $socket) === 1) {
            $held[(int) $socket[1]] = true;
        }
    }

    return $held;
}

/**
 * The local port of every socket in one of the kernel's socket tables that
 * a process in the container holds, by inode, and with $listening only TCP
 * sockets in LISTEN. A line that is not a socket is an error: a table this
 * misreads must not pass for one with nothing in it.
 *
 * @param array<int, true> $held
 * @return list<int>
 */
function heldPorts(string $table, array $held, bool $listening): array
{
    $ports = [];
    foreach (array_slice(explode("\n", trim(readOrThrow($table))), 1) as $line) {
        if (preg_match(SOCKET_LINE, $line, $socket) !== 1) {
            throw new RuntimeException("$table has a line that is not a socket: $line");
        }
        if ($listening && strtoupper($socket[2]) !== TCP_LISTEN) {
            continue;
        }
        if (isset($held[(int) $socket[3]])) {
            $ports[] = (int) hexdec($socket[1]);
        }
    }

    return $ports;
}

/**
 * @param list<int> $ports
 * @return list<int>
 */
function sortedPorts(array $ports): array
{
    $ports = array_values(array_unique($ports));
    sort($ports);

    return $ports;
}

/**
 * The TCP ports a process in the container listens on, and the UDP ports
 * it holds a socket on, from the kernel's own tables, so a socket no
 * process advertises counts too. Only sockets a process here holds count:
 * Docker's resolver for a user-defined network has a TCP listener and a UDP
 * socket in the same namespace, at 127.0.0.11, but held from outside the
 * container.
 *
 * @param list<string> $tcpTables
 * @param list<string> $udpTables
 * @param array<int, true> $held
 * @return array{tcp: list<int>, udp: list<int>}
 */
function listeners(array $tcpTables, array $udpTables, array $held): array
{
    $tcp = [];
    foreach ($tcpTables as $table) {
        $tcp = [...$tcp, ...heldPorts($table, $held, true)];
    }
    $udp = [];
    foreach ($udpTables as $table) {
        $udp = [...$udp, ...heldPorts($table, $held, false)];
    }

    return ['tcp' => sortedPorts($tcp), 'udp' => sortedPorts($udp)];
}

/**
 * The TCP ports given are the only ones a process in the container listens
 * on, and no process in it holds a UDP socket at all. If no descriptor
 * could be read, nothing counts, and the ports given are missing.
 */
function assertListeners(string ...$ports): void
{
    $expected = [];
    foreach ($ports as $port) {
        if (preg_match('/\A[1-9][0-9]{0,4}\z/', $port) !== 1 || (int) $port > 65535) {
            throw new InvalidArgumentException("'$port' is not a TCP port");
        }
        $expected[] = (int) $port;
    }
    $found = listeners(TCP_TABLES, UDP_TABLES, socketInodes(descriptorTargets()));

    Assertions::equals(
        'TCP ports a process in the container listens on',
        implode(' ', sortedPorts($expected)),
        implode(' ', $found['tcp']),
    );
    Assertions::equals(
        'UDP ports a process in the container holds a socket on',
        'none',
        $found['udp'] === [] ? 'none' : implode(' ', $found['udp']),
    );
}

/**
 * Prints "tcp <port>" for each TCP port listened on and "udp <port>" for
 * each UDP port held, as assert-listeners counts them, from a TCP table, a
 * UDP table and a file of descriptor targets, one per line. It reads files,
 * not /proc, so its parsing can be tested anywhere.
 */
function parseListeners(string $tcpTable, string $udpTable, string $targets): void
{
    $found = listeners([$tcpTable], [$udpTable], socketInodes(explode("\n", readOrThrow($targets))));
    foreach ($found['tcp'] as $port) {
        fwrite(STDOUT, "tcp $port\n");
    }
    foreach ($found['udp'] as $port) {
        fwrite(STDOUT, "udp $port\n");
    }
}

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
 * @return array<string, Command>
 */
function coreCommands(): array
{
    return [
        'assert-pid1' => new Command(['argv'], true, assertPid1(...)),
        'assert-caps' => new Command([], false, assertCaps(...)),
        'assert-no-shell' => new Command([], false, assertNoShell(...)),
        'assert-read-only' => new Command([], false, assertReadOnly(...)),
        'assert-listeners' => new Command(['tcp-port'], true, assertListeners(...)),
        'probe-egress' => new Command([], false, probeEgress(...)),
        'http-request' => new Command(['method', 'url', 'headers', 'body'], false, httpRequest(...)),
        'parse-listeners' => new Command(['tcp-table', 'udp-table', 'fd-targets'], false, parseListeners(...)),
    ];
}

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
 * The core's subcommands, then the app's.
 *
 * @return array<string, Command>
 */
function commands(): array
{
    $core = coreCommands();
    $app = appCommands(APP_FILE);
    $clashes = array_keys(array_intersect_key($app, $core));
    if ($clashes !== []) {
        throw new UnexpectedValueException(APP_FILE . ' redefines core subcommands: ' . implode(', ', $clashes));
    }

    return $core + $app;
}

/**
 * @param array<string, Command> $commands
 */
function usage(array $commands): string
{
    $lines = ['usage: frankenphp php-cli core.php <subcommand> [arguments]', '', 'subcommands:'];

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
