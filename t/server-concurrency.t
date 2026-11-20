use strict;
use warnings;

use File::Temp qw(tempdir);
use IO::Select;
use IO::Socket::INET;
use IO::Socket::SSL;
use JSON::PP qw(decode_json);
use Test::More;

my $probe = IO::Socket::INET->new(LocalAddr => '127.0.0.1', Listen => 1)
    or plan skip_all => "loopback listener unavailable: $!";
$probe->close();

my $tmp = tempdir(CLEANUP => 1);
my $cert = "$tmp/server.crt";
my $key = "$tmp/server.key";
my $generated = system('openssl', 'req', '-x509', '-newkey', 'ec',
    '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '1',
    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
    '-keyout', $key, '-out', $cert);
plan skip_all => 'OpenSSL command unavailable' if $generated == -1;
BAIL_OUT('Could not create test certificate') if $generated;

local %ENV = (%ENV,
    IPFIRE_API_HOST => '127.0.0.1',
    IPFIRE_API_PORT => 0,
    IPFIRE_API_CERT_FILE => $cert,
    IPFIRE_API_KEY_FILE => $key,
);
my $daemon_pid = open(my $daemon, '-|', $^X, 'bin/ipfire-api-daemon.pl')
    or die "Could not start daemon: $!";
END {
    local $?;
    if ($daemon_pid) {
        kill 'TERM', $daemon_pid;
        close $daemon;
    }
}

local $SIG{ALRM} = sub { die "Concurrency test timed out\n" };
alarm 15;

my $startup = <$daemon> // '';
my ($port) = $startup =~ /listening on 127\.0\.0\.1:(\d+)/;
BAIL_OUT("Daemon did not announce a port: $startup") unless $port;

my $upgrade = join "\r\n", 'GET / HTTP/1.1', 'Host: localhost',
    'Connection: Upgrade', 'Upgrade: websocket', 'Sec-WebSocket-Version: 13',
    'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==', '', '';

sub read_bytes {
    my ($socket, $length) = @_;

    my $data = '';
    while (length($data) < $length) {
        $socket->sysread(my $chunk, $length - length($data)) or die "Incomplete reply";
        $data .= $chunk;
    }
    return $data;
}

sub connect_websocket {
    my ($extra) = @_;

    my $socket = IO::Socket::SSL->new(
        PeerAddr => '127.0.0.1', PeerPort => $port, Timeout => 3,
        SSL_hostname => 'localhost', SSL_verifycn_name => 'localhost',
        SSL_verifycn_scheme => 'http', SSL_verify_mode => SSL_VERIFY_PEER,
        SSL_ca_file => $cert,
    ) or die IO::Socket::SSL::errstr();
    print {$socket} $upgrade, $extra or die "Could not send upgrade";
    my $headers = '';
    $headers .= read_bytes($socket, 1) until $headers =~ /\r\n\r\n\z/;
    like $headers, qr/\AHTTP\/1\.1 101 /, 'WebSocket upgrade succeeds';
    return $socket;
}

sub ping_request {
    my ($id) = @_;

    my $payload = qq({"id":"$id","method":"system.ping"});
    my $mask = "\x01\x02\x03\x04";
    my $masked = $payload ^ substr($mask x int((length($payload) + 3) / 4), 0, length($payload));
    return pack('CC', 0x81, 0x80 | length($payload)) . $mask . $masked;
}

sub check_pong {
    my ($socket, $id) = @_;

    my ($header, $length) = unpack('CC', read_bytes($socket, 2));
    is $header, 0x81, "$id receives a text frame";
    is_deeply decode_json(read_bytes($socket, $length)),
        { id => $id, result => { pong => JSON::PP::true } },
        "$id receives the expected result";
}

my $stalled = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => $port)
    or die "Could not open idle TCP connection: $!";
my $stalled_read = IO::Select->new($stalled);
my $first = connect_websocket(ping_request('first'));
check_pong($first, 'first');
ok !$stalled_read->can_read(0), 'another client completed TLS and a request while the first handshake was pending';

my $partial = ping_request('partial');
print {$first} substr($partial, 0, 4) or die "Could not send partial frame";
my $second = connect_websocket(ping_request('second'));
check_pong($second, 'second');
print {$first} substr($partial, 4) or die "Could not complete partial frame";
check_pong($first, 'partial');

ok scalar $stalled_read->can_read(7), 'stalled handshake reaches its deadline';
is sysread($stalled, my $tail, 1), 0, 'timed-out connection closes';
print {$second} ping_request('after-timeout') or die "Could not send another request";
check_pong($second, 'after-timeout');

alarm 0;
done_testing;
