use strict;
use warnings;

use Digest::SHA qw(sha256_hex);
use File::Temp qw(tempdir);
use IO::Select;
use IO::Socket::INET;
use IO::Socket::SSL;
use JSON::PP;
use Time::HiRes qw(sleep);
use IPFire::API::NetworkSettings qw(save_network_settings);

my $checks = 0;
my $failures = 0;
my $json = JSON::PP->new->utf8->canonical;

sub check {
    my ($passed, $description) = @_;

    ++$checks;
    ++$failures unless $passed;
    print($passed ? "ok $checks - $description\n" : "not ok $checks - $description\n");
}

sub skip_all {
    my ($reason) = @_;

    print "1..0 # SKIP $reason\n";
    exit 0;
}

my $probe = IO::Socket::INET->new(LocalAddr => '127.0.0.1', Listen => 1)
    or skip_all("loopback listener unavailable: $!");
$probe->close();

my $tmp = tempdir(CLEANUP => 1);
my $cert = "$tmp/server.crt";
my $key = "$tmp/server.key";
my $generated = system('openssl', 'req', '-x509', '-newkey', 'ec',
    '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '1',
    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
    '-keyout', $key, '-out', $cert);
skip_all('OpenSSL command unavailable') if $generated == -1;
die "Could not create test certificate\n" if $generated;

local %ENV = (%ENV,
    IPFIRE_API_PORT => 0,
    IPFIRE_API_CERT_FILE => $cert,
    IPFIRE_API_KEY_FILE => $key,
    IPFIRE_API_CLIENT_DIR => "$tmp/clients",
    IPFIRE_API_NETWORK_SETTINGS_FILE => "$tmp/network.json",
    IPFIRE_API_ETHERNET_SETTINGS_FILE => "$tmp/ethernet.settings",
    IPFIRE_API_RED_DIRECTORY => "$tmp/red",
);
mkdir "$tmp/red" or die "Could not create temporary RED directory: $!";
delete @ENV{qw(IPFIRE_API_HOST IPFIRE_API_ALLOWED_NETWORKS)};
open my $ethernet, '>', $ENV{IPFIRE_API_ETHERNET_SETTINGS_FILE} or die "Cannot create test settings: $!";
print {$ethernet} <<'SETTINGS';
CONFIG_TYPE=2
GREEN_ADDRESS=127.0.0.1
GREEN_NETMASK=255.255.255.255
ORANGE_ADDRESS=127.0.0.2
ORANGE_NETMASK=255.255.255.255
SETTINGS
close $ethernet or die "Cannot close test settings: $!";
save_network_settings($ENV{IPFIRE_API_NETWORK_SETTINGS_FILE}, { network_zones => [qw(green orange)] });

sub add_client {
    my ($name) = @_;
    open my $cli, '-|', $^X, 'bin/ipfire-api-clients.pl', 'add', $name
        or die "Could not start client tool: $!";
    my $token = <$cli> // '';
    close $cli or die "Could not add client";
    chomp $token;
    return $token;
}

my $first_token = add_client('first');
my $second_token = add_client('second');
my $burst_token = add_client('burst');
my $log_path = "$tmp/daemon.log";
my $daemon_pid = open(my $daemon, '-|') // die "Could not fork daemon: $!";
if (!$daemon_pid) {
    open STDERR, '>', $log_path or die "Could not open daemon log: $!";
    exec $^X, 'bin/ipfire-api-daemon.pl' or die "Could not start daemon: $!";
}
END {
    local $?;
    if ($daemon_pid) {
        kill 'KILL', $daemon_pid;
        close $daemon;
    }
}

local $SIG{ALRM} = sub { die "Concurrency test timed out\n" };
alarm 40;

my $startup = <$daemon> // '';
my ($port) = $startup =~ /listening on 127\.0\.0\.1:(\d+)/;
die "Daemon did not announce a port: $startup\n" unless $port;
my $orange_startup = <$daemon> // '';
check($orange_startup eq "IPFire API v2 listening on 127.0.0.2:$port\n", 'both zones listen on the same port');

sub connect_tls {
    my (%overrides) = @_;
    return IO::Socket::SSL->new(
        PeerAddr => '127.0.0.1', PeerPort => $port, Timeout => 3,
        SSL_hostname => 'localhost', SSL_verifycn_name => 'localhost',
        SSL_verifycn_scheme => 'http', SSL_verify_mode => SSL_VERIFY_PEER,
        SSL_ca_file => $cert, %overrides,
    );
}

for my $version (qw(TLSv1_2 TLSv1_3)) {
    my $socket = connect_tls(SSL_version => $version);
    check(defined($socket), "$version connects with a trusted certificate and matching hostname");
    $socket->close() if $socket;
}
my $legacy = connect_tls(SSL_version => 'TLSv1_1', SSL_cipher_list => 'DEFAULT:@SECLEVEL=0');
check(!defined($legacy), 'TLS 1.1 is rejected');
$legacy->close() if $legacy;
my $wrong_name = connect_tls(SSL_verifycn_name => 'incorrect.example');
check(!defined($wrong_name) && IO::Socket::SSL::errstr() =~ /hostname/i, 'certificate hostname mismatch is rejected');
$wrong_name->close() if $wrong_name;
my $untrusted = connect_tls(SSL_ca_file => undef);
check(!defined($untrusted) && IO::Socket::SSL::errstr() =~ /certificate verify failed/i,
    'untrusted server certificate is rejected');
$untrusted->close() if $untrusted;

my $upgrade = join "\r\n", 'GET / HTTP/1.1', 'Host: localhost',
    'Connection: Upgrade', 'Upgrade: websocket', 'Sec-WebSocket-Version: 13',
    'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==', '';

sub read_bytes {
    my ($socket, $length) = @_;

    my $data = '';
    while (length($data) < $length) {
        $socket->sysread(my $chunk, $length - length($data)) or die "Incomplete reply";
        $data .= $chunk;
    }
    return $data;
}

sub request_upgrade {
    my ($token, $extra, $address) = @_;

    $address //= '127.0.0.1';
    my $socket = IO::Socket::SSL->new(
        LocalAddr => $address, PeerAddr => $address, PeerPort => $port, Timeout => 3,
        SSL_hostname => 'localhost', SSL_verifycn_name => 'localhost',
        SSL_verifycn_scheme => 'http', SSL_verify_mode => SSL_VERIFY_PEER,
        SSL_ca_file => $cert,
    ) or die IO::Socket::SSL::errstr();
    my $authorization = defined $token ? "Authorization: Bearer $token\r\n" : '';
    print {$socket} $upgrade, $authorization, "\r\n", $extra // '' or die "Could not send upgrade";
    my $headers = '';
    $headers .= read_bytes($socket, 1) until $headers =~ /\r\n\r\n\z/;
    return ($socket, $headers);
}

sub connect_websocket {
    my ($socket, $headers) = request_upgrade(@_);
    check($headers =~ /\AHTTP\/1\.1 101 / ? 1 : 0, 'WebSocket upgrade succeeds');
    return $socket;
}

sub api_request {
    my ($id, $method, $params) = @_;

    my $request = { id => $id, method => $method // 'system.ping' };
    $request->{params} = $params if defined $params;
    my $payload = $json->encode($request);
    my $mask = "\x01\x02\x03\x04";
    my $masked = $payload ^ substr($mask x int((length($payload) + 3) / 4), 0, length($payload));
    return pack('CC', 0x81, 0x80 | length($payload)) . $mask . $masked;
}

sub read_response {
    my ($socket, $id) = @_;

    my ($header, $length) = unpack('CC', read_bytes($socket, 2));
    check($header == 0x81, "$id receives a text frame");
    $length = unpack('n', read_bytes($socket, 2)) if $length == 126;
    return $json->decode(read_bytes($socket, $length));
}

sub check_pong {
    my ($socket, $id) = @_;

    my $response = read_response($socket, $id);
    my $expected = { id => $id, result => { pong => JSON::PP::true } };
    check($json->encode($response) eq $json->encode($expected), "$id receives the expected result");
}

my $blocked = IO::Socket::INET->new(
    LocalAddr => '127.0.0.2', PeerAddr => '127.0.0.1', PeerPort => $port, Timeout => 2,
) or die "Could not open TCP connection from the unlisted address: $!";
my $blocked_read = IO::Select->new($blocked);
my $blocked_bytes = $blocked_read->can_read(2) ? sysread($blocked, my $blocked_data, 1) : undef;
check(defined($blocked_bytes) && $blocked_bytes == 0, 'unlisted address is closed before TLS');
$blocked->close();

my $stalled = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => $port)
    or die "Could not open idle TCP connection: $!";
my $stalled_read = IO::Select->new($stalled);
my $first = connect_websocket($first_token, api_request('first'));
check_pong($first, 'first');
check(!$stalled_read->can_read(0), 'another client completed TLS and a request while the first handshake was pending');

my $partial = api_request('partial');
print {$first} substr($partial, 0, 4) or die "Could not send partial frame";
my $second = connect_websocket($second_token, api_request('second'));
check_pong($second, 'second');
my $orange = connect_websocket($second_token, api_request('orange'), '127.0.0.2');
check_pong($orange, 'orange');
my $topic = { event => 'system.info' };
my $subscriber = connect_websocket($second_token, api_request('watch', 'events.subscribe', $topic));
my $subscription = read_response($subscriber, 'subscribe');
check($json->encode($subscription) eq $json->encode({
    id => 'watch', result => { event => 'system.info', subscribed => JSON::PP::true },
}), 'subscription is acknowledged with the original request ID');
print {$first} substr($partial, 4) or die "Could not complete partial frame";
check_pong($first, 'partial');

check(scalar $stalled_read->can_read(7), 'stalled handshake reaches its deadline');
my $bytes_read = sysread($stalled, my $tail, 1);
check(defined($bytes_read) && $bytes_read == 0, 'timed-out connection closes');
print {$second} api_request('after-timeout') or die "Could not send another request";
check_pong($second, 'after-timeout');

print {$first} api_request('info', 'system.info') or die "Could not query system information";
my $info = read_response($first, 'info');
check(($info->{id} // '') eq 'info' && length($info->{result}{hostname} // ''),
    'monitoring client can read system information');

my $event = read_response($subscriber, 'subscription');
check(!exists($event->{id}) && ($event->{event} // '') eq 'system.info'
    && $event->{data}{hostname} eq $info->{result}{hostname}
    && $event->{data}{uptime_seconds} >= $info->{result}{uptime_seconds} - 1,
    'subscriber receives system information without issuing a request');
check(!$orange->pending() && !IO::Select->new($orange)->can_read(0),
    'another connection with the same token does not receive the event');
my $red_topic = { event => 'red.status' };
print {$subscriber} api_request('watch-red', 'events.subscribe', $red_topic) or die "Could not subscribe to RED";
my $red_subscription = read_response($subscriber, 'RED subscription');
check($json->encode($red_subscription) eq $json->encode({
    id => 'watch-red', result => { event => 'red.status', subscribed => JSON::PP::true },
}), 'a connection can subscribe to system and RED events together');
my $red_initial = read_response($subscriber, 'initial RED state');
check($json->encode($red_initial) eq $json->encode({
    event => 'red.status', data => { status => 'disconnected', connected_since => undef },
}), 'RED subscription sends its initial state');
print {$subscriber} api_request('leave', 'events.unsubscribe', $topic) or die "Could not unsubscribe";
my $unsubscription = read_response($subscriber, 'unsubscribe');
check($json->encode($unsubscription) eq $json->encode({
    id => 'leave', result => { event => 'system.info', subscribed => JSON::PP::false },
}), 'unsubscribe is acknowledged');
check(!$subscriber->pending() && !IO::Select->new($subscriber)->can_read(5.2),
    'unsubscribed system and unchanged RED produce no duplicate notifications');

open my $active, '>', "$tmp/red/active" or die "Could not mark RED active: $!";
close $active or die "Could not close temporary RED marker: $!";
my $connected_since = (stat "$tmp/red/active")[9];
my $connected = read_response($subscriber, 'RED connected');
check($json->encode($connected) eq $json->encode({
    event => 'red.status', data => { status => 'connected', connected_since => $connected_since },
}), 'RED stays subscribed after system unsubscribe and announces activation');
unlink "$tmp/red/active" or die "Could not clear temporary RED marker: $!";
my $disconnected = read_response($subscriber, 'RED disconnected');
check($json->encode($disconnected) eq $json->encode($red_initial), 'RED announces deactivation');
print {$subscriber} api_request('leave-red', 'events.unsubscribe', $red_topic) or die "Could not unsubscribe from RED";
my $red_unsubscription = read_response($subscriber, 'RED unsubscribe');
check(($red_unsubscription->{id} // '') eq 'leave-red' && !$red_unsubscription->{result}{subscribed},
    'RED unsubscribe is acknowledged');
print {$subscriber} api_request('invalid-topic', 'events.subscribe', { event => 'unsupported' })
    or die "Could not send invalid event request";
my $unknown_topic = read_response($subscriber, 'invalid event');
check(($unknown_topic->{error}{code} // '') eq 'invalid_params', 'unknown event is rejected');

my (undef, $missing_token) = request_upgrade(undef);
check($missing_token =~ /\AHTTP\/1\.1 401 / ? 1 : 0, 'upgrade without a token is rejected');
my $invalid_credential = 'first.' . ('0' x 64);
my (undef, $invalid_token) = request_upgrade($invalid_credential);
check($invalid_token =~ /\AHTTP\/1\.1 401 / ? 1 : 0, 'upgrade with an invalid token is rejected');

my $burst_green = connect_websocket($burst_token);
my $burst_orange = connect_websocket($burst_token, undef, '127.0.0.2');
my @green_ids = map { "burst-green-$_" } 1 .. 8;
my @orange_ids = map { "burst-orange-$_" } 1 .. 8;
print {$burst_green} map { api_request($_) } @green_ids or die "Could not send GREEN burst";
print {$burst_orange} map { api_request($_) } @orange_ids or die "Could not send ORANGE burst";

my ($accepted, $limited) = (0, 0);
for my $batch ([$burst_green, @green_ids], [$burst_orange, @orange_ids]) {
    my ($socket, @ids) = @$batch;
    for my $id (@ids) {
        my $response = read_response($socket, $id);
        next unless ($response->{id} // '') eq $id;
        if (($response->{error}{code} // '') eq 'rate_limited') {
            ++$limited;
        } elsif ($response->{result}{pong}) {
            ++$accepted;
        }
    }
}
check($accepted >= 10 && $limited > 0 && $accepted + $limited == 16,
    'the two connections share a request allowance and preserve request IDs');
print {$second} api_request('other-token') or die "Could not check the other token";
check_pong($second, 'other-token');

sleep 0.6;
print {$burst_orange} api_request('after-refill') or die "Could not retry after refill";
check_pong($burst_orange, 'after-refill');

system($^X, 'bin/ipfire-api-clients.pl', 'revoke', 'first') == 0 or die "Could not revoke first client";
print {$first} api_request('revoked', 'system.info') or die "Could not check revoked client";
my $denied = read_response($first, 'revoked');
check(($denied->{id} // '') eq 'revoked'
    && ($denied->{error}{code} // '') eq 'access_denied', 'revocation takes effect on an open connection');
my (undef, $revoked_token) = request_upgrade($first_token);
check($revoked_token =~ /\AHTTP\/1\.1 401 / ? 1 : 0, 'revoked token cannot open a new connection');
print {$second} api_request('still-authorized') or die "Could not check second client";
check_pong($second, 'still-authorized');

save_network_settings($ENV{IPFIRE_API_NETWORK_SETTINGS_FILE}, { network_zones => ['green'] });
check((<$daemon> // '') eq "IPFire API v2 network settings applied\n", 'daemon reloads saved zones without a restart');
check((<$daemon> // '') eq "IPFire API v2 listening on 127.0.0.1:$port\n", 'GREEN keeps its address and port');
check(!$orange->sysread(my $orange_tail, 1), 'the removed zone connection is closed');

my $occupied = IO::Socket::INET->new(
    LocalAddr => '127.0.0.2', LocalPort => $port, Listen => 1, ReuseAddr => 1,
);
check(defined($occupied), 'the daemon releases the removed zone listener');
die "Could not reserve the removed zone address: $!" unless $occupied;
save_network_settings($ENV{IPFIRE_API_NETWORK_SETTINGS_FILE}, { network_zones => [qw(green orange)] });
sleep 1.2;
my $green = connect_websocket($second_token, api_request('green-after-failed-reload'));
check_pong($green, 'green-after-failed-reload');
$occupied->close();

check((<$daemon> // '') eq "IPFire API v2 network settings applied\n", 'daemon retries the new zone after a bind failure');
check((<$daemon> // '') eq "IPFire API v2 listening on 127.0.0.1:$port\n", 'GREEN still listens after adding ORANGE');
check((<$daemon> // '') eq "IPFire API v2 listening on 127.0.0.2:$port\n", 'ORANGE is active again on the same port');
my $reloaded = connect_websocket($second_token, api_request('orange-after-reload'), '127.0.0.2');
check_pong($reloaded, 'orange-after-reload');

kill 'TERM', $daemon_pid or die "Could not signal daemon: $!";
my $shutdown = <$daemon> // '';
check($shutdown eq "IPFire API v2 stopped\n", 'daemon reports an orderly shutdown');
my $closed = close $daemon;
$daemon_pid = undef;
check($closed, 'daemon exits successfully on SIGTERM');
my $client_read = $reloaded->sysread(my $last, 1);
check(!$client_read, 'the active WebSocket connection is closed');
my $rebound = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1', LocalPort => $port, Listen => 1, ReuseAddr => 1,
);
check(defined $rebound, 'the listening port can be reused');

open my $log_file, '<', $log_path or die "Could not read daemon log: $!";
my $log = do { local $/; <$log_file> } // '';
check($log =~ /TLS handshake failed: timed out/, 'handshake timeout remains visible in the log');
my @credentials = ($first_token, $second_token, $burst_token, $invalid_credential);
my @sensitive = (@credentials, map { sha256_hex($_) } @credentials);
check(!grep({ index($log, $_) >= 0 } @sensitive), 'daemon logs contain no test tokens or token digests');

alarm 0;
print "1..$checks\n";
exit($failures ? 1 : 0);
