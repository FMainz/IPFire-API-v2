use strict;
use warnings;

use Errno qw(EINTR);
use IO::Handle;
use IO::Select;
use IO::Socket::SSL qw(SSL_WANT_READ);
use JSON::PP qw(decode_json);
use Socket qw(AF_UNIX SOCK_STREAM PF_UNSPEC);
use Test::More;
use Time::HiRes qw(clock_gettime CLOCK_MONOTONIC);

use IPFire::API::WebSocket qw(handle_upgrade handle_frames);
use IPFire::API::Protocol qw(handle_request);

sub client_frame {
    my ($header, $payload) = @_;
    my $length = length($payload);
    my $mask = "\x01\x02\x03\x04";
    my $masked = $payload ^ substr($mask x int(($length + 3) / 4), 0, $length);
    my $size = $length < 126   ? pack('C', 0x80 | $length)
             : $length < 65536 ? pack('Cn', 0xfe, $length)
             :                   pack('CNN', 0xff, 0, $length);
    return pack('C', $header) . $size . $mask . $masked;
}

sub exchange {
    my ($input, $upgrade, $on_text) = @_;
    socketpair(my $server, my $client, AF_UNIX, SOCK_STREAM, PF_UNSPEC) or die "socketpair: $!";
    $client->print($input) or die "write to client socket: $!";
    $client->flush() or die "flush client socket: $!";
    my $buffer = $upgrade ? handle_upgrade($server) : '';
    handle_frames($server, $buffer, $on_text) if defined $buffer;
    close $server or die "close server socket: $!";
    local $/;
    return $client->getline() // '';
}

my $close = client_frame(0x88, pack('n', 1000));
my $normal_close = pack('CCn', 0x88, 2, 1000);
my $protocol_error = pack('CCn', 0x88, 2, 1002);

is exchange(client_frame(0x89, 'hello') . $close),
    "\x8a\x05hello" . $normal_close, 'Ping receives an unmasked Pong with the same payload, then Close';
is exchange(client_frame(0x01, "\xe2") . client_frame(0x89, '')
      . client_frame(0x80, "\x82\xac") . $close),
    "\x8a\x00" . $normal_close, 'Ping is handled between fragments of a UTF-8 sequence';
is exchange(client_frame(0x82, 'x' x 65536) . $close),
    $normal_close, 'the largest supported frame uses the 64-bit length field';
is exchange(client_frame(0x02, 'x' x 32769) . client_frame(0x80, 'x' x 32768)),
    pack('CCn', 0x88, 2, 1009), 'size limit applies to the full fragmented message';
is exchange(pack('CC', 0x89, 0)), $protocol_error, 'unmasked client frame is rejected';
is exchange(client_frame(0x09, '')), $protocol_error, 'fragmented control frame is rejected';
is exchange(client_frame(0x80, '')), $protocol_error, 'unexpected continuation frame is rejected';
is exchange(pack('CCn', 0x81, 0xfe, 125)), $protocol_error, 'nonminimal length encoding is rejected';
is exchange(client_frame(0x88, pack('n', 1005))), $protocol_error, 'reserved close code is rejected';
is exchange(client_frame(0x81, "\xff")), pack('CCn', 0x88, 2, 1007), 'invalid UTF-8 is rejected';

my $request = join "\r\n", 'GET / HTTP/1.1', 'Host: localhost', 'Connection: Upgrade',
    'Upgrade: websocket', 'Sec-WebSocket-Version: 13',
    'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==', '', '';
my $reply = exchange($request . client_frame(0x89, 'hi') . $close, 1);
like $reply, qr/\AHTTP\/1\.1 101 .*?\r\n\r\n\x8a\x02hi\Q$normal_close\E\z/s,
    'the upgrade response precedes frames and preserves bytes already read';

subtest 'JSON responses travel in text frames on the same connection' => sub {
    my $id = 'a' x 128;
    my @requests = (
        ['{', undef, 'invalid_json'],
        ['{"id":1,"method":"system.ping"}', undef, 'invalid_request'],
        ['{"id":"one","method":"other"}', 'one', 'method_not_found'],
        ['{"id":"two","method":"system.ping","params":[1]}', 'two', 'invalid_params'],
        ['{"id":"' . $id . '","method":"system.ping"}', $id, undef],
    );
    my $input = join '', (map { client_frame(0x81, $_->[0]) } @requests), $close;
    my $output = exchange($input, 0, \&handle_request);

    for my $case (@requests) {
        my (undef, $expected_id, $expected_error) = @$case;
        my ($header, $length) = unpack('CC', substr($output, 0, 2, ''));
        is $header, 0x81, 'response is a complete text frame';
        if (!defined $expected_error) {
            is $length, 126, 'long response uses the extended length field';
        }
        $length = unpack('n', substr($output, 0, 2, '')) if $length == 126;
        my $response = decode_json(substr($output, 0, $length, ''));
        is $response->{id}, $expected_id, 'response carries the request ID when valid';
        if (defined $expected_error) {
            is $response->{error}{code}, $expected_error, 'response carries expected error code';
        } else {
            is_deeply $response->{result}, { pong => JSON::PP::true }, 'ping receives a JSON pong';
        }
    }
    is $output, $normal_close, 'connection closes normally after all requests';
};

subtest 'interrupted readiness wait resumes before the original deadline' => sub {
    pipe(my $read, my $write) or die "pipe: $!";
    syswrite($write, 'x') == 1 or die "write to pipe: $!";
    my $select = IO::Select->new($read);
    my $can_read = IO::Select->can('can_read');
    my $calls = 0;

    no warnings 'redefine';
    local *IO::Select::can_read = sub {
        if (++$calls == 1) {
            $! = EINTR;
            return;
        }
        return $can_read->(@_);
    };
    local $IPFire::API::WebSocket::SSL_ERROR = SSL_WANT_READ;
    ok IPFire::API::WebSocket::_wait_for_ssl($select, clock_gettime(CLOCK_MONOTONIC) + 1),
        'the wait reports the readable handle after an interruption';
    is $calls, 2, 'the interrupted wait is retried';
    ok !IPFire::API::WebSocket::_wait_for_ssl($select, clock_gettime(CLOCK_MONOTONIC) - 1),
        'an expired deadline does not wait for a ready handle';
    is $calls, 2, 'the expired wait does not call select';
};

done_testing;
