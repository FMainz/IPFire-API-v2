use strict;
use warnings;

use JSON::PP qw(decode_json);
use Test::More;

use IPFire::API::WebSocket qw(consume_upgrade consume_frame upgrade_response);
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
    my $reply = '';
    if ($upgrade) {
        my ($response, $close) = consume_upgrade(\$input);
        $reply = $response // '';
        return $reply if !defined($response) || $close;
    }

    my %state;
    while (1) {
        my ($frame, $close) = consume_frame(\$input, \%state, $on_text);
        last unless defined $frame;
        $reply .= $frame;
        last if $close;
    }
    return $reply;
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

subtest 'malformed upgrades are rejected before authentication' => sub {
    my $authorize = sub { fail('malformed upgrade must not reach authentication'); return 1 };
    for my $header ('Host: duplicate', 'Content-Length: 1', 'Transfer-Encoding: chunked') {
        my $invalid = $request;
        $invalid =~ s/\r\n\r\n\z/\r\n$header\r\n\r\n/;
        like upgrade_response($invalid, $authorize), qr/\AHTTP\/1\.1 400 /, "$header rejected";
    }
    my $oversized = $request;
    $oversized =~ s/\r\n\r\n\z/"\r\nX-Fill: " . ('x' x 8192) . "\r\n\r\n"/e;
    like upgrade_response($oversized, $authorize), qr/\AHTTP\/1\.1 431 /, 'oversized headers rejected';
};

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
    my $output = exchange($input, 0, sub { handle_request($_[0], 'monitoring') });

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

subtest 'method failure allows another request on the same connection' => sub {
    no warnings 'once', 'redefine';
    local *IPFire::API::System::hostname = sub { die "private exception detail\n" };
    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, @_ };

    my $input = client_frame(0x81, '{"id":"failed","method":"system.info"}')
        . client_frame(0x81, '{"id":"next","method":"system.ping"}') . $close;
    my $output = exchange($input, 0, sub { handle_request($_[0], 'monitoring') });

    for my $expected (
        { id => 'failed', error => { code => 'internal_error', message => 'Internal server error' } },
        { id => 'next', result => { pong => JSON::PP::true } },
    ) {
        my ($header, $length) = unpack('CC', substr($output, 0, 2, ''));
        is $header, 0x81, 'reply is a text frame';
        is_deeply decode_json(substr($output, 0, $length, '')), $expected, "reply for $expected->{id}";
    }
    is $output, $normal_close, 'connection closes normally';
    is_deeply \@warnings, ["API method system.info failed\n"], 'log identifies the method without exception details';
};

subtest 'partial input is retained until its frame is complete' => sub {
    my $frame = client_frame(0x82, 'x' x 65536);
    my %state;
    my $input = '';
    for my $chunk (substr($frame, 0, 1), substr($frame, 1, 8), substr($frame, 9, 4)) {
        $input .= $chunk;
        my $partial = $input;
        my @result = consume_frame(\$input, \%state);
        is_deeply \@result, [], 'incomplete frame needs more input';
        is $input, $partial, 'partial bytes are kept';
    }
    $input .= substr($frame, 13) . $close;
    is_deeply [consume_frame(\$input, \%state)], ['', 0], 'complete binary frame is consumed';
    is $input, $close, 'following frame remains buffered';
    is_deeply [consume_frame(\$input, \%state)], [$normal_close, 1], 'buffered Close can be handled immediately';
};

done_testing;
