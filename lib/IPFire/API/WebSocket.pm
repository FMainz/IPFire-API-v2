package IPFire::API::WebSocket;

use strict;
use warnings;

use Digest::SHA qw(sha1);
use Encode qw(decode FB_CROAK LEAVE_SRC);
use Errno qw(EINTR);
use Exporter 'import';
use IO::Select;
use IO::Socket::SSL qw($SSL_ERROR SSL_WANT_READ SSL_WANT_WRITE);
use MIME::Base64 qw(decode_base64 encode_base64);
use Time::HiRes qw(clock_gettime CLOCK_MONOTONIC);

our @EXPORT_OK = qw(handle_upgrade handle_frames upgrade_response);

use constant MAX_HEADER_BYTES => 8192;
use constant UPGRADE_TIMEOUT => 5;
use constant FRAME_TIMEOUT => 30;
use constant MAX_MESSAGE_BYTES => 65536;
use constant WEBSOCKET_GUID => '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

sub handle_upgrade {
    my ($client) = @_;

    my $deadline = clock_gettime(CLOCK_MONOTONIC) + UPGRADE_TIMEOUT;
    my $select = IO::Select->new($client);
    $client->blocking(0);

    my $request = '';
    while (index($request, "\r\n\r\n") < 0 && length($request) < MAX_HEADER_BYTES) {
        my $chunk = _read_chunk($client, $select, $deadline, MAX_HEADER_BYTES - length($request));
        return unless defined $chunk;
        $request .= $chunk;
    }

    my $response = upgrade_response($request);
    return unless _write_all($client, $select, $deadline, $response);
    return unless $response =~ /\AHTTP\/1\.1 101 /;
    return substr($request, index($request, "\r\n\r\n") + 4);
}

sub _read_chunk {
    my ($client, $select, $deadline, $size) = @_;

    while (clock_gettime(CLOCK_MONOTONIC) < $deadline) {
        my $count = $client->sysread(my $chunk, $size);
        return $count ? $chunk : undef if defined $count;
        return unless _wait_for_ssl($select, $deadline);
    }
    return;
}

sub _write_all {
    my ($client, $select, $deadline, $response) = @_;

    my $offset = 0;
    while ($offset < length($response)) {
        return if clock_gettime(CLOCK_MONOTONIC) >= $deadline;
        my $count = $client->syswrite($response, length($response) - $offset, $offset);
        if (!defined $count) {
            return unless _wait_for_ssl($select, $deadline);
            next;
        }
        return unless $count;
        $offset += $count;
    }
    return 1;
}

sub _wait_for_ssl {
    my ($select, $deadline) = @_;

    return unless defined $SSL_ERROR;
    my $wait = $SSL_ERROR == SSL_WANT_READ  ? 'can_read'
             : $SSL_ERROR == SSL_WANT_WRITE ? 'can_write'
             : return;
    while (1) {
        my $remaining = $deadline - clock_gettime(CLOCK_MONOTONIC);
        return if $remaining <= 0;
        local $! = 0;
        return 1 if $select->$wait($remaining);
        return unless $! == EINTR;
    }
}

sub upgrade_response {
    my ($request) = @_;

    my $header_end = index($request, "\r\n\r\n");
    return _http_error('431 Request Header Fields Too Large')
        if $header_end + 4 > MAX_HEADER_BYTES
        || ($header_end < 0 && length($request) >= MAX_HEADER_BYTES);
    return _http_error('400 Bad Request') if $header_end < 0;

    my ($request_line, @lines) = split /\r\n/, substr($request, 0, $header_end);
    my $bad_request = _http_error('400 Bad Request');
    return $bad_request unless defined $request_line
        && $request_line =~ m{\AGET /[!-~]* HTTP/1\.1\z};

    my %headers;
    for my $line (@lines) {
        return $bad_request unless $line =~ /\A([!#\$%&'*+.^_`|~0-9A-Za-z-]+):[ \t]*([\t\x20-\x7e\x80-\xff]*)\z/;
        my ($name, $value) = (lc($1), $2);
        $value =~ s/[ \t]+\z//;
        push @{ $headers{$name} }, $value;
    }

    for my $name (qw(host sec-websocket-key sec-websocket-version)) {
        return $bad_request unless exists $headers{$name}
            && @{ $headers{$name} } == 1 && length $headers{$name}[0];
    }

    return $bad_request unless _contains_token($headers{connection}, 'upgrade')
        && _contains_token($headers{upgrade}, 'websocket');
    return $bad_request if exists $headers{'transfer-encoding'}
        || (exists $headers{'content-length'}
            && (@{ $headers{'content-length'} } != 1 || $headers{'content-length'}[0] ne '0'));

    my $version = $headers{'sec-websocket-version'}[0];
    return $bad_request unless $version =~ /\A(?:0|[1-9][0-9]{0,2})\z/ && $version <= 255;
    return _http_error('426 Upgrade Required', "Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n")
        unless $version eq '13';

    my $key = $headers{'sec-websocket-key'}[0];
    return $bad_request unless $key =~ /\A[A-Za-z0-9+\/]{22}==\z/;
    my $decoded_key = decode_base64($key);
    return $bad_request unless length($decoded_key) == 16 && encode_base64($decoded_key, '') eq $key;

    my $accept = encode_base64(sha1($key . WEBSOCKET_GUID), '');
    return "HTTP/1.1 101 Switching Protocols\r\n"
        . "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: $accept\r\n\r\n";
}

sub _contains_token {
    my ($values, $expected) = @_;

    return scalar grep { lc($_) eq $expected } split /[ \t]*,[ \t]*/, join(',', @{ $values // [] });
}

sub _http_error {
    my ($status, $extra_headers) = @_;

    return "HTTP/1.1 $status\r\n"
        . ($extra_headers // '') . "Connection: close\r\nContent-Length: 0\r\n\r\n";
}

sub handle_frames {
    my ($client, $buffer, $on_text) = @_;

    my $select = IO::Select->new($client);
    my ($message_type, $message);

    while (1) {
        my $deadline = clock_gettime(CLOCK_MONOTONIC) + FRAME_TIMEOUT;
        my ($error, $opcode, $fin, $payload) = _read_frame($client, $select, $deadline, \$buffer);
        return unless defined $error;
        return _send_frame($client, $select, 8, pack('n', $error)) if $error;

        if ($opcode == 8) {
            my $status = _close_error($payload);
            return _send_frame($client, $select, 8, $status ? pack('n', $status) : $payload);
        }
        if ($opcode == 9) {
            return unless _send_frame($client, $select, 10, $payload);
        }
        next if $opcode >= 8;

        if (($opcode == 0) != defined($message_type)) {
            return _send_frame($client, $select, 8, pack('n', 1002));
        }
        $message_type //= $opcode;
        $message .= $payload;
        if (length($message) > MAX_MESSAGE_BYTES) {
            return _send_frame($client, $select, 8, pack('n', 1009));
        }
        next unless $fin;

        if ($message_type == 1) {
            return _send_frame($client, $select, 8, pack('n', 1007)) unless _valid_utf8($message);
            return if $on_text && !_send_frame($client, $select, 1, $on_text->($message));
        }

        undef $message_type;
        $message = '';
    }
}

sub _read_frame {
    my ($client, $select, $deadline, $buffer) = @_;

    my $header = _read_exactly($client, $select, $deadline, $buffer, 2);
    return unless defined $header;
    my ($first, $second) = unpack('CC', $header);
    my $fin = $first & 0x80;
    my $opcode = $first & 0x0f;
    my $length = $second & 0x7f;

    return (1002) if ($first & 0x70) || !($second & 0x80)
        || ($opcode > 2 && $opcode < 8) || $opcode > 10
        || ($opcode >= 8 && (!$fin || $length > 125));

    if ($length == 126) {
        my $extended = _read_exactly($client, $select, $deadline, $buffer, 2);
        return unless defined $extended;
        $length = unpack('n', $extended);
        return (1002) if $length < 126;
    } elsif ($length == 127) {
        my $extended = _read_exactly($client, $select, $deadline, $buffer, 8);
        return unless defined $extended;
        my ($high, $low) = unpack('NN', $extended);
        return (1002) if $high >= 0x80000000 || (!$high && $low < 65536);
        return (1009) if $high || $low > MAX_MESSAGE_BYTES;
        $length = $low;
    }

    my $masked = _read_exactly($client, $select, $deadline, $buffer, 4 + $length);
    return unless defined $masked;
    my $mask = substr($masked, 0, 4);
    my $payload = substr($masked, 4) ^ substr($mask x int(($length + 3) / 4), 0, $length);
    return (0, $opcode, $fin, $payload);
}

sub _read_exactly {
    my ($client, $select, $deadline, $buffer, $size) = @_;

    while (length($$buffer) < $size) {
        my $chunk = _read_chunk($client, $select, $deadline, $size - length($$buffer));
        return unless defined $chunk;
        $$buffer .= $chunk;
    }
    return substr($$buffer, 0, $size, '');
}

sub _send_frame {
    my ($client, $select, $opcode, $payload) = @_;

    my $length = length($payload);
    my $size = $length < 126   ? pack('C', $length)
             : $length < 65536 ? pack('Cn', 126, $length)
             :                   pack('CNN', 127, 0, $length);
    my $frame = pack('C', 0x80 | $opcode) . $size . $payload;
    my $deadline = clock_gettime(CLOCK_MONOTONIC) + UPGRADE_TIMEOUT;
    return _write_all($client, $select, $deadline, $frame);
}

sub _close_error {
    my ($payload) = @_;

    return 0 unless length($payload);
    return 1002 if length($payload) == 1;
    my $code = unpack('n', $payload);
    return 1002 unless ($code >= 1000 && $code <= 1003)
        || ($code >= 1007 && $code <= 1014) || ($code >= 3000 && $code <= 4999);
    return _valid_utf8(substr($payload, 2)) ? 0 : 1007;
}

sub _valid_utf8 {
    return eval { decode('UTF-8', $_[0], FB_CROAK | LEAVE_SRC); 1 };
}

1;
