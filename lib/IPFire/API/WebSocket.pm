package IPFire::API::WebSocket;

use strict;
use warnings;

use Digest::SHA qw(sha1);
use Encode qw(decode FB_CROAK LEAVE_SRC);
use Exporter 'import';
use MIME::Base64 qw(decode_base64 encode_base64);

our @EXPORT_OK = qw(consume_upgrade consume_frame upgrade_response text_frame);

use constant MAX_HEADER_BYTES => 8192;
use constant MAX_MESSAGE_BYTES => 65536;
use constant WEBSOCKET_GUID => '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

sub consume_upgrade {
    my ($buffer, $authenticate) = @_;

    my $header_end = index($$buffer, "\r\n\r\n");
    return if $header_end < 0 && length($$buffer) < MAX_HEADER_BYTES;

    my $response = upgrade_response($$buffer, $authenticate);
    return ($response, 1) unless $response =~ /\AHTTP\/1\.1 101 /;
    substr($$buffer, 0, $header_end + 4, '');
    return ($response, 0);
}

sub upgrade_response {
    my ($request, $authenticate) = @_;

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

    if ($authenticate) {
        my $authorization = $headers{authorization} // [];
        return _http_error('401 Unauthorized', "WWW-Authenticate: Bearer realm=\"IPFire API v2\"\r\n")
            unless @$authorization == 1 && $authenticate->($authorization->[0]);
    }

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

# Return no values for incomplete input, or a reply and a close flag for a
# consumed frame. An empty reply means no response is needed for that frame.
sub consume_frame {
    my ($buffer, $state, $on_text) = @_;

    my ($error, $opcode, $fin, $payload) = _read_frame($buffer);
    return unless defined $error;
    return (_encode_frame(8, pack('n', $error)), 1) if $error;

    if ($opcode == 8) {
        my $status = _close_error($payload);
        return (_encode_frame(8, $status ? pack('n', $status) : $payload), 1);
    }
    return (_encode_frame(10, $payload), 0) if $opcode == 9;
    return ('', 0) if $opcode >= 8;

    if (($opcode == 0) != defined($state->{message_type})) {
        return (_encode_frame(8, pack('n', 1002)), 1);
    }
    $state->{message_type} //= $opcode;
    $state->{message} .= $payload;
    if (length($state->{message}) > MAX_MESSAGE_BYTES) {
        return (_encode_frame(8, pack('n', 1009)), 1);
    }
    return ('', 0) unless $fin;

    my $type = delete $state->{message_type};
    my $message = delete $state->{message};
    return ('', 0) unless $type == 1;
    return (_encode_frame(8, pack('n', 1007)), 1) unless _valid_utf8($message);
    return ($on_text ? text_frame($on_text->($message)) : '', 0);
}

sub text_frame { return _encode_frame(1, $_[0]); }

sub _read_frame {
    my ($buffer) = @_;

    return if length($$buffer) < 2;
    my ($first, $second) = unpack('CC', $$buffer);
    my $fin = $first & 0x80;
    my $opcode = $first & 0x0f;
    my $length = $second & 0x7f;
    my $offset = 2;

    return (1002) if ($first & 0x70) || !($second & 0x80)
        || ($opcode > 2 && $opcode < 8) || $opcode > 10
        || ($opcode >= 8 && (!$fin || $length > 125));

    if ($length == 126) {
        return if length($$buffer) < 4;
        $length = unpack('n', substr($$buffer, 2, 2));
        return (1002) if $length < 126;
        $offset = 4;
    } elsif ($length == 127) {
        return if length($$buffer) < 10;
        my ($high, $low) = unpack('NN', substr($$buffer, 2, 8));
        return (1002) if $high >= 0x80000000 || (!$high && $low < 65536);
        return (1009) if $high || $low > MAX_MESSAGE_BYTES;
        $length = $low;
        $offset = 10;
    }

    return if length($$buffer) < $offset + 4 + $length;
    my $frame = substr($$buffer, 0, $offset + 4 + $length, '');
    my $mask = substr($frame, $offset, 4);
    my $payload = substr($frame, $offset + 4) ^ substr($mask x int(($length + 3) / 4), 0, $length);
    return (0, $opcode, $fin, $payload);
}

sub _encode_frame {
    my ($opcode, $payload) = @_;

    my $length = length($payload);
    my $size = $length < 126   ? pack('C', $length)
             : $length < 65536 ? pack('Cn', 126, $length)
             :                   pack('CNN', 127, 0, $length);
    return pack('C', 0x80 | $opcode) . $size . $payload;
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
