use strict;
use warnings;
use Digest::SHA qw(sha1);
use IO::Socket::SSL;
use JSON::PP qw(decode_json encode_json);
use MIME::Base64 qw(encode_base64);

alarm 10;
die "Usage: perl t/ipfire-smoke.pl <certificate hostname> [connect address] [CA file] (token on stdin)\n"
    unless @ARGV >= 1 && @ARGV <= 3;
my ($host, $address, $ca_file) = @ARGV;
my $token = <STDIN> // '';
chomp $token;
die "Expected a client token on stdin\n" unless $token =~ /\A[a-z0-9][a-z0-9_-]{0,63}\.[0-9a-f]{64}\z/;
my $tls = IO::Socket::SSL->new(
    PeerHost => $address // '127.0.0.1', PeerPort => 8444,
    SSL_hostname => $host, SSL_verifycn_name => $host, SSL_verifycn_scheme => 'http',
    SSL_verify_mode => SSL_VERIFY_PEER, SSL_ca_file => $ca_file // '/etc/httpd/server.crt',
) or die IO::Socket::SSL::errstr() . "\n";
$tls->autoflush(1);
print $tls->get_sslversion(), " verified for $host\n";

open my $random, '<:raw', '/dev/urandom' or die "$!\n";
read($random, my $bytes, 32) == 32 or die "Could not read random bytes\n";
my $key = encode_base64(substr($bytes, 0, 16), '');
print {$tls} "GET / HTTP/1.1\r\nHost: $host:8444\r\nUpgrade: websocket\r\n"
    . "Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: $key\r\n"
    . "Authorization: Bearer $token\r\n\r\n"
    or die "Could not send upgrade\n";
my $headers = do { local $/ = "\r\n\r\n"; <$tls> } // '';
my $accept = encode_base64(sha1($key . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'), '');
die "Upgrade failed\n" unless $headers =~ /\AHTTP\/1\.1 101 / && $headers =~ /\r\nSec-WebSocket-Accept: \Q$accept\E\r\n/i;
print "Upgrade OK\n";

sub read_bytes {
    my ($socket, $length) = @_;
    my $data = '';
    while (length($data) < $length) {
        read($socket, my $chunk, $length - length($data)) or die "Incomplete frame reply\n";
        $data .= $chunk;
    }
    return $data;
}

my @frames = (
    [0x89, 0x8a, 16, 'Pong', ''],
    [0x81, 0x81, 20, 'system.ping', '{"id":"ping-1","method":"system.ping"}'],
    [0x81, 0x81, 24, 'system.info', '{"id":"info-1","method":"system.info"}'],
    [0x88, 0x88, 28, 'Close', ''],
);
for my $frame (@frames) {
    my ($send, $expect, $offset, $label, $payload) = @$frame;
    my $length = length($payload);
    my $mask = substr($bytes, $offset, 4);
    my $masked = $payload ^ substr($mask x int(($length + 3) / 4), 0, $length);
    print {$tls} pack('CC', $send, 0x80 | $length) . $mask . $masked
        or die "Could not send $label frame\n";
    my ($header, $size) = unpack('CC', read_bytes($tls, 2));
    die "Unexpected $label reply frame\n"
        unless $header == $expect && $size < 127 && ($expect == 0x81 || $size <= 125);
    $size = unpack('n', read_bytes($tls, 2)) if $size == 126;
    if ($label eq 'system.ping') {
        my $response = decode_json(read_bytes($tls, $size));
        my $pong = $response->{result}{pong};
        die "Unexpected system.ping result\n" unless ($response->{id} // '') eq 'ping-1'
            && JSON::PP::is_bool($pong) && $pong;
    } elsif ($label eq 'system.info') {
        my $response = decode_json(read_bytes($tls, $size));
        my $info = $response->{result};
        die "Unexpected system.info result\n" unless ($response->{id} // '') eq 'info-1'
            && ref($info) eq 'HASH' && length($info->{hostname} // '')
            && length($info->{ipfire_release} // '') && ($info->{uptime_seconds} // '') =~ /\A[0-9]+\z/;
        print encode_json($info), "\n";
    } else {
        die "Unexpected $label payload\n" if $size;
    }
    print "$label OK\n";
}
$tls->close();
