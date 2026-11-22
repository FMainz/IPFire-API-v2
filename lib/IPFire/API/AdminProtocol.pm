package IPFire::API::AdminProtocol;

use strict;
use warnings;

use Exporter 'import';
use JSON::PP;

our @EXPORT_OK = qw(read_message write_message);
my $json = JSON::PP->new->utf8->max_depth(8);
use constant MAX_MESSAGE => 65536;

sub read_message {
    my ($socket) = @_;
    my $size = unpack('N', _read_bytes($socket, 4));
    die "Invalid admin message length\n" if !$size || $size > MAX_MESSAGE;
    my $message = $json->decode(_read_bytes($socket, $size));
    die "Invalid admin message\n" unless ref($message) eq 'HASH';
    return $message;
}

sub write_message {
    my ($socket, $message) = @_;
    my $payload = $json->encode($message);
    die "Admin message is too large\n" if length($payload) > MAX_MESSAGE;
    print {$socket} pack('N', length($payload)), $payload or die "Cannot send admin message\n";
    $socket->flush() or die "Cannot send admin message\n";
}

sub _read_bytes {
    my ($socket, $size) = @_;
    my $buffer = '';
    while (length($buffer) < $size) {
        my $read = sysread($socket, my $part, $size - length($buffer));
        die "Incomplete admin message\n" unless $read;
        $buffer .= $part;
    }
    return $buffer;
}

1;
