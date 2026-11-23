package IPFire::API::NetworkPolicy;

use strict;
use warnings;

use Socket qw(AF_INET inet_pton sockaddr_family unpack_sockaddr_in);

sub new {
    my ($class, $host, $allowed_networks) = @_;

    my $address = inet_pton(AF_INET, $host);
    die "IPFIRE_API_HOST must be a specific IPv4 address\n"
        unless defined $address && $address ne "\0" x 4;

    if (!defined $allowed_networks) {
        die "Set IPFIRE_API_ALLOWED_NETWORKS for a non-loopback listener\n"
            unless substr($address, 0, 1) eq "\x7f";
        $allowed_networks = '127.0.0.0/8';
    }

    my @networks;
    for my $entry (split /,/, $allowed_networks, -1) {
        my ($ip, $bits) = $entry =~ /\A\s*([0-9.]+)\/([0-9]{1,3})\s*\z/;
        my $network = defined $ip ? inet_pton(AF_INET, $ip) : undef;
        die "IPFIRE_API_ALLOWED_NETWORKS must contain valid IPv4 CIDRs\n"
            unless defined $network && $bits <= 32;

        push @networks, [$network, $bits];
    }
    die "IPFIRE_API_ALLOWED_NETWORKS must contain at least one network\n" unless @networks;
    return bless { networks => \@networks }, $class;
}

sub allows_peer {
    my ($self, $peer) = @_;
    return 0 unless defined $peer && sockaddr_family($peer) == AF_INET;
    my (undef, $address) = unpack_sockaddr_in($peer);

    for my $entry (@{$self->{networks}}) {
        my ($network, $bits) = @$entry;
        my $bytes = int($bits / 8);
        next unless substr($address, 0, $bytes) eq substr($network, 0, $bytes);

        my $remaining = $bits % 8;
        return 1 unless $remaining;
        my $mask = 0xff << (8 - $remaining);
        return 1 if (ord(substr($address, $bytes, 1)) & $mask)
            == (ord(substr($network, $bytes, 1)) & $mask);
    }
    return 0;
}

1;
