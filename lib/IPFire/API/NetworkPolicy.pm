package IPFire::API::NetworkPolicy;

use strict;
use warnings;

use Socket qw(AF_INET AF_INET6 inet_pton sockaddr_family unpack_sockaddr_in unpack_sockaddr_in6);

my $ipv4_mapped_prefix = ("\0" x 10) . "\xff\xff";

sub _parse_address {
    my ($address) = @_;
    return inet_pton(AF_INET, $address) // inet_pton(AF_INET6, $address);
}

sub _is_mapped {
    my ($address) = @_;
    return length($address) == 16 && substr($address, 0, 12) eq $ipv4_mapped_prefix;
}

sub new {
    my ($class, $host, $allowed_networks) = @_;

    my $address = _parse_address($host);
    die "IPFIRE_API_HOST must be a specific IPv4 or IPv6 address\n"
        unless defined $address && $address ne "\0" x length($address) && !_is_mapped($address);

    if (!defined $allowed_networks) {
        my $loopback = length($address) == 4
            ? substr($address, 0, 1) eq "\x7f"
            : $address eq (("\0" x 15) . "\x01");
        die "Set IPFIRE_API_ALLOWED_NETWORKS for a non-loopback listener\n" unless $loopback;
        $allowed_networks = '127.0.0.0/8,::1/128';
    }

    my @networks;
    for my $entry (split /,/, $allowed_networks, -1) {
        my ($ip, $bits) = $entry =~ /\A\s*([0-9a-fA-F:.]+)\/([0-9]{1,3})\s*\z/;
        my $network = defined $ip ? _parse_address($ip) : undef;
        die "IPFIRE_API_ALLOWED_NETWORKS must contain valid IPv4 or IPv6 CIDRs\n"
            unless defined $network && $bits <= 8 * length($network) && !_is_mapped($network);

        push @networks, [$network, $bits];
    }
    die "IPFIRE_API_ALLOWED_NETWORKS must contain at least one network\n" unless @networks;
    return bless { networks => \@networks }, $class;
}

sub allows_peer {
    my ($self, $peer) = @_;
    return 0 unless defined $peer;

    my $family = sockaddr_family($peer);
    my $address;
    if ($family == AF_INET) {
        (undef, $address) = unpack_sockaddr_in($peer);
    } elsif ($family == AF_INET6) {
        (undef, $address) = unpack_sockaddr_in6($peer);
        $address = substr($address, 12) if _is_mapped($address);
    } else {
        return 0;
    }

    for my $entry (@{ $self->{networks} }) {
        my ($network, $bits) = @$entry;
        next unless length($address) == length($network);
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
