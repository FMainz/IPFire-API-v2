use strict;
use warnings;

use File::Temp qw(tempfile);
use Socket qw(AF_INET AF_INET6 inet_pton pack_sockaddr_in pack_sockaddr_in6);
use Test::More;

use IPFire::API::NetworkPolicy;
use IPFire::API::NetworkSettings qw(client_network_presets listeners_for_zones);

sub peer {
    my ($address) = @_;
    my $ipv4 = inet_pton(AF_INET, $address);
    return defined($ipv4)
        ? pack_sockaddr_in(8444, $ipv4)
        : pack_sockaddr_in6(8444, inet_pton(AF_INET6, $address));
}

my $local = IPFire::API::NetworkPolicy->new('127.0.0.1', undef);
ok $local->allows_peer(peer('127.0.0.2')), 'default policy allows IPv4 loopback';
ok $local->allows_peer(peer('::1')), 'default policy allows IPv6 loopback';
ok !$local->allows_peer(peer('192.0.2.1')), 'default policy denies other IPv4 addresses';
ok !$local->allows_peer(peer('2001:db8::1')), 'default policy denies other IPv6 addresses';
ok !$local->allows_peer(undef), 'connections without a peer address are denied';

my $policy = IPFire::API::NetworkPolicy->new('192.0.2.1', '192.0.2.0/25, 2001:db8:0:0:8000::/65');
ok $policy->allows_peer(peer('192.0.2.127')), 'last address in an IPv4 prefix is allowed';
ok !$policy->allows_peer(peer('192.0.2.128')), 'first address outside an IPv4 prefix is denied';
ok $policy->allows_peer(peer('::ffff:192.0.2.127')), 'IPv4-mapped peers use the IPv4 policy';
ok $policy->allows_peer(peer('2001:db8::ffff:0:0:1')), 'address inside an IPv6 prefix is allowed';
ok !$policy->allows_peer(peer('2001:db8::7fff:0:0:1')), 'address outside an IPv6 prefix is denied';
ok !$policy->allows_peer(peer('127.0.0.1')), 'an explicit list replaces the defaults';

for my $host ('0.0.0.0', '::', 'localhost', '') {
    eval { IPFire::API::NetworkPolicy->new($host, '192.0.2.0/24') };
    like $@, qr/IPFIRE_API_HOST/, "invalid listener address '$host' is rejected";
}
eval { IPFire::API::NetworkPolicy->new('192.0.2.1', undef) };
like $@, qr/IPFIRE_API_ALLOWED_NETWORKS/, 'non-loopback listener requires explicit networks';

for my $networks ('', '192.0.2.0/33', '2001:db8::/129', '192.0.2.1', '127.0.0.1/32,') {
    eval { IPFire::API::NetworkPolicy->new('127.0.0.1', $networks) };
    like $@, qr/IPFIRE_API_ALLOWED_NETWORKS/, "invalid CIDR list '$networks' is rejected";
}

my ($ethernet, $path) = tempfile(UNLINK => 1);
print {$ethernet} <<'SETTINGS';
CONFIG_TYPE='2'
GREEN_ADDRESS=192.0.2.190
GREEN_NETMASK=255.255.255.192
ORANGE_ADDRESS=198.51.100.1
ORANGE_NETMASK=255.255.255.0
BLUE_ADDRESS=203.0.113.1
BLUE_NETMASK=255.255.255.0
RED_ADDRESS=192.0.2.1
RED_NETMASK=255.255.255.0
SETTINGS
close $ethernet or die "Cannot close test settings: $!";
my $presets = client_network_presets($path);
is_deeply $presets, [
    { id => 'green', network => '192.0.2.128/26', address => '192.0.2.190' },
    { id => 'orange', network => '198.51.100.0/24', address => '198.51.100.1' },
], 'presets use configured IPv4 prefixes and exclude RED and disabled BLUE';
is_deeply listeners_for_zones([qw(green orange)], $presets), [
    { host => '192.0.2.190', allowed_networks => '192.0.2.128/26' },
    { host => '198.51.100.1', allowed_networks => '198.51.100.0/24' },
], 'each selected zone pairs its listen address with its own source network';
eval { listeners_for_zones(['blue'], $presets) };
like $@, qr/selected network is unavailable/, 'a removed zone cannot be applied';

done_testing;
