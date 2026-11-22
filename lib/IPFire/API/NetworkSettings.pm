package IPFire::API::NetworkSettings;

use strict;
use warnings;

use Errno qw(ENOENT);
use Exporter 'import';
use Fcntl qw(O_RDONLY O_NONBLOCK O_NOFOLLOW S_ISREG);
use File::Basename qw(dirname);
use File::Temp;
use JSON::PP;
use Socket qw(AF_INET inet_ntop inet_pton);
use IPFire::API::NetworkPolicy;

our @EXPORT_OK = qw(load_network_settings save_network_settings client_network_presets listeners_for_zones);
my $json = JSON::PP->new->utf8->max_depth(4);

sub client_network_presets {
    my ($path) = @_;
    my @presets;
    open my $settings, '<', $path or return \@presets;

    my %settings;
    while (my $line = <$settings>) {
        my ($key, $value) = $line =~ /\A(CONFIG_TYPE|(?:GREEN|ORANGE|BLUE)_(?:ADDRESS|NETMASK))='?([0-9.]+)'?\s*\z/;
        $settings{$key} = $value if defined $key;
    }

    my $type = $settings{CONFIG_TYPE} // '';
    my %zones = (
        0 => ['GREEN'],
        1 => ['GREEN'],
        2 => [qw(GREEN ORANGE)],
        3 => [qw(GREEN BLUE)],
        4 => [qw(GREEN ORANGE BLUE)],
    );
    for my $zone (@{ $zones{$type} // [] }) {
        my ($address, $netmask) = @settings{"${zone}_ADDRESS", "${zone}_NETMASK"};
        next unless defined $address && defined $netmask;
        my $ip = inet_pton(AF_INET, $address);
        my $mask = inet_pton(AF_INET, $netmask);
        next unless defined $ip && defined $mask && $ip ne "\0" x 4;
        my ($prefix) = unpack('B32', $mask) =~ /\A(1+)0*\z/;
        next unless defined $prefix;
        my $network = pack('N', unpack('N', $ip) & unpack('N', $mask));
        my $cidr = inet_ntop(AF_INET, $network) . '/' . length($prefix);
        push @presets, { id => lc($zone), network => $cidr, address => inet_ntop(AF_INET, $ip) };
    }
    return \@presets;
}

sub listeners_for_zones {
    my ($zones, $presets) = @_;
    my $settings = _validate({ network_zones => $zones });
    my %presets = map { $_->{id} => $_ } @$presets;
    return [
        map {
            my $preset = $presets{$_}
                or die "A selected network is unavailable. Reload the page and try again.\n";
            { host => $preset->{address}, allowed_networks => $preset->{network} };
        } @{ $settings->{network_zones} }
    ];
}

sub load_network_settings {
    my ($path) = @_;
    unless (sysopen my $file, $path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW) {
        return {} if $! == ENOENT;
        die "Cannot read network settings\n";
    } else {
        my @info = stat $file;
        die "Invalid network settings file\n"
            unless @info && S_ISREG($info[2]) && $info[4] == $> && !($info[2] & 0022)
            && $info[7] <= 4096;
        my $length = read($file, my $data, 4097);
        die "Cannot read network settings\n" unless defined $length && $length == $info[7];
        my $settings = eval { $json->decode($data) };
        die "Invalid network settings file\n" unless ref $settings eq 'HASH';
        return _validate($settings);
    }
}

sub save_network_settings {
    my ($path, $settings) = @_;
    $settings = _validate($settings);
    my $file = File::Temp->new(DIR => dirname($path));
    print {$file} $json->encode($settings), "\n" or die "Cannot write network settings\n";
    close $file or die "Cannot close network settings\n";
    rename $file->filename(), $path or die "Cannot save network settings\n";
}

sub _validate {
    my ($settings) = @_;
    if (exists $settings->{network_zones}) {
        my $zones = $settings->{network_zones};
        die "Invalid network settings\n" unless ref($zones) eq 'ARRAY';
        die "Select at least one client network.\n" unless @$zones;
        my %seen;
        for my $zone (@$zones) {
            die "Invalid network settings\n"
                unless defined($zone) && !ref($zone) && $zone =~ /\A(?:green|orange|blue)\z/ && !$seen{$zone}++;
        }
        return { network_zones => $zones };
    }
    my ($host, $networks) = @{$settings}{qw(host allowed_networks)};
    die "Invalid network settings\n" unless defined($host) && !ref($host) && length($host) <= 45
        && (!defined($networks) || (!ref($networks) && length($networks) <= 2048));
    IPFire::API::NetworkPolicy->new($host, $networks);
    return { host => $host, allowed_networks => $networks };
}

1;
