#!/usr/bin/perl
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 FMainz
# Legacy HA-IPFire interface and API v2 administration.

use strict;
use warnings;
use Fcntl qw(:DEFAULT :flock :mode);
use File::Temp;
use POSIX qw(setsid);
use Time::Local qw(timegm);

if (($ENV{'QUERY_STRING'} // '') =~ /\Aview=admin(?:&submit=1)?\z/) {
    # Map the installed API directory to the Perl namespace used in the checkout.
    local @INC = (sub {
        my (undef, $module) = @_;
        return unless $module =~ m{\AIPFire/(API/[A-Za-z0-9_]+\.pm)\z};
        open my $file, '<', "/usr/local/lib/$1" or return;
        return $file;
    }, @INC);
    require IPFire::API::AdminPage;
    IPFire::API::AdminPage::run();
    exit 0;
}

require '/var/ipfire/general-functions.pl';
require "/opt/pakfire/lib/functions.pl";
use JSON::PP;

my $api_version = "1";
my $api_revision = "0.2.15"; # Legacy HA-IPFire capability revision.
my $update_runtime_dir = '/tmp/ipfire-api';
my $update_state_file = "$update_runtime_dir/update.json";
my $update_lock_file = "$update_runtime_dir/update.lock";
my $update_log_file = "$update_runtime_dir/update.log";

# -----------------------------------------------------------------------------
# JSON helper
# -----------------------------------------------------------------------------

sub json_escape {
    my ($value) = @_;

    $value //= '';
    $value =~ s/\\/\\\\/g;
    $value =~ s/"/\\"/g;
    $value =~ s/\r/\\r/g;
    $value =~ s/\n/\\n/g;
    $value =~ s/\t/\\t/g;

    return $value;
}

sub json_string {
    my ($value) = @_;
    return '"' . json_escape($value) . '"';
}

sub dns_unescape_remark {
    my ($value) = @_;
    $value //= '';
    $value =~ s/&quot;/"/g;
    $value =~ s/&#39;/'/g;
    $value =~ s/&gt;/>/g;
    $value =~ s/&lt;/</g;
    $value =~ s/&amp;/&/g;
    return $value;
}

sub read_file {
    my ($path) = @_;

    open(my $fh, '<', $path) or return undef;
    my $value = <$fh>;
    close($fh);

    return undef unless defined $value;
    chomp $value;

    return $value;
}

sub ensure_update_runtime_dir {
    unless (-e $update_runtime_dir || -l $update_runtime_dir) {
        mkdir($update_runtime_dir, 0700)
            or return undef unless -d $update_runtime_dir;
    }

    return undef if -l $update_runtime_dir || !-d $update_runtime_dir;

    my @stat = lstat($update_runtime_dir);
    return undef unless @stat && $stat[4] == $>;

    if (($stat[2] & 0777) != 0700) {
        chmod(0700, $update_runtime_dir) or return undef;
    }

    return $update_runtime_dir;
}

sub print_json_headers {
    STDOUT->autoflush(1);
    print "Content-Type: application/json; charset=utf-8\r\n";
    print "Cache-Control: no-store, no-cache, must-revalidate\r\n";
    print "Pragma: no-cache\r\n";
    print "\r\n";
}

sub form_parameter {
    my ($body, $parameter) = @_;
    my @values;

    foreach my $pair (split(/&/, $body)) {
        my ($key, $value) = split(/=/, $pair, 2);
        next unless defined $key;
        $value //= '';
        $key =~ tr/+/ /;
        $value =~ tr/+/ /;
        $key =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg;
        $value =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg;
        push @values, $value if $key eq $parameter;
    }

    return undef unless @values == 1;
    return $values[0];
}

sub dns_config_data {
    my $settings_file = "${General::swroot}/dns/settings";
    my $servers_file = "${General::swroot}/dns/servers";
    my %settings = (
        'USE_ISP_NAMESERVERS' => 'off',
        'PROTO' => 'UDP',
        'ENABLE_SAFE_SEARCH' => 'off',
        'ENABLE_SAFE_SEARCH_YOUTUBE' => 'on',
    );
    eval { &General::readhash($settings_file, \%settings) if -f $settings_file; };

    my %manual_servers;
    eval { &General::readhasharray($servers_file, \%manual_servers) if -f $servers_file; };
    my @enabled;
    for my $id (sort { $a <=> $b } keys %manual_servers) {
        next unless $id =~ /^\d+$/ && ref($manual_servers{$id}) eq 'ARRAY';
        my ($address, $tls_hostname, $status, $remark) = @{$manual_servers{$id}};
        my $entry = {
            'id' => int($id), 'address' => $address // '', 'source' => 'manual',
            'enabled' => (($status // '') eq 'enabled') ? JSON::PP::true : JSON::PP::false,
        };
        $entry->{'tls_hostname'} = $tls_hostname if defined $tls_hostname && $tls_hostname ne '';
        $entry->{'remark'} = dns_unescape_remark($remark) if defined $remark && $remark ne '';
        push @enabled, $entry if ($status // '') eq 'enabled';
    }

    my $use_isp = ($settings{'USE_ISP_NAMESERVERS'} // 'off') eq 'on';
    for my $index (1 .. 2) {
        my $address = read_file("/var/run/dns$index");
        next unless defined $address && $address =~ /^[0-9a-fA-F:.]+$/;
        my $entry = {
            'id' => "isp$index", 'address' => $address, 'source' => 'isp',
            'enabled' => $use_isp ? JSON::PP::true : JSON::PP::false,
        };
        push @enabled, $entry if $use_isp;
    }

    return { 'enabled_servers' => \@enabled };
}

sub red_traffic_data {
    my $interface = read_file('/var/ipfire/red/iface');

    return (undef, undef) unless defined $interface;
    return (undef, undef) unless $interface =~ /^[A-Za-z0-9_.:-]+$/;

    my $rx_bytes = read_file("/sys/class/net/$interface/statistics/rx_bytes");
    my $tx_bytes = read_file("/sys/class/net/$interface/statistics/tx_bytes");

    return (undef, undef)
        unless defined $rx_bytes && defined $tx_bytes;

    return (undef, undef)
        unless $rx_bytes =~ /^\d+$/ && $tx_bytes =~ /^\d+$/;

    return (int($rx_bytes), int($tx_bytes));
}

sub system_data {
    open(my $fh, '<', '/etc/system-release') or return ('', 0, 0);

    my $version = <$fh>;
    close($fh);

    chomp($version) if defined $version;

    my %pakfire_status = &Pakfire::status();

    my $core_update =
        (($pakfire_status{'CoreUpdateAvailable'} // '') eq 'yes');

    my $package_updates =
        $pakfire_status{'PakUpdatesAvailable'} // 0;

    $package_updates = 0 unless $package_updates =~ /^\d+$/;
    $package_updates = int($package_updates);

    return (
        defined $version ? $version : '',
        $core_update,
        $package_updates,
    );
}

sub pakfire_updates_data {
    no warnings 'once';
    my $database_dir = $Conf::dbdir;
    return undef unless defined $database_dir && $database_dir ne '';

    my $core_list_file = "$database_dir/lists/core-list.db";
    open(my $core_fh, '<', $core_list_file) or return undef;
    my $available_core_release;
    while (my $line = <$core_fh>) {
        if ($line =~ /^\s*\$?core_release\s*=\s*["']?(\d+)["']?/) {
            $available_core_release = int($1);
            last;
        }
    }
    close($core_fh);

    my $installed_core_release = $Conf::core_mine;
    return undef unless defined $installed_core_release
        && $installed_core_release =~ /^\d+$/;
    return undef unless defined $available_core_release;

    my @updates;
    if ($available_core_release > $installed_core_release) {
        push @updates, {
            'type' => 'core',
            'name' => 'core',
            'version' => $Conf::version,
            'installed_release' => int($installed_core_release),
            'available_release' => $available_core_release,
        };
    }

    my $packages_file = "$database_dir/lists/packages_list.db";
    open(my $packages_fh, '<', $packages_file) or return undef;
    my %available_packages;
    while (my $line = <$packages_fh>) {
        chomp $line;
        my ($name, $version, $release) = split(/;/, $line);
        next unless defined $name && defined $version && defined $release;
        next unless $release =~ /^\d+$/;
        $available_packages{$name} = {
            'version' => $version,
            'release' => int($release),
        };
    }
    close($packages_fh);

    my $installed_dir = "$database_dir/installed";
    opendir(my $installed_dh, $installed_dir) or return undef;
    my @installed_files = sort grep { $_ ne '.' && $_ ne '..' && $_ !~ /^old/ }
        readdir($installed_dh);
    closedir($installed_dh);

    foreach my $file (@installed_files) {
        my $path = "$installed_dir/$file";
        next unless -f $path;
        open(my $meta_fh, '<', $path) or return undef;

        my ($name, $version, $release);
        while (my $line = <$meta_fh>) {
            if ($line =~ /^Name:\s*(.*?)\s*$/) {
                $name = $1;
            } elsif ($line =~ /^ProgVersion:\s*(.*?)\s*$/) {
                $version = $1;
            } elsif ($line =~ /^Release:\s*(\d+)\s*$/) {
                $release = int($1);
            }
        }
        close($meta_fh);

        next unless defined $name && defined $version && defined $release;
        my $available = $available_packages{$name};
        next unless defined $available;
        next unless $release < $available->{'release'};

        push @updates, {
            'type' => 'package',
            'name' => $name,
            'installed_version' => $version,
            'available_version' => $available->{'version'},
            'installed_release' => $release,
            'available_release' => $available->{'release'},
        };
    }

    return \@updates;
}

sub write_update_operation_state {
    my ($state) = @_;
    return 0 unless defined ensure_update_runtime_dir();
    my $temporary_file = $update_state_file . '.' . $$;

    open(my $fh, '>', $temporary_file) or return 0;
    print {$fh} encode_json($state), "\n";
    close($fh) or return 0;
    chmod(0600, $temporary_file);

    unless (rename($temporary_file, $update_state_file)) {
        unlink($temporary_file);
        return 0;
    }

    return 1;
}

sub read_update_operation_state {
    my $contents = read_file($update_state_file);
    return undef unless defined $contents;

    my $state = eval { decode_json($contents) };
    return undef unless ref($state) eq 'HASH';

    return $state;
}

sub update_operation_data {
    return { 'status' => 'unknown' }
        unless defined ensure_update_runtime_dir();

    my $state = read_update_operation_state();
    unless (-e $update_lock_file) {
        return $state if defined $state;
        return {
            'status' => 'idle',
            'started_at' => undef,
            'finished_at' => undef,
            'exit_code' => undef,
        };
    }

    sysopen(my $lock_fh, $update_lock_file, O_RDWR | O_CREAT, 0600)
        or return { 'status' => 'unknown' };

    unless (flock($lock_fh, LOCK_EX | LOCK_NB)) {
        if (defined $state && ($state->{'status'} // '') =~ /^(?:starting|running)$/) {
            $state->{'status'} = 'running';
            $state->{'finished_at'} = undef;
            $state->{'exit_code'} = undef;
            delete $state->{'error'};
            return $state;
        }

        return {
            'status' => 'running',
            'started_at' => time(),
            'finished_at' => undef,
            'exit_code' => undef,
        };
    }

    if (defined $state && ($state->{'status'} // '') =~ /^(?:starting|running)$/) {
        $state->{'status'} = 'failed';
        $state->{'error'} = 'process_ended_unexpectedly';
        $state->{'finished_at'} = time();
        write_update_operation_state($state);
    }

    close($lock_fh);

    return $state if defined $state;
    return {
        'status' => 'idle',
        'started_at' => undef,
        'finished_at' => undef,
        'exit_code' => undef,
    };
}

sub start_pakfire_upgrade {
    my $pakfire = '/usr/local/bin/pakfire';
    return { 'result' => 'error', 'error' => 'pakfire_not_found' }
        unless -x $pakfire;

    return { 'result' => 'error', 'error' => 'update_runtime_unavailable' }
        unless defined ensure_update_runtime_dir();

    sysopen(my $lock_fh, $update_lock_file, O_RDWR | O_CREAT, 0600)
        or return { 'result' => 'error', 'error' => 'update_lock_unavailable' };

    unless (flock($lock_fh, LOCK_EX | LOCK_NB)) {
        close($lock_fh);
        return { 'result' => 'error', 'error' => 'update_in_progress' };
    }

    my @system_status = system_data();
    my $core_update = $system_status[1];
    my $package_updates = $system_status[2];
    my $updates = pakfire_updates_data();
    unless (defined $updates) {
        close($lock_fh);
        return { 'result' => 'error', 'error' => 'update_list_unavailable' };
    }
    unless (@{$updates}) {
        close($lock_fh);
        return { 'result' => 'error', 'error' => 'no_updates_available' };
    }

    my $started_at = time();
    my $state = {
        'status' => 'starting',
        'started_at' => $started_at,
        'finished_at' => undef,
        'exit_code' => undef,
    };
    unless (write_update_operation_state($state)) {
        close($lock_fh);
        return { 'result' => 'error', 'error' => 'update_state_unavailable' };
    }

    my $pid = fork();
    unless (defined $pid) {
        $state->{'status'} = 'failed';
        $state->{'error'} = 'could_not_start_update';
        $state->{'finished_at'} = time();
        write_update_operation_state($state);
        close($lock_fh);
        return { 'result' => 'error', 'error' => 'could_not_start_update' };
    }

    if ($pid == 0) {
        eval { setsid(); };
        $SIG{'HUP'} = 'IGNORE';
        umask(0077);

        close(STDIN);
        close(STDOUT);
        close(STDERR);
        open(STDIN, '<', '/dev/null');
        open(STDOUT, '>>', $update_log_file) or open(STDOUT, '>', '/dev/null');
        open(STDERR, '>&STDOUT');
        $| = 1;

        $state->{'status'} = 'running';
        write_update_operation_state($state);

        my $result = system { $pakfire } $pakfire, 'upgrade', '-y', '--no-colors';
        if ($result == -1) {
            $state->{'status'} = 'failed';
            $state->{'error'} = 'could_not_execute_pakfire';
        } elsif ($result & 127) {
            $state->{'status'} = 'failed';
            $state->{'error'} = 'pakfire_terminated_by_signal';
            $state->{'exit_code'} = 128 + ($result & 127);
        } else {
            $state->{'exit_code'} = $result >> 8;
            $state->{'status'} = $state->{'exit_code'} == 0 ? 'completed' : 'failed';
            $state->{'error'} = 'pakfire_failed' if $state->{'exit_code'} != 0;
        }
        $state->{'finished_at'} = time();
        write_update_operation_state($state);
        close($lock_fh);
        POSIX::_exit(0);
    }

    close($lock_fh);
    return {
        'result' => 'accepted',
        'status' => 'running',
        'started_at' => $started_at,
    };
}

sub cpu_data {
    open(my $fh, '<', '/proc/stat') or return (undef, undef);

    my @fields;

    while (my $line = <$fh>) {
        if ($line =~ /^cpu\s+(.+)$/) {
            @fields = split(/\s+/, $1);
            last;
        }
    }

    close($fh);

    return (undef, undef) unless @fields >= 8;

    foreach my $value (@fields[0 .. 7]) {
        return (undef, undef) unless $value =~ /^\d+$/;
    }

    # user + nice + system + idle + iowait + irq + softirq + steal
    my $total = 0;
    $total += $_ for @fields[0 .. 7];

    # idle + iowait
    my $idle = $fields[3] + $fields[4];

    return (int($total), int($idle));
}

sub memory_data {
    open(my $fh, '<', '/proc/meminfo') or return ();

    my %memory;

    while (my $line = <$fh>) {
        if ($line =~ /^(MemTotal|MemAvailable|MemFree|Buffers|Cached):\s+(\d+)\s+kB$/) {
            $memory{$1} = int($2) * 1024;
        }
    }

    close($fh);

    return (
        $memory{'MemTotal'},
        $memory{'MemAvailable'},
        $memory{'MemFree'},
        $memory{'Buffers'},
        $memory{'Cached'},
    );
}

sub uptime_data {
    open(my $fh, '<', '/proc/uptime') or return undef;

    my $line = <$fh>;

    close($fh);

    return undef unless defined $line;

    my ($uptime) = split(/\s+/, $line);

    return undef unless defined $uptime;
    return undef unless $uptime =~ /^\d+(?:\.\d+)?$/;

    return int($uptime);
}

sub disk_data {
    open(my $fh, '-|', 'df', '-B1', '/') or return ();

    my $header = <$fh>;
    my $line = <$fh>;

    close($fh);

    return () unless defined $line;

    $line =~ s/^\s+|\s+$//g;

    my @fields = split(/\s+/, $line);

    return () unless @fields >= 6;
    return () unless $fields[1] =~ /^\d+$/;
    return () unless $fields[2] =~ /^\d+$/;
    return () unless $fields[3] =~ /^\d+$/;
    return () unless $fields[4] =~ /^(\d+)%$/;

    my $total = int($fields[1]);
    my $used = int($fields[2]);
    my $available = int($fields[3]);
    my $use_percent = int($1);

    return (
        $total,
        $used,
        $available,
        $use_percent,
    );
}

sub smart_data {
    my $runtime_dir = ensure_update_runtime_dir();
    my $cache_file = defined $runtime_dir ? "$runtime_dir/smart.json" : undef;
    my $cache_age  = 60 * 60;    # 60 Minuten

    # Cache verwenden, wenn vorhanden, nicht leer und noch aktuell
    if (defined $cache_file && -f $cache_file && -s $cache_file) {
        my $mtime = (stat($cache_file))[9];

        if (defined $mtime && (time - $mtime) < $cache_age) {
            open(my $fh, '<', $cache_file) or return undef;

            local $/;
            my $data = <$fh>;

            close($fh);

            my $cached = eval { decode_json($data) };
            if (ref($cached) eq 'HASH' && defined $cached->{temperature} && defined $cached->{errors}) {
                return encode_json({ temperature => $cached->{temperature}, errors => $cached->{errors} });
            }
        }
    }

    # SMART-Daten über den von IPFire vorgesehenen Wrapper ermitteln.
    my $output = '';

    if (open(my $fh, '-|', '/usr/local/bin/smartctrl', 'sda')) {
        local $/;
        $output = <$fh> // '';

        close($fh);
    }

    # SMART-Ausgabe muss einen erfolgreichen Health-Test enthalten.
    return undef
        unless $output =~ /SMART overall-health self-assessment test result:\s*PASSED/i;

    # SMART-Attribute aus der tabellarischen Ausgabe auswerten.
    my (
        $temperature,
        $power_on_hours,
        $power_cycles,
        $uncorrectable_errors,
        $remaining_lifetime,
    );

    foreach my $line (split(/\n/, $output)) {
        $line =~ s/^\s+|\s+$//g;

        my @fields = split(/\s+/, $line);

        # SMART-Attributzeilen beginnen mit der Attribut-ID.
        next unless @fields >= 10;
        next unless $fields[0] =~ /^\d+$/;

        my $id  = int($fields[0]);
        my $raw = $fields[-1];

        next unless $raw =~ /^\d+$/;

        if ($id == 9) {
            $power_on_hours = int($raw);
        } elsif ($id == 12) {
            $power_cycles = int($raw);
        } elsif ($id == 160) {
            $uncorrectable_errors = int($raw);
        } elsif ($id == 169) {
            $remaining_lifetime = int($raw);
        } elsif ($id == 194) {
            $temperature = int($raw);
        }
    }

    # Nur vollständige SMART-Daten als gültiges Ergebnis akzeptieren.
    return undef
        unless defined $temperature
            && defined $power_on_hours
            && defined $power_cycles
            && defined $uncorrectable_errors
            && defined $remaining_lifetime;

    # smartctrl liefert in der aktuellen Ausgabe keinen SMART-Error-Log.
    # Daher bleibt errors zunächst 0.
    my $errors = 0;

    my $json = encode_json({ temperature => $temperature, errors => $errors });

    # Nur vollständige und erfolgreiche SMART-Daten cachen.
    if (defined $cache_file) {
        eval {
            my $cache = File::Temp->new(DIR => $runtime_dir);
            rename($cache->filename(), $cache_file) if print {$cache} $json and close($cache);
        };
    }

    return $json;
}

sub fireinfo_data {
    my $profile_file = '/var/ipfire/fireinfo/profile';

    open(my $fh, '<', $profile_file) or return ();

    local $/;
    my $json = <$fh>;
    close($fh);

    my $data = eval { decode_json($json) };
    return () if $@ || !ref($data);

    my $profile = $data->{'profile'} // {};

    my $cpu = $profile->{'cpu'} // {};
    my $network = $profile->{'network'} // {};
    my $system = $profile->{'system'} // {};

    return (
        $cpu->{'arch'} // '',
        $cpu->{'model_string'} // '',
        int($cpu->{'count'} // 0),

        $system->{'model'} // '',
        $system->{'vendor'} // '',
        $system->{'virtual'} ? 1 : 0,

        $network->{'blue'} ? 1 : 0,
        $network->{'green'} ? 1 : 0,
        $network->{'orange'} ? 1 : 0,
        $network->{'red'} ? 1 : 0,
    );
}

sub configured_interface_name {
    my ($device) = @_;
    return undef unless defined $device;

    # IPFire can store the lower-device suffix shown by `ip link`, e.g.
    # blue0@green0. The actual sysfs directory is named only blue0.
    $device =~ s/\@.*$//;
    return undef unless $device =~ /^[A-Za-z0-9_.:-]+$/;

    return $device;
}

sub sysfs_interface_name {
    my ($device) = @_;
    $device = configured_interface_name($device);
    return undef unless defined $device;
    return undef unless -e "/sys/class/net/$device";

    return $device;
}

sub network_device_for_mac {
    my ($mac_address) = @_;
    return undef unless defined $mac_address;
    return undef unless $mac_address =~ /^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/i;

    opendir(my $dh, '/sys/class/net') or return undef;
    my (@matches, @physical_matches);

    while (my $device = readdir($dh)) {
        next unless $device =~ /^[A-Za-z0-9_.:-]+$/;
        my $address = read_file("/sys/class/net/$device/address");
        next unless defined $address && lc($address) eq lc($mac_address);

        push @matches, $device;
        push @physical_matches, $device if -e "/sys/class/net/$device/device";
    }

    closedir($dh);

    return $physical_matches[0] if @physical_matches;
    return $matches[0] if @matches;
    return undef;
}

sub network_interface_data {
    my ($configured_device) = @_;
    my $device = sysfs_interface_name($configured_device);
    return undef unless defined $device;

    my %data = (
        'device' => $device,
        'rx_bytes' => undef,
        'tx_bytes' => undef,
    );

    my $rx_bytes = read_file("/sys/class/net/$device/statistics/rx_bytes");
    my $tx_bytes = read_file("/sys/class/net/$device/statistics/tx_bytes");
    $data{'rx_bytes'} = int($rx_bytes)
        if defined $rx_bytes && $rx_bytes =~ /^\d+$/;
    $data{'tx_bytes'} = int($tx_bytes)
        if defined $tx_bytes && $tx_bytes =~ /^\d+$/;

    return \%data;
}

sub network_interfaces_data {
    my %settings;
    &General::readhash("${General::swroot}/ethernet/settings", \%settings);

    my %interfaces;
    foreach my $zone (qw(red green orange blue)) {
        my $device = $settings{uc($zone) . '_DEV'};
        $interfaces{$zone} = network_interface_data($device);
    }

    return \%interfaces;
}

sub network_hosts_data {
    my $hosts_file = "${General::swroot}/main/hosts";
    return undef unless -r $hosts_file;

    open(my $fh, '<', $hosts_file) or return undef;
    my @hosts;

    while (my $line = <$fh>) {
        chomp $line;
        $line =~ s/\r$//;
        next if $line =~ /^\s*(?:#|$)/;

        my @fields = split(/,/, $line, -1);
        next unless @fields >= 5;

        my ($enabled, $address, $hostname, $domain, $ptr) = @fields;
        next unless defined $address && length $address;
        next unless defined $hostname && length $hostname;

        my $fqdn = length($domain // '') ? "$hostname.$domain" : $hostname;
        my %entry = (
            'enabled' => ($enabled // '') eq 'on' ? JSON::PP::true() : JSON::PP::false(),
            'ip_address' => $address,
            'hostname' => $hostname,
            'fqdn' => $fqdn,
            'ptr_enabled' => ($ptr // '') eq 'off' ? JSON::PP::false() : JSON::PP::true(),
        );
        $entry{'domain'} = $domain if defined $domain && length $domain;
        push @hosts, \%entry;
    }

    close($fh);
    return \@hosts;
}

sub dhcp_leases_data {
    my $lease_file = '/var/state/dhcp/dhcpd.leases';
    open(my $fh, '<', $lease_file) or return undef;

    my %leases;
    my $lease;

    while (my $line = <$fh>) {
        if ($line =~ /^\s*lease\s+(\S+)\s*\{/) {
            $lease = {
                'ip_address' => $1,
                'mac_address' => undef,
                'hostname' => undef,
                'expires_at' => undef,
                'expires_never' => JSON::PP::false,
                'status' => 'unknown',
                'expired' => undef,
            };
            next;
        }

        next unless defined $lease;

        if ($line =~ /^\s*ends\s+\d\s+(\d{4})\/(\d{1,2})\/(\d{1,2})\s+(\d{1,2}):(\d{1,2}):(\d{1,2})/) {
            my ($year, $month, $day, $hour, $minute, $second) = ($1, $2, $3, $4, $5, $6);
            my $expires = eval {
                timegm($second, $minute, $hour, $day, $month - 1, $year);
            };
            if (defined $expires) {
                $lease->{'expires_at'} = sprintf(
                    '%04d-%02d-%02dT%02d:%02d:%02dZ',
                    $year, $month, $day, $hour, $minute, $second
                );
                my $expired = $expires <= time();
                $lease->{'status'} = $expired ? 'expired' : 'active';
                $lease->{'expired'} = $expired ? JSON::PP::true() : JSON::PP::false();
            }
        } elsif ($line =~ /^\s*ends\s+never/) {
            $lease->{'expires_never'} = JSON::PP::true();
            $lease->{'status'} = 'active';
            $lease->{'expired'} = JSON::PP::false();
        } elsif ($line =~ /^\s*hardware\s+ethernet\s+([0-9a-f:]+);/i) {
            $lease->{'mac_address'} = lc($1);
        } elsif ($line =~ /^\s*client-hostname\s+"((?:\\.|[^"])*)";/) {
            my $hostname = $1;
            $hostname =~ s/\\(["\\])/$1/g;
            $lease->{'hostname'} = $hostname;
        } elsif ($line =~ /^\s*\}\s*$/) {
            # The lease file keeps historical records. The latest record for
            # an address is the one shown by IPFire's current lease list.
            $leases{$lease->{'ip_address'}} = $lease;
            $lease = undef;
        }
    }

    close($fh);
    return [ map { $leases{$_} } sort keys %leases ];
}

sub services_data {
    my %services = (
        'dhcp' => {
            'process' => 'dhcpd',
        },
        'web_server' => {
            'process' => 'httpd',
        },
        'cron' => {
            'process' => 'fcron',
        },
        'dns_resolver' => {
            'process' => 'kresd',
        },
        'logging' => {
            'process' => 'syslogd',
        },
        'ntp' => {
            'process' => 'ntpd',
        },
        'ssh' => {
            'process' => 'sshd',
        },
        'vpn' => {
            'process' => 'charon',
        },
        'web_proxy' => {
            'process' => 'squid',
        },
        'ips' => {
            'pidfile' => '/var/run/suricata.pid',
        },
        'ovpn_roadwarrior' => {
            'process' => 'openvpn',
            'pidfile' => '/var/run/openvpn-rw.pid',
        },
        'lldp' => {
            'process' => 'lldpd',
        },
        'dbus' => {
            'process' => 'dbus-daemon',
            'pidfile' => '/var/run/dbus/pid',
        },
    );

    my %status;

    foreach my $service (keys %services) {
        my %config = %{ $services{$service} };

        my @pids;

        if (defined $config{'pidfile'}) {
            @pids = &General::read_pids($config{'pidfile'});
        } else {
            @pids = &General::find_pids($config{'process'});
        }

        $status{$service} = scalar(@pids) ? 1 : 0;
    }

    return %status;
}

sub addons_data {
    my %addons;

    my %paklist = &Pakfire::dblist("installed");

    foreach my $pak (sort keys %paklist) {
        my %metadata = &Pakfire::getmetadata($pak, "installed");

        next unless "$metadata{'Services'}";

        foreach my $service (split(/ /, "$metadata{'Services'}")) {
            next unless $service;

            my @status = &General::system_output(
                "/usr/local/bin/addonctrl",
                "$pak",
                "status",
                "$service"
            );

            my $output = join('', @status);

            my $running =
                ($output =~ /is\ running/ && $output !~ /is\ not\ running/);

            $addons{$pak} = {
                'running' => $running ? 1 : 0,
            };
        }
    }

    return %addons;
}

my $method = $ENV{'REQUEST_METHOD'} // 'GET';
my $post_body = '';

if ($method eq 'POST') {
    my $api_header = $ENV{'HTTP_X_IPFIRE_API'} // '';
    my $legacy_api_header = $ENV{'HTTP_X_HA_IPFIRE_API'} // '';

    if ($api_header ne '1' && $legacy_api_header ne '1') {
        print_json_headers();
        print '{"api_version":'.$api_version.',"api_revision":'.json_string($api_revision).',"error":"forbidden"}';
        exit 0;
    }

    my $content_length = $ENV{'CONTENT_LENGTH'} // 0;
    if ($content_length =~ /\A[0-9]{1,4}\z/ && $content_length <= 4096) {
        while (length($post_body) < $content_length) {
            my $part;
            unless (read(STDIN, $part, $content_length - length($post_body))) {
                $post_body = '';
                last;
            }
            $post_body .= $part;
        }
    }
    print_json_headers();
    my $action = form_parameter($post_body, 'action') // '';

    if ($action eq 'upgrade') {
        my $result = start_pakfire_upgrade();
        print encode_json({ 'api_version' => int($api_version), 'api_revision' => $api_revision, %{$result} });
        exit 0;
    }

    if ($action eq 'reboot') {
        unless (-e '/var/run/need_reboot') {
            print encode_json({
                'api_version' => int($api_version),
                'api_revision' => $api_revision,
                'result' => 'error',
                'error' => 'reboot_not_required',
            });
            exit 0;
        }

        my $reboot_helper = '/usr/local/bin/ipfirereboot';
        unless (-x $reboot_helper) {
            print encode_json({
                'api_version' => int($api_version),
                'api_revision' => $api_revision,
                'result' => 'error',
                'error' => 'reboot_helper_not_found',
            });
            exit 0;
        }

        my $pid = fork();
        unless (defined $pid) {
            print encode_json({
                'api_version' => int($api_version),
                'api_revision' => $api_revision,
                'result' => 'error',
                'error' => 'could_not_schedule_reboot',
            });
            exit 0;
        }

        if ($pid == 0) {
            eval { setsid(); };
            $SIG{'HUP'} = 'IGNORE';
            close(STDIN);
            close(STDOUT);
            close(STDERR);
            open(STDIN, '<', '/dev/null');
            open(STDOUT, '>', '/dev/null');
            open(STDERR, '>&STDOUT');
            sleep 1;
            exec { $reboot_helper } $reboot_helper, 'boot'
                or POSIX::_exit(127);
        }

        print encode_json({
            'api_version' => int($api_version),
            'api_revision' => $api_revision,
            'result' => 'accepted',
            'status' => 'rebooting',
        });
        exit 0;
    }

    if ($action ne 'connect' && $action ne 'disconnect') {
        print '{"api_version":'.$api_version.',"api_revision":'.json_string($api_revision).',"error":"invalid_action"}';
        exit 0;
    }

    my $redctrl = '/usr/local/bin/redctrl';

    unless (-x $redctrl) {
        print '{"api_version":'.$api_version.',"api_revision":'.json_string($api_revision).',"error":"redctrl_not_found"}';
        exit 0;
    }

    my $command;

    if ($action eq 'connect') {
        $command = -e "${General::swroot}/red/active"
            ? 'restart'
            : 'start';
    } elsif ($action eq 'disconnect') {
        if (!-e "${General::swroot}/red/active") {
            print '{"api_version":'.$api_version.',"api_revision":'.json_string($api_revision).',"result":"ok"}';
            exit 0;
        }

        $command = 'stop';
    }
    unless (defined $command) {
        print '{"api_version":'.$api_version.',"api_revision":'.json_string($api_revision).',"result":"error","error":"invalid_action"}';
        exit 0;
    }

    my $result;

    {
        open my $null, '>', '/dev/null'
            or die "Cannot open /dev/null: $!";

        local *STDOUT = $null;
        local *STDERR = $null;

        $result = system("$redctrl $command >/dev/null 2>&1");
    }

    if ($result == 0) {
        print '{"api_version":'.$api_version.',"api_revision":'.json_string($api_revision).',"result":"ok"}';
    } else {
        my $exit_code = $result >> 8;
        print '{"api_version":'.$api_version.',"api_revision":'.json_string($api_revision).',"result":"error","error":"redctrl_failed","exit_code":'
            . $exit_code
            . "}";
    }

    exit 0;
}

if ($method ne 'GET') {
    print_json_headers();
    print '{"api_version":'.$api_version.',"api_revision":'.json_string($api_revision).',"error":"method_not_allowed"}';
    exit 0;
}

my ($version, $core_update, $package_updates) = system_data();
my $reboot_required = -e '/var/run/need_reboot' ? 1 : 0;
my $available_updates = pakfire_updates_data();
my $update_operation = update_operation_data();
my ($red_rx_bytes, $red_tx_bytes) = red_traffic_data();
my ($cpu_total, $cpu_idle) = cpu_data();
my $uptime = uptime_data();
my $smart = smart_data();

my ($memory_total,
    $memory_available,
    $memory_free,
    $memory_buffers,
    $memory_cached,
) = memory_data();

my (
    $disk_total,
    $disk_used,
    $disk_available,
    $disk_use_percent,
) = disk_data();

my (
    $architecture,
    $cpu_model,
    $cpu_count,
    $model,
    $vendor,
    $virtual,
    $blue,
    $green,
    $orange,
    $red,
) = fireinfo_data();

my $pakfire_version = &Pakfire::make_version();
my @kernel_version = &General::system_output("uname", "-r");
my $kernel_release = $kernel_version[0] // '';
chomp($kernel_release);

my %services = services_data();
my $dhcp_leases = dhcp_leases_data();
my %addons = addons_data();
my $network_interfaces = network_interfaces_data();
my $network_hosts = network_hosts_data();

print_json_headers();

# -----------------------------------------------------------------------------
# Read IPFire connection information
# -----------------------------------------------------------------------------

my %pppsettings = ();
&General::readhash("${General::swroot}/ppp/settings", \%pppsettings);

my $state = 'disconnected';
my $duration = 0;
my $connected_since = undef;

# IPFire creates /var/ipfire/red/active while the RED connection is active.
# Its modification time is also used by Header::connectionstatus() to display
# the connection age.
my $active_file = "${General::swroot}/red/active";

if (-e $active_file) {
    my @stat = stat($active_file);
    my $mtime = $stat[9];

    if (defined $mtime) {
        $connected_since = int($mtime);
        $duration = time() - $mtime;
        $duration = 0 if $duration < 0;
    }

    $state = 'connected';
} else {
    # Match IPFire's own connectionstatus() logic:
    # keepconnected + running pppd means that the connection is being brought
    # up; otherwise the connection is closed.
    my $keepconnected = "${General::swroot}/red/keepconnected";

    if (-e $keepconnected) {
        my $pppd_running = system("ps -ef | grep -q '[p]ppd'") == 0;
        $state = 'connecting' if $pppd_running;
    }
}

my $profile = $pppsettings{'PROFILENAME'} // '';

my $external_ip = read_file("${General::swroot}/red/local-ipaddress");
my $external_hostname = '';

if ($external_ip ne '') {
    $external_hostname =
        (gethostbyaddr(pack("C4", split(/\./, $external_ip)), 2))[0]
        || '';
}

# -----------------------------------------------------------------------------
# JSON response
# -----------------------------------------------------------------------------

my @json;
push @json, '"api_version":'.$api_version;
push @json, '"api_revision":'.json_string($api_revision);

push @json, '"system":{'
    . '"version":' . json_string($version)
    . ',"pakfire_version":' . json_string($pakfire_version)
    . ',"kernel_version":' . json_string($kernel_release)
    . ',"architecture":' . json_string($architecture)
    . ',"cpu_model":' . json_string($cpu_model)
    . ',"cpu_count":' . (defined $cpu_count ? $cpu_count : 'null')
    . ',"model":' . json_string($model)
    . ',"vendor":' . json_string($vendor)
    . ',"virtual":' . ($virtual ? 'true' : 'false')
    . ',"core_update":' . ($core_update ? 'true' : 'false')
    . ',"package_updates":' . $package_updates
    . ',"reboot_required":' . ($reboot_required ? 'true' : 'false')
    . ',"uptime":' . (defined $uptime ? $uptime : 'null')
    . ',"cpu":{'
    . '"total":' . (defined $cpu_total ? $cpu_total : 'null')
    . ',"idle":' . (defined $cpu_idle ? $cpu_idle : 'null')
    . '}'
    . ',"memory":{'
    . '"total":' . (defined $memory_total ? $memory_total : 'null')
    . ',"available":' . (defined $memory_available ? $memory_available : 'null')
    . ',"free":' . (defined $memory_free ? $memory_free : 'null')
    . ',"buffers":' . (defined $memory_buffers ? $memory_buffers : 'null')
    . ',"cached":' . (defined $memory_cached ? $memory_cached : 'null')
    . '}'
    . ',"disk":{'
    . '"root":{'
    . '"total":' . (defined $disk_total ? $disk_total : 'null')
    . ',"used":' . (defined $disk_used ? $disk_used : 'null')
    . ',"available":' . (defined $disk_available ? $disk_available : 'null')
    . ',"use_percent":' . (defined $disk_use_percent ? $disk_use_percent : 'null')
    . '}'
    . '}'
    . ',"smart":' . (defined $smart ? $smart : '{}')
    . '}';

push @json, '"updates":{"available":'
    . (defined $available_updates ? encode_json($available_updates) : 'null')
    . ',"operation":' . encode_json($update_operation)
    . '}';

my @network_json = (
    '"blue":' . ($blue ? 'true' : 'false'),
    '"green":' . ($green ? 'true' : 'false'),
    '"orange":' . ($orange ? 'true' : 'false'),
    '"red":' . ($red ? 'true' : 'false'),
    '"interfaces":' . encode_json($network_interfaces),
);
push @network_json, '"hosts":' . encode_json($network_hosts)
    if defined $network_hosts;
push @network_json, '"dns":' . encode_json(dns_config_data());
push @json, '"network":{' . join(',', @network_json) . '}';

push @json, '"dhcp":{"leases":'
    . (defined $dhcp_leases ? encode_json($dhcp_leases) : 'null')
    . '}';

push @json, '"services":{'
    . '"dhcp":' . ($services{'dhcp'} ? 'true' : 'false')
    . ',"web_server":' . ($services{'web_server'} ? 'true' : 'false')
    . ',"cron":' . ($services{'cron'} ? 'true' : 'false')
    . ',"dns_resolver":' . ($services{'dns_resolver'} ? 'true' : 'false')
    . ',"logging":' . ($services{'logging'} ? 'true' : 'false')
    . ',"ntp":' . ($services{'ntp'} ? 'true' : 'false')
    . ',"ssh":' . ($services{'ssh'} ? 'true' : 'false')
    . ',"vpn":' . ($services{'vpn'} ? 'true' : 'false')
    . ',"web_proxy":' . ($services{'web_proxy'} ? 'true' : 'false')
    . ',"ips":' . ($services{'ips'} ? 'true' : 'false')
    . ',"ovpn_roadwarrior":' . ($services{'ovpn_roadwarrior'} ? 'true' : 'false')
    . ',"lldp":' . ($services{'lldp'} ? 'true' : 'false')
    . ',"dbus":' . ($services{'dbus'} ? 'true' : 'false')
    . '}';

my @addon_json;

foreach my $addon (sort keys %addons) {
    push @addon_json,
        json_string($addon)
        . ':{'
        . '"running":' . ($addons{$addon}{'running'} ? 'true' : 'false')
        . '}';
}

push @json, '"addons":{' . join(',', @addon_json) . '}' if @addon_json;

push @json, '"traffic":{'
    . '"rx_bytes":' . (defined $red_rx_bytes ? $red_rx_bytes : 'null')
    . ',"tx_bytes":' . (defined $red_tx_bytes ? $red_tx_bytes : 'null')
    . '}';

my @connection;
push @connection, '"state":' . json_string($state);

if (defined $connected_since) {
    push @connection, '"connected_since":' . $connected_since;
    push @connection, '"duration":' . int($duration);
    push @connection, '"duration_text":' . json_string(&General::format_time(int($duration)));
} else {
    push @connection, '"connected_since":null';
    push @connection, '"duration":0';
    push @connection, '"duration_text":""';
}

push @connection, '"profile":' . json_string($profile);
push @connection, '"external_ip":' . json_string($external_ip);
push @connection, '"external_hostname":' . json_string($external_hostname);

push @json, '"connection":{' . join(',', @connection) . '}';

print '{' . join(',', @json) . "}\n";

exit 0;
