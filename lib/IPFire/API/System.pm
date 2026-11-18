package IPFire::API::System;

use strict;
use warnings;

use Exporter 'import';
use Sys::Hostname qw(hostname);

our @EXPORT_OK = qw(system_info);

sub system_info {
    my $release = _first_line('/etc/system-release');
    my $uptime = _first_line('/proc/uptime');
    my $seconds;
    if (defined $uptime && $uptime =~ /\A([0-9]+)(?:\.[0-9]+)?(?:\s|\z)/) {
        $seconds = 0 + $1;
    }

    return {
        hostname       => hostname(),
        ipfire_release => $release,
        uptime_seconds => $seconds,
    };
}

sub _first_line {
    my ($path) = @_;

    open my $file, '<', $path or return;
    my $line = <$file>;
    return unless defined $line;
    $line =~ s/\s+\z//;
    return length($line) ? $line : undef;
}

1;
