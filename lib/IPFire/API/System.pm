package IPFire::API::System;

use strict;
use warnings;

use Exporter 'import';
use Errno qw(ENOENT);
use Sys::Hostname qw(hostname);

our @EXPORT_OK = qw(system_info red_status);

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

sub red_status {
    my $directory = $ENV{IPFIRE_API_RED_DIRECTORY} // '/var/ipfire/red';
    my @active = stat "$directory/active";
    return { status => 'connected', connected_since => $active[9] } if @active;
    return { status => 'disconnected', connected_since => undef }
        if $! == ENOENT && -d $directory;
    return { status => 'unknown', connected_since => undef };
}

1;
