#!/usr/bin/env perl

use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../lib";

use IPFire::API::Auth;
use IPFire::API::Config qw(get_config);

my ($command, $name) = @ARGV;
my $clients = IPFire::API::Auth->new(get_config()->{client_dir});
if (@ARGV == 2 && $command eq 'add') {
    print $clients->add_client($name), "\n";
} elsif (@ARGV == 1 && $command eq 'list') {
    print "$_\tmonitoring\n" for $clients->list_clients();
} elsif (@ARGV == 2 && $command eq 'revoke') {
    $clients->revoke_client($name);
} else {
    die "Usage: perl bin/ipfire-api-clients.pl add <name> | list | revoke <name>\n";
}
