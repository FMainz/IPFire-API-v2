#!/usr/bin/env perl

use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../lib";

use IPFire::API::Server;

my $server = IPFire::API::Server->new();

$server->start();
