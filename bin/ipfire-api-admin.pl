#!/usr/bin/env perl

use strict;
use warnings;

use Fcntl qw(:flock O_NOFOLLOW O_CREAT O_RDWR S_ISDIR S_ISSOCK);
use File::Basename qw(dirname);
use FindBin;
use IO::Socket::UNIX;
use Socket qw(SOCK_STREAM);
use lib "$FindBin::Bin/../lib";

use IPFire::API::AdminService;
use IPFire::API::Config qw(get_config);

my ($web_user) = @ARGV;
my (undef, undef, $web_uid, $web_gid) = defined($web_user) ? getpwnam($web_user) : ();
die "Usage: perl bin/ipfire-api-admin.pl <web-server-user>\n" unless @ARGV == 1 && defined $web_uid;
my $config = get_config();
my $socket_path = $config->{admin_socket};
my $directory = dirname($socket_path);
umask 0022;
mkdir $directory, 0755 unless -d $directory;
umask 0077;
my @directory = lstat $directory;
die "Admin socket directory must be owned by this user and permit web-server traversal\n"
    unless @directory && S_ISDIR($directory[2]) && $directory[4] == $>
    && ($directory[2] & 0001) && !($directory[2] & 0022);

sysopen my $lock, "$directory/admin.lock", O_RDWR | O_CREAT | O_NOFOLLOW, 0600
    or die "Cannot open admin lock: $!\n";
flock($lock, LOCK_EX | LOCK_NB) or die "Admin service is already running\n";
my @old = lstat $socket_path;
if (@old) {
    die "Invalid existing admin socket\n" unless S_ISSOCK($old[2]) && $old[4] == $>;
    unlink $socket_path or die "Cannot remove old admin socket: $!\n";
}

my $server = IO::Socket::UNIX->new(Type => SOCK_STREAM, Local => $socket_path, Listen => 8)
    or die "Cannot bind admin socket: $!\n";
END { unlink $socket_path if defined $server; }
chown(-1, $web_gid, $socket_path) or die "Cannot set admin socket group: $!\n";
chmod(0660, $socket_path) or die "Cannot set admin socket permissions: $!\n";

my $admin = IPFire::API::AdminService->new($config, $web_uid);
local $SIG{INT} = local $SIG{TERM} = sub { exit 0 };
while (my $peer = $server->accept()) {
    $admin->serve_peer($peer);
}
die "Cannot accept an admin connection: $!\n";
