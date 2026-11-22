package IPFire::API::Auth;

use strict;
use warnings;
use feature 'bitwise';

use Digest::SHA qw(sha256_hex);
use Errno qw(EEXIST);
use Fcntl qw(O_NOFOLLOW O_NONBLOCK O_RDONLY S_ISDIR S_ISREG);
use File::Temp;

my $client_name = qr/[a-z0-9][a-z0-9_-]{0,63}/;

sub new {
    my ($class, $directory) = @_;
    return bless { directory => $directory }, $class;
}

sub add_client {
    my ($self, $name) = @_;
    my $path = $self->_client_path($name) or die "Invalid client name\n";
    mkdir $self->{directory}, 0700 or $! == EEXIST
        or die "Cannot create client directory: $!\n";
    $self->_private_directory() or die "Client directory must be private and owned by this user\n";

    open my $random, '<:raw', '/dev/urandom' or die "Cannot open random source: $!\n";
    read($random, my $secret, 32) == 32 or die "Cannot generate client token\n";
    my $token = $name . '.' . unpack('H*', $secret);
    my $digest = sha256_hex($token);
    my $file = File::Temp->new(DIR => $self->{directory});
    print {$file} "monitoring $digest\n" or die "Cannot write client record: $!\n";
    close $file or die "Cannot close client record: $!\n";
    link($file->filename(), $path) or die "Cannot add client: $!\n";
    return $token;
}

sub list_clients {
    my ($self) = @_;
    return unless -e $self->{directory};
    $self->_private_directory() or die "Client directory must be private and owned by this user\n";
    opendir my $dir, $self->{directory} or die "Cannot open client directory: $!\n";
    my @names = sort grep { s/\.client\z// && $self->_client_digest($_) } readdir $dir;
    return @names;
}

sub revoke_client {
    my ($self, $name) = @_;
    my $path = $self->_client_path($name) or die "Invalid client name\n";
    $self->_private_directory() or die "Client directory must be private and owned by this user\n";
    unlink($path) or die "Cannot revoke client: $!\n";
}

sub authenticate {
    my ($self, $header) = @_;
    return unless defined $header && $header =~ /\A(?i:Bearer) ($client_name\.[0-9a-f]{64})\z/;
    my $token = $1;
    my ($name) = split /\./, $token, 2;
    my $identity = { name => $name, digest => sha256_hex($token) };
    return $identity if $self->role_for($identity);
    return;
}

sub role_for {
    my ($self, $identity) = @_;
    return unless $identity;

    my $digest = $self->_client_digest($identity->{name});
    return unless defined $digest && unpack('%32C*', $digest ^. $identity->{digest}) == 0;
    return 'monitoring';
}

sub _client_path {
    my ($self, $name) = @_;
    return unless defined $name && $name =~ /\A$client_name\z/;
    return "$self->{directory}/$name.client";
}

sub _private_directory {
    my ($self) = @_;
    my @info = lstat $self->{directory};
    return @info && S_ISDIR($info[2]) && $info[4] == $> && !($info[2] & 0077);
}

sub _client_digest {
    my ($self, $name) = @_;
    my $path = $self->_client_path($name);
    return unless defined $path && $self->_private_directory();
    sysopen my $file, $path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW or return;
    my @info = stat $file;
    return unless @info && S_ISREG($info[2]) && $info[4] == $> && !($info[2] & 0077);

    my $size = read($file, my $record, 128);
    return unless $size && $record =~ /\Amonitoring ([0-9a-f]{64})\n\z/;
    return $1;
}

1;
