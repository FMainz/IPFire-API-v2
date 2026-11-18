
package IPFire::API::Server;

use strict;
use warnings;

use IO::Socket::SSL;
use IO::Select;

use IPFire::API::Config qw(get_config);

sub new {
    my ($class) = @_;

    my $self = {
        config  => get_config(),
        socket  => undef,
        clients => {},
    };

    return bless $self, $class;
}

sub start {
    my ($self) = @_;

    my $config = $self->{config};

    my $server = IO::Socket::SSL->new(
        LocalAddr     => $config->{host},
        LocalPort     => $config->{port},
        Listen        => 10,
        ReuseAddr     => 1,
        SSL_server    => 1,
        SSL_cert_file => $config->{cert_file},
        SSL_key_file  => $config->{key_file},
    ) or die "TLS server error: "
           . IO::Socket::SSL::errstr() . "\n";

    $self->{socket} = $server;

    print "IPFire API v2 listening on "
        . "$config->{host}:$config->{port}\n";
}

1;
