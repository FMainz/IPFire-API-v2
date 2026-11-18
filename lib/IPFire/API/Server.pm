
package IPFire::API::Server;

use strict;
use warnings;

use Errno qw(ECONNABORTED EINTR ETIMEDOUT);
use IO::Handle;
use IO::Socket::SSL qw($SSL_ERROR SSL_WANT_READ SSL_WANT_WRITE);
use Time::HiRes qw(clock_gettime CLOCK_MONOTONIC);

use IPFire::API::Config qw(get_config);
use IPFire::API::Protocol qw(handle_request);
use IPFire::API::WebSocket qw(handle_upgrade handle_frames);

use constant TLS_HANDSHAKE_TIMEOUT => 5;

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
        LocalAddr          => $config->{host},
        LocalPort          => $config->{port},
        Listen             => 10,
        ReuseAddr          => 1,
        SSL_server         => 1,
        SSL_startHandshake => 0,
        SSL_cert_file      => $config->{cert_file},
        SSL_key_file       => $config->{key_file},
    ) or die "TLS server error: "
           . IO::Socket::SSL::errstr() . "\n";

    $self->{socket} = $server;

    STDOUT->autoflush(1);
    print "IPFire API v2 listening on "
        . $server->sockhost() . ':' . $server->sockport() . "\n";

    local $SIG{PIPE} = 'IGNORE';
    while (1) {
        my $client = $server->accept();
        if (!$client) {
            next if $! == EINTR || $! == ECONNABORTED;
            die "TCP accept error: $!\n";
        }

        my $deadline = clock_gettime(CLOCK_MONOTONIC) + TLS_HANDSHAKE_TIMEOUT;
        if (!$server->accept_SSL($client, Timeout => TLS_HANDSHAKE_TIMEOUT)) {
            # IO::Socket::SSL can leave a WANT error set when its wait expires.
            my $timed_out = $! == ETIMEDOUT || (defined $SSL_ERROR
                && ($SSL_ERROR == SSL_WANT_READ || $SSL_ERROR == SSL_WANT_WRITE)
                && clock_gettime(CLOCK_MONOTONIC) >= $deadline);
            my $error = $timed_out ? 'timed out' : (IO::Socket::SSL::errstr() || "$!");
            warn "TLS handshake failed: $error\n";
            $client->close(SSL_no_shutdown => 1) if defined fileno($client);
            next;
        }

        my $handled = eval {
            my $buffer = handle_upgrade($client);
            handle_frames($client, $buffer, \&handle_request) if defined $buffer;
            1;
        };
        warn "WebSocket connection failed: $@" unless $handled;
        if (!$client->close() && defined fileno($client)) {
            $client->close(SSL_no_shutdown => 1);
        }
    }
}

1;
