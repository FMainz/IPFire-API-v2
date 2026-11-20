package IPFire::API::Server;

use strict;
use warnings;

use Errno qw(EAGAIN ECONNABORTED EINTR EWOULDBLOCK);
use IO::Handle;
use IO::Select;
use IO::Socket::SSL;
use Time::HiRes qw(clock_gettime CLOCK_MONOTONIC);

use IPFire::API::Client;
use IPFire::API::Config qw(get_config);

use constant MAX_CLIENTS => 32;

sub new {
    my ($class) = @_;

    return bless { config => get_config() }, $class;
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
    ) or die "TLS server error: " . IO::Socket::SSL::errstr() . "\n";

    defined $server->blocking(0) or die "Cannot make the listener non-blocking: $!\n";
    STDOUT->autoflush(1);
    print "IPFire API v2 listening on " . $server->sockhost() . ':' . $server->sockport() . "\n";

    local $SIG{PIPE} = 'IGNORE';
    my %clients;
    my $listener_fd = fileno($server);
    while (1) {
        my $read = IO::Select->new($server);
        my $write = IO::Select->new();
        my %ready;
        my $deadline;
        my $now = clock_gettime(CLOCK_MONOTONIC);
        for my $fd (keys %clients) {
            my $client = $clients{$fd};
            if ($client->deadline() <= $now) {
                delete $clients{$fd};
                $client->close(1);
                next;
            }
            $deadline = $client->deadline() if !defined($deadline) || $client->deadline() < $deadline;
            if ($client->waits_for_write()) {
                $write->add($client->socket());
            } else {
                $read->add($client->socket());
                $ready{$fd} = 1 if $client->has_pending_input();
            }
        }

        my $timeout = defined($deadline) ? $deadline - clock_gettime(CLOCK_MONOTONIC) : undef;
        $timeout = 0 if %ready || (defined($timeout) && $timeout < 0);
        local $! = 0;
        my ($readable, $writable) = IO::Select->select($read, $write, undef, $timeout);
        die "Socket select error: $!\n" if !defined($readable) && $! && $! != EINTR;
        $ready{fileno($_)} = 1 for @{$readable // []}, @{$writable // []};

        if (delete $ready{$listener_fd}) {
            my $socket = $server->accept();
            if (!$socket) {
                die "TCP accept error: $!\n"
                    unless $! == EINTR || $! == ECONNABORTED || $! == EAGAIN || $! == EWOULDBLOCK;
            } elsif (keys(%clients) >= MAX_CLIENTS || !defined($socket->blocking(0))) {
                $socket->close(SSL_no_shutdown => 1);
            } else {
                $clients{fileno($socket)} = IPFire::API::Client->new($socket);
            }
        }

        for my $fd (keys %ready) {
            my $client = $clients{$fd};
            my $expired = $client->deadline() <= clock_gettime(CLOCK_MONOTONIC);
            my $alive = !$expired && eval { $client->advance() };
            warn "Client connection failed: $@" if !$expired && $@;
            next if $alive;

            delete $clients{$fd};
            $client->close($expired);
        }
    }
}

1;
