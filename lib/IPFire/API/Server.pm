package IPFire::API::Server;

use strict;
use warnings;

use Errno qw(EAGAIN ECONNABORTED EINTR EWOULDBLOCK);
use IO::Handle;
use IO::Select;
use IO::Socket::SSL;
use Time::HiRes qw(clock_gettime CLOCK_MONOTONIC);

use IPFire::API::Auth;
use IPFire::API::Client;
use IPFire::API::Config qw(get_config);
use IPFire::API::NetworkPolicy;
use IPFire::API::NetworkSettings qw(client_network_presets listeners_for_zones load_network_settings);
use IPFire::API::RequestLimit;

use constant MAX_CLIENTS => 32;

sub new {
    my ($class) = @_;

    return bless { config => get_config() }, $class;
}

sub _configured_endpoints {
    my ($config) = @_;
    my $settings = load_network_settings($config->{network_settings_file});
    return $settings->{network_zones} && !defined($config->{host}) && !defined($config->{allowed_networks})
        ? listeners_for_zones($settings->{network_zones}, client_network_presets($config->{ethernet_settings_file}))
        : [{
            host => $config->{host} // $settings->{host} // '127.0.0.1',
            allowed_networks => $config->{allowed_networks} // $settings->{allowed_networks},
        }];
}

sub _endpoint_key {
    my ($endpoints) = @_;
    return join "\0", map { ($_->{host}, $_->{allowed_networks} // '') } @$endpoints;
}

sub _open_listeners {
    my ($config, $endpoints, $current) = @_;
    my %sockets = map { $_->{host} => $_->{socket} } @$current;
    my $port = @$current ? $current->[0]{socket}->sockport() : $config->{port};
    my @listeners;
    for my $endpoint (@$endpoints) {
        my $host = $endpoint->{host};
        my $policy = IPFire::API::NetworkPolicy->new($host, $endpoint->{allowed_networks});
        my $server = $sockets{$host};
        if (!$server) {
            $server = IO::Socket::SSL->new(
                LocalAddr          => $host,
                LocalPort          => $port,
                Listen             => 10,
                ReuseAddr          => 1,
                SSL_server         => 1,
                SSL_startHandshake => 0,
                SSL_version        => 'SSLv23:!SSLv2:!SSLv3:!TLSv1:!TLSv1_1',
                SSL_cert_file      => $config->{cert_file},
                SSL_key_file       => $config->{key_file},
            ) or die "TLS server error on $host: " . IO::Socket::SSL::errstr() . "\n";
            defined $server->blocking(0) or die "Cannot make the listener non-blocking: $!\n";
            $port ||= $server->sockport();
        }
        push @listeners, { host => $host, socket => $server, policy => $policy };
    }
    return \@listeners;
}

sub _announce_listeners {
    my ($listeners) = @_;
    for my $listener (@$listeners) {
        my $server = $listener->{socket};
        print "IPFire API v2 listening on " . $server->sockhost() . ':' . $server->sockport() . "\n";
    }
}

sub start {
    my ($self) = @_;

    my $config = $self->{config};
    my $endpoints = _configured_endpoints($config);
    my $endpoint_key = _endpoint_key($endpoints);
    my $follow_settings = !defined($config->{host}) && !defined($config->{allowed_networks});
    pipe(my $shutdown_reader, my $shutdown_writer) or die "Cannot create shutdown pipe: $!\n";
    defined $shutdown_writer->blocking(0) or die "Cannot make the shutdown pipe non-blocking: $!\n";
    my $stopping = 0;
    my $request_shutdown = sub {
        return if $stopping;
        $stopping = 1;
        local $!;
        # Wake select even if the signal arrived just before the call.
        while (!defined syswrite($shutdown_writer, "\n")) {
            last unless $! == EINTR;
        }
    };
    local $SIG{INT} = $request_shutdown;
    local $SIG{TERM} = $request_shutdown;
    local $SIG{PIPE} = 'IGNORE';

    my $auth = IPFire::API::Auth->new($config->{client_dir});
    my $request_limit = IPFire::API::RequestLimit->new();
    my $listeners = _open_listeners($config, $endpoints, []);
    STDOUT->autoflush(1);
    _announce_listeners($listeners);

    my %clients;
    my $shutdown_fd = fileno($shutdown_reader);
    my $next_reload = $follow_settings ? clock_gettime(CLOCK_MONOTONIC) + 1 : undef;
    my $reload_error = '';
    while (!$stopping) {
        my $now = clock_gettime(CLOCK_MONOTONIC);
        if (defined($next_reload) && $now >= $next_reload) {
            my $replacement;
            my $new_key;
            my $ok = eval {
                my $new_endpoints = _configured_endpoints($config);
                $new_key = _endpoint_key($new_endpoints);
                $replacement = _open_listeners($config, $new_endpoints, $listeners)
                    if $new_key ne $endpoint_key;
                1;
            };
            my $error = $ok ? '' : $@;
            warn "Cannot apply API network settings: $error" if length($error) && $error ne $reload_error;
            $reload_error = $error;
            if ($replacement) {
                my %retained = map { $_->{host} => 1 } @$replacement;
                for my $listener (@$listeners) {
                    $listener->{socket}->close() unless $retained{$listener->{host}};
                }
                $_->close() for values %clients;
                %clients = ();
                $listeners = $replacement;
                $endpoint_key = $new_key;
                print "IPFire API v2 network settings applied\n";
                _announce_listeners($listeners);
            }
            $next_reload = clock_gettime(CLOCK_MONOTONIC) + 1;
        }

        my $read = IO::Select->new($shutdown_reader, map { $_->{socket} } @$listeners);
        my $write = IO::Select->new();
        my %ready;
        my $deadline = $next_reload;
        for my $fd (keys %clients) {
            my $client = $clients{$fd};
            my $client_deadline = $client->deadline();
            if (defined($client_deadline) && $client_deadline <= $now) {
                delete $clients{$fd};
                $client->close(1);
                next;
            }
            my $event_deadline = $client->event_deadline();
            if (defined($event_deadline) && $event_deadline <= $now && !$client->has_pending_input()) {
                $client->queue_event($now);
                $event_deadline = $client->event_deadline();
            }
            if (defined($event_deadline) && (!defined($deadline) || $event_deadline < $deadline)) {
                $deadline = $event_deadline;
            }
            $client_deadline = $client->deadline();
            if (defined($client_deadline) && (!defined($deadline) || $client_deadline < $deadline)) {
                $deadline = $client_deadline;
            }
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
        last if $stopping || $ready{$shutdown_fd};

        for my $listener (@$listeners) {
            my $server = $listener->{socket};
            next unless delete $ready{fileno($server)};
            my $socket = $server->accept();
            if (!$socket) {
                die "TCP accept error: $!\n"
                    unless $! == EINTR || $! == ECONNABORTED || $! == EAGAIN || $! == EWOULDBLOCK;
            } elsif (keys(%clients) >= MAX_CLIENTS
                || !$listener->{policy}->allows_peer(getpeername($socket))
                || !defined($socket->blocking(0))) {
                $socket->close(SSL_no_shutdown => 1);
            } else {
                $clients{fileno($socket)} = IPFire::API::Client->new($socket, $auth, $request_limit);
            }
        }

        for my $fd (keys %ready) {
            last if $stopping;
            my $client = $clients{$fd};
            my $client_deadline = $client->deadline();
            my $expired = defined($client_deadline) && $client_deadline <= clock_gettime(CLOCK_MONOTONIC);
            my $alive;
            unless ($expired) {
                my $handled = eval {
                    $alive = $client->advance();
                    1;
                };
                warn "Unexpected error while handling a client connection\n" unless $handled;
            }
            next if $alive;

            delete $clients{$fd};
            $client->close($expired);
        }
    }

    $_->{socket}->close() for @$listeners;
    $_->close() for values %clients;
    print "IPFire API v2 stopped\n";
}

1;
