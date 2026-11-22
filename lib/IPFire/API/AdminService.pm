package IPFire::API::AdminService;

use strict;
use warnings;

use Socket qw(SOL_SOCKET SO_PEERCRED);

use IPFire::API::AdminProtocol qw(read_message write_message);
use IPFire::API::Auth;
use IPFire::API::NetworkSettings qw(client_network_presets listeners_for_zones load_network_settings save_network_settings);

use constant INIT_SCRIPT => '/etc/rc.d/init.d/ipfire-api-v2';
my %daemon_actions = (
    start_daemon => 'daemon-start',
    stop_daemon => 'daemon-stop',
    enable_daemon_autostart => 'daemon-enable',
    disable_daemon_autostart => 'daemon-disable',
);

sub new {
    my ($class, $config, $web_uid) = @_;
    return bless {
        clients => IPFire::API::Auth->new($config->{client_dir}),
        settings_path => $config->{network_settings_file},
        ethernet_settings_path => $config->{ethernet_settings_file} // '/var/ipfire/ethernet/settings',
        web_uid => $web_uid,
    }, $class;
}

sub serve_peer {
    my ($self, $peer) = @_;

    my $credentials = getsockopt($peer, SOL_SOCKET, SO_PEERCRED);
    return unless defined $credentials && length($credentials) == 12;
    my (undef, $uid) = unpack('iII', $credentials);
    return unless $uid == $self->{web_uid};

    local $SIG{PIPE} = 'IGNORE';
    local $SIG{ALRM} = sub { die "Admin request timed out\n" };
    eval {
        alarm 3;
        my $request = read_message($peer);
        alarm 9;
        my $reply = eval { $self->_dispatch($request) };
        if (!$reply) {
            my $error = $@;
            my $known_error = $error =~ /\A(?:
                Invalid\ client\ name | Invalid\ network\ settings |
                The\ API\ daemon\ setting\ could\ not\ be\ changed\.\ Check\ the\ system\ log\. |
                IPFIRE_API_[A-Z_]+[^\n]* | Set\ IPFIRE_API_ALLOWED_NETWORKS[^\n]* |
                A\ selected\ network\ is\ unavailable\.\ Reload\ the\ page\ and\ try\ again\. |
                Select\ at\ least\ one\ client\ network\.
            )\n\z/x;
            $reply = { error => $known_error ? $error : 'The requested change could not be completed.' };
        }
        write_message($peer, $reply);
    };
    alarm 0;
}

sub _dispatch {
    my ($self, $request) = @_;
    my $clients = $self->{clients};
    my $settings_path = $self->{settings_path};
    my $action = $request->{action} // '';
    die "Invalid admin action\n" if ref $action;

    if ($action eq 'list') {
        return {
            clients => [$clients->list_clients()],
            settings => load_network_settings($settings_path),
            network_presets => client_network_presets($self->{ethernet_settings_path}),
            daemon => _daemon_state(),
        };
    }
    if (my $command = $daemon_actions{$action}) {
        die "The API daemon setting could not be changed. Check the system log.\n"
            unless defined _run_init($command);
        return { saved => 1 };
    }
    if ($action eq 'add') {
        return { token => $clients->add_client($request->{name}) };
    }
    if ($action eq 'revoke') {
        $clients->revoke_client($request->{name});
        return { saved => 1 };
    }
    if ($action eq 'save_network_zones') {
        die "Invalid network settings\n" if exists $request->{host} || exists $request->{allowed_networks};
        my $zones = $request->{network_zones};
        listeners_for_zones($zones, client_network_presets($self->{ethernet_settings_path}));
        save_network_settings($settings_path, { network_zones => $zones });
        return { saved => 1 };
    }
    die "Invalid admin action\n";
}

sub _daemon_state {
    my $state = _run_init('daemon-state') // '';
    my ($running, $autostart) = $state =~ /\A(running|stopped) (enabled|disabled)\n\z/;
    return unless defined $running;
    return { running => $running eq 'running' ? 1 : 0, autostart => $autostart eq 'enabled' ? 1 : 0 };
}

sub _run_init {
    my ($command) = @_;
    return unless -x INIT_SCRIPT;
    open my $child, '-|', INIT_SCRIPT, $command or return;
    my $output = do { local $/; <$child> } // '';
    return close($child) ? $output : undef;
}

1;
