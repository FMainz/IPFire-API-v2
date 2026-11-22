package IPFire::API::AdminPage;

use strict;
use warnings;

use IO::Socket::UNIX;
use Socket qw(SOCK_STREAM);

use IPFire::API::AdminProtocol qw(read_message write_message);
use IPFire::API::Config qw(get_config);

use constant PAGE => '/cgi-bin/api.cgi?view=admin';
use constant CSRF_COOKIE => '__Host-ipfire-api-csrf';

my %action_messages = (
    add => 'Client created. Copy the token now.',
    revoke => 'Client deleted. Its token is no longer valid.',
    save_network_zones => 'Network settings saved. The running API daemon applies them automatically.',
    start_daemon => 'API daemon started.',
    stop_daemon => 'API daemon stopped.',
    enable_daemon_autostart => 'API daemon autostart enabled.',
    disable_daemon_autostart => 'API daemon autostart disabled.',
);

sub run {
    my $method = $ENV{REQUEST_METHOD} // '';
    return _plain_error('403 Forbidden', 'Sign in to the IPFire WebGUI over HTTPS.')
        unless length($ENV{REMOTE_USER} // '') && ($ENV{HTTPS} // '') eq 'on';

    my $webgui_loaded = eval {
        require '/var/ipfire/general-functions.pl';
        require '/var/ipfire/header.pl';
        1;
    };
    if (!$webgui_loaded) {
        warn "Cannot load the IPFire WebGUI\n";
        return _plain_error('500 Internal Server Error', 'Could not load the IPFire WebGUI.');
    }

    return _error('405 Method Not Allowed', 'This page accepts GET and POST.')
        unless $method eq 'GET' || $method eq 'POST';

    my @cookies = ($ENV{HTTP_COOKIE} // '') =~ /(?:\A|;\s*)__Host-ipfire-api-csrf=([a-f0-9]{64})(?=;|\z)/g;
    my $csrf = @cookies == 1 ? $cookies[0] : undef;
    my ($message, $token, $status);
    if ($method eq 'POST') {
        my $form = _read_form();
        return _error('400 Bad Request', 'Invalid form submission.') unless $form;
        return _error('403 Forbidden', 'Reload the page and submit the form again.')
            unless defined $csrf && ($form->{csrf} // '') eq $csrf;
        my $action = $form->{action} // '';
        return _error('400 Bad Request', 'Unknown action.')
            unless $action =~ /\A(?:add|revoke|save|start_daemon|stop_daemon|save_autostart)\z/;

        my $request = { action => $action };
        if ($action eq 'save') {
            $request->{action} = 'save_network_zones';
            $request->{network_zones} = [grep { exists $form->{"zone_$_"} } qw(green orange blue)];
        } elsif ($action eq 'save_autostart') {
            $request->{action} = exists $form->{autostart} ? 'enable_daemon_autostart' : 'disable_daemon_autostart';
        } elsif ($action eq 'add' || $action eq 'revoke') {
            $request->{name} = $form->{name};
        }
        my $result = _request($request);
        if ($result->{error}) {
            $message = $result->{error};
            $status = $result->{unavailable} ? '503 Service Unavailable' : '400 Bad Request';
        } else {
            $token = $result->{token};
            $message = $action_messages{$request->{action}};
        }
    }

    my $set_cookie;
    if (!defined $csrf) {
        open my $random, '<:raw', '/dev/urandom' or die "Cannot open random source\n";
        read($random, my $bytes, 32) == 32 or die "Cannot generate form token\n";
        $csrf = unpack('H*', $bytes);
        $set_cookie = CSRF_COOKIE . "=$csrf; Path=/; Secure; HttpOnly; SameSite=Strict";
    }

    my $state = _request({ action => 'list' });
    $status //= '503 Service Unavailable' if $state->{error};
    _headers($status, $set_cookie, $method eq 'POST' && !defined($token));
    Header::openpage('IPFire API v2', 1, '');
    _content($state, $csrf, $message, $token);
    Header::closepage();
}

sub _read_form {
    my $length = $ENV{CONTENT_LENGTH} // '';
    return unless $length =~ /\A[0-9]{1,4}\z/ && $length > 0 && $length <= 8192
        && ($ENV{CONTENT_TYPE} // '') eq 'application/x-www-form-urlencoded';

    my $body = '';
    while (length($body) < $length) {
        read(STDIN, my $part, $length - length($body)) or return;
        $body .= $part;
    }

    my %form;
    for my $field (split /&/, $body) {
        my ($key, $value) = split /=/, $field, 2;
        return unless defined $value && !exists $form{$key}
            && $key =~ /\A(?:action|csrf|name|autostart|zone_(?:green|orange|blue))\z/
            && $value !~ /%(?![0-9a-f]{2})/i;
        $value =~ tr/+/ /;
        $value =~ s/%([a-f0-9]{2})/chr hex $1/egi;
        return if $value =~ /[^\x20-\x7e]/;
        return if ($key eq 'autostart' || $key =~ /\Azone_/) && $value ne '1';
        $form{$key} = $value;
    }
    return \%form;
}

sub _request {
    my ($request) = @_;
    local $SIG{PIPE} = 'IGNORE';
    local $SIG{ALRM} = sub { die "Admin service timed out\n" };
    my $reply = eval {
        alarm 11;
        my $connection = IO::Socket::UNIX->new(Type => SOCK_STREAM, Peer => get_config()->{admin_socket})
            or die "Admin service is unavailable\n";
        write_message($connection, $request);
        read_message($connection);
    };
    alarm 0;
    return $reply // { error => 'The local API administration service is unavailable.', unavailable => 1 };
}

sub _escape {
    my ($value) = @_;
    $value //= '';
    $value =~ s/&/&amp;/g;
    $value =~ s/</&lt;/g;
    $value =~ s/>/&gt;/g;
    $value =~ s/"/&quot;/g;
    $value =~ s/'/&#39;/g;
    return $value;
}

sub _form {
    my ($action, $csrf, $id) = @_;
    my $form_id = defined $id ? ' id="' . _escape($id) . '"' : '';
    return '<form method="post" action="' . PAGE . '&amp;submit=1"' . $form_id . '>'
        . '<input type="hidden" name="csrf" value="' . $csrf . '">'
        . '<input type="hidden" name="action" value="' . $action . '">';
}

sub _content {
    my ($state, $csrf, $message, $token) = @_;

    if (defined($message) || $state->{error}) {
        Header::openbox('100%', 'left', 'Status');
        print '<p role="status">', _escape($message), '</p>' if defined $message;
        print '<p><label for="token">Client token</label> ',
            '<input id="token" readonly value="', _escape($token), '" size="75"></p>',
            '<p><a href="', PAGE, '">Return to administration</a></p>' if defined $token;
        print '<p>', _escape($state->{error}), '</p>' if $state->{error};
        Header::closebox();
        return if $state->{error};
    }

    _daemon_controls($state->{daemon}, $csrf);

    Header::openbox('100%', 'left', 'Client access');
    if (@{$state->{clients}}) {
        print '<table class="tbl"><thead><tr><th>Client</th><th>Role</th><th>Action</th></tr></thead><tbody>';
        for my $name (@{$state->{clients}}) {
            my $safe_name = _escape($name);
            print '<tr>', qq(<td style="text-align:center">$safe_name</td>),
                '<td style="text-align:center">Monitoring</td>',
                '<td style="text-align:center">', _form('revoke', $csrf),
                qq(<input type="hidden" name="name" value="$safe_name">),
                qq(<button aria-label="Delete client $safe_name">Delete client</button></form></td></tr>);
        }
        print '</tbody></table>';
    } else {
        print '<p>No clients configured.</p>';
    }
    print _form('add', $csrf),
        '<div', (@{$state->{clients}} ? ' style="padding-top:12px"' : ''),
        '><label for="name">New client name</label> ',
        '<input id="name" name="name" required maxlength="64" pattern="[a-z0-9][a-z0-9_\-]*"> ',
        '<button>Create token</button></div></form>';
    Header::closebox();

    my @presets = grep { defined $_->{address} && defined $_->{network} }
        @{ $state->{network_presets} // [] };
    Header::openbox('100%', 'left', 'Network access');
    if (!@presets) {
        print '<p>No configured IPFire zones are available. Check the IPFire network configuration and restart the API administration service after an update.</p>';
        Header::closebox();
        return;
    }
    print _form('save', $csrf);
    _network_options($state->{settings}, \@presets);
    print '<div style="padding-top:12px"><button>Save network settings</button></div></form>';
    Header::closebox();
}

sub _daemon_controls {
    my ($state, $csrf) = @_;

    Header::openbox('100%', 'left', 'API daemon');
    if ($state) {
        my ($status, $action, $label) = $state->{running}
            ? ('Running', 'stop_daemon', 'Stop') : ('Stopped', 'start_daemon', 'Start');
        print '<div style="display:inline-grid;grid-template-columns:auto auto;',
            'align-items:center;justify-items:start;gap:.5em .75em">',
            "<span>Status: $status</span>", _form($action, $csrf),
            "<button type=\"submit\">$label</button></form>",
            '<label><input type="checkbox" name="autostart" value="1" form="api-v2-autostart"',
            ($state->{autostart} ? ' checked' : ''),
            '> Start at system boot</label>',
            _form('save_autostart', $csrf, 'api-v2-autostart'),
            '<button type="submit">Save</button></form></div>';
    } else {
        print '<p>Service controls are unavailable.</p>';
    }
    Header::closebox();
}

sub _network_options {
    my ($settings, $presets) = @_;

    my %selected = map { $_ => 1 } @{ $settings->{network_zones} // [] };
    if (!$settings->{network_zones}) {
        my %legacy_networks = map { s/\A\s+|\s+\z//gr => 1 }
            split /,/, $settings->{allowed_networks} // '';
        %selected = map { $_->{id} => 1 } grep { $legacy_networks{$_->{network}} } @$presets;
        $selected{green} = 1 unless %selected;
    }

    print '<fieldset><legend>Allowed networks</legend>';
    for my $preset (@$presets) {
        my $id = $preset->{id};
        my $checked = $selected{$id} ? ' checked' : '';
        my $label = uc($id) . " ($preset->{network})";
        print '<div><label><input type="checkbox" name="zone_', _escape($id), '" value="1"',
            $checked, '> ', _escape($label), '</label> &mdash; Listen address: ',
            _escape($preset->{address}), '</div>';
    }
    print '</fieldset>';

    if (exists $settings->{host}) {
        print '<p>Saving replaces the previous listen address and allowed networks with the selected zones.</p>';
    }
}

sub _error {
    my ($status, $message) = @_;
    _headers($status, undef, ($ENV{REQUEST_METHOD} // '') eq 'POST');
    Header::openpage('IPFire API v2', 1, '');
    Header::openbox('100%', 'left', 'Status');
    print '<p>', _escape($message), '</p>';
    Header::closebox();
    Header::closepage();
}

sub _plain_error {
    my ($status, $message) = @_;
    print "Status: $status\r\nContent-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\n\r\n$message\n";
}

sub _headers {
    my ($status, $cookie, $return_to_page) = @_;
    print "Status: $status\r\n" if defined $status;
    print "Set-Cookie: $cookie\r\n" if defined $cookie;
    print 'Refresh: 10; url=', PAGE, "\r\n" if $return_to_page;
    print "Content-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\n",
        "X-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n",
        "Content-Security-Policy: default-src 'none'; style-src 'self' 'unsafe-inline'; ",
        "script-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; ",
        "form-action 'self'; frame-ancestors 'none'; base-uri 'none'\r\n\r\n";
}

1;
