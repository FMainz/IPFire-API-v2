use strict;
use warnings;

use Test::More;

use IPFire::API::AdminPage;
use IPFire::API::AdminService;

sub parse_form {
    my ($body) = @_;
    local $ENV{CONTENT_TYPE} = 'application/x-www-form-urlencoded';
    local $ENV{CONTENT_LENGTH} = length($body);
    local *STDIN;
    open STDIN, '<', \$body or die "Cannot open test form: $!";
    return IPFire::API::AdminPage::_read_form();
}

is_deeply parse_form('action=save&zone_green=1&zone_orange=1'),
    { action => 'save', zone_green => '1', zone_orange => '1' }, 'selected zones are accepted';
is_deeply parse_form('action=save&zone_green=1'),
    { action => 'save', zone_green => '1' }, 'an unchecked zone can be omitted';
is scalar parse_form('action=save&zone_green=1&zone_orange=0'),
    undef, 'an unexpected checkbox value rejects the entire form';
is scalar parse_form('action=save&zone_green=1&zone_green=1'),
    undef, 'a duplicate checkbox rejects the entire form';

is_deeply parse_form('action=save_autostart&autostart=1'),
    { action => 'save_autostart', autostart => '1' }, 'autostart may be selected';
is_deeply parse_form('action=save_autostart'),
    { action => 'save_autostart' }, 'autostart may be unchecked';
is scalar parse_form('action=save_autostart&autostart=0'),
    undef, 'an invalid autostart value rejects the submission';

subtest 'admin service dispatches only explicit daemon commands' => sub {
    no warnings 'redefine';
    my @commands;
    my $state = "running disabled\n";
    local *IPFire::API::AdminService::_run_init = sub {
        push @commands, $_[0];
        return $_[0] eq 'daemon-state' ? $state : '';
    };
    my $service = IPFire::API::AdminService->new({}, $>);
    is_deeply IPFire::API::AdminService::_daemon_state(), { running => 1, autostart => 0 },
        'running and autostart states are independent';
    $state = "unexpected\n";
    is scalar IPFire::API::AdminService::_daemon_state(), undef, 'invalid status is unavailable';
    for my $action (qw(start_daemon stop_daemon enable_daemon_autostart disable_daemon_autostart)) {
        is_deeply $service->_dispatch({ action => $action }), { saved => 1 }, "$action succeeds";
    }
    eval { $service->_dispatch({ action => 'restart' }); };
    like $@, qr/Invalid admin action/, 'the combined restart is unavailable over the admin socket';
    is_deeply \@commands, [qw(daemon-state daemon-state daemon-start daemon-stop daemon-enable daemon-disable)],
        'only the intended init commands are invoked';
};

subtest 'status pages return to the GET view after ten seconds' => sub {
    no warnings 'once', 'redefine';
    local $INC{'/var/ipfire/general-functions.pl'} = 1;
    local $INC{'/var/ipfire/header.pl'} = 1;
    local *Header::openpage = local *Header::closepage = sub {};
    local *Header::openbox = local *Header::closebox = sub {};
    local *IPFire::API::AdminPage::_request = sub {
        my ($request) = @_;
        return { clients => [] } if $request->{action} eq 'list';
        return { token => 'one-time-token' } if $request->{action} eq 'add';
        return { error => 'Start failed' } if $request->{action} eq 'start_daemon';
        return { saved => 1 };
    };

    my $csrf = 'a' x 64;
    local $ENV{REMOTE_USER} = 'admin';
    local $ENV{HTTPS} = 'on';
    local $ENV{HTTP_COOKIE} = "__Host-ipfire-api-csrf=$csrf";
    local $ENV{CONTENT_TYPE} = 'application/x-www-form-urlencoded';

    my $render = sub {
        my ($body) = @_;
        local $ENV{REQUEST_METHOD} = defined $body ? 'POST' : 'GET';
        $body //= '';
        local $ENV{CONTENT_LENGTH} = length($body);
        local *STDIN;
        local *STDOUT;
        my $output = '';
        open STDIN, '<', \$body or die "Cannot open test form: $!";
        open STDOUT, '>', \$output or die "Cannot capture test response: $!";
        IPFire::API::AdminPage::run();
        return $output;
    };

    my $refresh = qr{^Refresh: 10; url=/cgi-bin/api\.cgi\?view=admin\r$}m;
    like $render->("action=stop_daemon&csrf=$csrf"), $refresh, 'successful POST status refreshes to the page URL';
    like $render->("action=start_daemon&csrf=$csrf"), $refresh, 'failed POST status refreshes too';
    like $render->("action=unknown&csrf=$csrf"), $refresh, 'form validation errors also return to GET';
    my $get_page = $render->();
    unlike $get_page, qr/^Refresh:/m, 'GET has no automatic refresh';
    like $get_page, qr{method="post" action="/cgi-bin/api\.cgi\?view=admin&amp;submit=1"},
        'form submits to a different URL from the timed return';
    my $token_page = $render->("action=add&name=test&csrf=$csrf");
    unlike $token_page, qr/^Refresh:/m, 'new token remains visible';
    like $token_page, qr{href="/cgi-bin/api\.cgi\?view=admin">Return to administration}, 'token page links directly to GET';
};

done_testing;
