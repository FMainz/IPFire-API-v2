package IPFire::API::Protocol;

use strict;
use warnings;

use Exporter 'import';
use JSON::PP;

use IPFire::API::System qw(system_info red_status);

our @EXPORT_OK = qw(handle_request event_data encode_event);

my $json = JSON::PP->new->utf8->allow_nonref->max_depth(16);
my %events = (
    'system.info' => \&system_info,
    'red.status' => \&red_status,
);
my %methods = (
    'system.ping' => ['monitoring', sub { return { pong => JSON::PP::true } }],
    'system.info' => ['monitoring', \&system_info],
    'events.subscribe' => ['monitoring', sub { _set_subscription(@_, JSON::PP::true) }, 1],
    'events.unsubscribe' => ['monitoring', sub { _set_subscription(@_, JSON::PP::false) }, 1],
);

sub handle_request {
    my ($message, $role, $rate_limited, $set_subscription) = @_;

    my $request = eval { $json->decode($message) };
    return _error(undef, 'invalid_json', 'Invalid JSON') if $@;

    return _error(undef, 'invalid_request', 'Request must be an object')
        unless ref $request eq 'HASH';

    my $id = $request->{id};
    return _error(undef, 'invalid_request', 'id must be a string of 1 to 128 characters')
        unless _is_string($id) && length($id) >= 1 && length($id) <= 128;

    return _error($id, 'rate_limited', 'Too many requests. Retry later.') if $rate_limited;

    my $method = $request->{method};
    return _error($id, 'invalid_request', 'method must be a nonempty string')
        unless _is_string($method) && length($method);

    return _error($id, 'access_denied', 'Access denied') unless defined $role;
    my $entry = $methods{$method};
    return _error($id, 'method_not_found', 'Unknown method') unless $entry;
    my ($required_role, $handler, $takes_event) = @$entry;
    return _error($id, 'access_denied', 'Access denied') unless $role eq $required_role;
    my $params = $request->{params};
    if ($takes_event) {
        return _error($id, 'invalid_params', "$method requires a supported event parameter")
            unless ref($params) eq 'HASH' && keys(%$params) == 1
            && _is_string($params->{event}) && exists $events{$params->{event}};
    } elsif (exists $request->{params} && (ref($params) ne 'HASH' || keys %$params)) {
        return _error($id, 'invalid_params', "$method takes no parameters");
    }

    my $reply = eval {
        my $result = $takes_event ? $handler->($set_subscription, $params->{event}) : $handler->();
        $json->encode({ id => $id, result => $result });
    };
    return $reply if defined $reply;

    warn "API method $method failed\n";
    return _error($id, 'internal_error', 'Internal server error');
}

sub _set_subscription {
    my ($set_subscription, $event, $enabled) = @_;
    $set_subscription->($event, $enabled);
    return { event => $event, subscribed => $enabled };
}

sub event_data {
    return $events{$_[0]}->();
}

sub encode_event {
    my ($name, $data) = @_;
    return $json->encode({ event => $name, data => $data });
}

sub _is_string {
    my ($value) = @_;

    return defined($value) && !ref($value) && $json->encode($value) =~ /\A"/;
}

sub _error {
    my ($id, $code, $message) = @_;

    return $json->encode({ id => $id, error => { code => $code, message => $message } });
}

1;
