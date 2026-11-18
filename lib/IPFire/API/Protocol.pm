package IPFire::API::Protocol;

use strict;
use warnings;

use Exporter 'import';
use JSON::PP;

use IPFire::API::System qw(system_info);

our @EXPORT_OK = qw(handle_request);

my $json = JSON::PP->new->utf8->allow_nonref->max_depth(16);
my %methods = (
    'system.ping' => sub { return { pong => JSON::PP::true } },
    'system.info' => \&system_info,
);

sub handle_request {
    my ($message) = @_;

    my $request = eval { $json->decode($message) };
    return _error(undef, 'invalid_json', 'Invalid JSON') if $@;

    return _error(undef, 'invalid_request', 'Request must be an object')
        unless ref $request eq 'HASH';

    my $id = $request->{id};
    return _error(undef, 'invalid_request', 'id must be a string of 1 to 128 characters')
        unless _is_string($id) && length($id) >= 1 && length($id) <= 128;

    my $method = $request->{method};
    return _error($id, 'invalid_request', 'method must be a nonempty string')
        unless _is_string($method) && length($method);

    my $handler = $methods{$method};
    return _error($id, 'method_not_found', 'Unknown method') unless $handler;
    return _error($id, 'invalid_params', "$method takes no parameters")
        if exists $request->{params}
        && (ref $request->{params} ne 'HASH' || keys %{ $request->{params} });

    return $json->encode({ id => $id, result => $handler->() });
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
