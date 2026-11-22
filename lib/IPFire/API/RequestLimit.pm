package IPFire::API::RequestLimit;

use strict;
use warnings;

use List::Util qw(min);
use Time::HiRes qw(clock_gettime CLOCK_MONOTONIC);

use constant BURST => 10;
use constant REFILL_PER_SECOND => 2;
use constant REFILL_TIME => BURST / REFILL_PER_SECOND;

sub new {
    my ($class) = @_;
    return bless { clients => {}, next_cleanup => 0 }, $class;
}

sub allow {
    my ($self, $client_digest) = @_;
    my $now = clock_gettime(CLOCK_MONOTONIC);
    my $clients = $self->{clients};

    if ($now >= $self->{next_cleanup}) {
        for my $digest (keys %$clients) {
            delete $clients->{$digest} if $now - $clients->{$digest}{updated} >= REFILL_TIME;
        }
        $self->{next_cleanup} = $now + REFILL_TIME;
    }

    my $bucket = $clients->{$client_digest} //= { tokens => BURST, updated => $now };
    my $available = min(BURST, $bucket->{tokens} + ($now - $bucket->{updated}) * REFILL_PER_SECOND);
    return 0 if $available < 1;

    $bucket->{tokens} = $available - 1;
    $bucket->{updated} = $now;
    return 1;
}

1;
