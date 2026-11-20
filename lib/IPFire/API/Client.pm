package IPFire::API::Client;

use strict;
use warnings;

use Errno qw(EINTR);
use IO::Socket::SSL qw($SSL_ERROR SSL_WANT_READ SSL_WANT_WRITE);
use Time::HiRes qw(clock_gettime CLOCK_MONOTONIC);

use IPFire::API::Protocol qw(handle_request);
use IPFire::API::WebSocket qw(consume_upgrade consume_frame);

use constant HANDSHAKE_TIMEOUT => 5;
use constant UPGRADE_TIMEOUT => 5;
use constant FRAME_TIMEOUT => 30;
use constant WRITE_TIMEOUT => 5;
use constant READ_SIZE => 8192;

sub new {
    my ($class, $socket) = @_;

    return bless {
        socket => $socket,
        operation => 'handshake',
        wait => 'read',
        deadline => clock_gettime(CLOCK_MONOTONIC) + HANDSHAKE_TIMEOUT,
        upgraded => 0,
        input => '',
        output => '',
        offset => 0,
        close_after_write => 0,
        message => {},
    }, $class;
}

sub deadline { return $_[0]->{deadline}; }
sub socket { return $_[0]->{socket}; }
sub waits_for_write { return $_[0]->{wait} eq 'write'; }

sub has_pending_input {
    my ($self) = @_;

    return $self->{operation} eq 'read' && !$self->waits_for_write()
        && $self->{socket}->pending();
}

sub close {
    my ($self, $expired) = @_;

    my $socket = $self->{socket};
    warn "TLS handshake failed: timed out\n" if $expired && $self->{operation} eq 'handshake';
    return unless defined fileno($socket);
    return if $self->{operation} ne 'handshake' && $socket->close();
    $socket->close(SSL_no_shutdown => 1) if defined fileno($socket);
}

sub advance {
    my ($self) = @_;

    my $socket = $self->{socket};
    if ($self->{operation} eq 'handshake') {
        # The handshake state belongs to this socket, independently of the listener.
        if (!$socket->accept_SSL()) {
            return 1 if $self->_retry();
            warn "TLS handshake failed: " . (IO::Socket::SSL::errstr() || "$!") . "\n";
            return;
        }
        $self->{operation} = $self->{wait} = 'read';
        $self->{deadline} = clock_gettime(CLOCK_MONOTONIC) + UPGRADE_TIMEOUT;
        return 1;
    }

    if ($self->{operation} eq 'write') {
        my $count = $socket->syswrite($self->{output}, length($self->{output}) - $self->{offset}, $self->{offset});
        return $self->_retry() unless defined $count;
        return unless $count;
        $self->{offset} += $count;
        $self->{wait} = 'write';
        return 1 if $self->{offset} < length($self->{output});
        return if $self->{close_after_write};

        $self->{output} = '';
        $self->{offset} = 0;
        $self->{operation} = $self->{wait} = 'read';
        $self->{deadline} = clock_gettime(CLOCK_MONOTONIC) + FRAME_TIMEOUT;
        $self->_handle_input();
        return 1;
    }

    my $count = $socket->sysread(my $chunk, READ_SIZE);
    return $self->_retry() unless defined $count;
    return unless $count;
    $self->{wait} = 'read';
    $self->{input} .= $chunk;
    $self->_handle_input();
    return 1;
}

sub _retry {
    my ($self) = @_;

    return 1 if $! == EINTR;
    return unless defined $SSL_ERROR;
    if ($SSL_ERROR == SSL_WANT_READ) {
        $self->{wait} = 'read';
    } elsif ($SSL_ERROR == SSL_WANT_WRITE) {
        $self->{wait} = 'write';
    } else {
        return;
    }
    return 1;
}

sub _handle_input {
    my ($self) = @_;

    my $input = \$self->{input};
    my ($reply, $close);
    if (!$self->{upgraded}) {
        ($reply, $close) = consume_upgrade($input);
        return unless defined $reply;
        $self->{upgraded} = !$close;
    } else {
        while (1) {
            ($reply, $close) = consume_frame($input, $self->{message}, \&handle_request);
            return unless defined $reply;
            if (length($reply)) {
                $self->{deadline} = clock_gettime(CLOCK_MONOTONIC) + WRITE_TIMEOUT;
                last;
            }
            $self->{deadline} = clock_gettime(CLOCK_MONOTONIC) + FRAME_TIMEOUT;
        }
    }

    $self->{output} = $reply;
    $self->{close_after_write} = $close;
    $self->{operation} = $self->{wait} = 'write';
}

1;
