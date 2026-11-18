
package IPFire::API::Config;

use strict;
use warnings;

use Exporter 'import';

our @EXPORT_OK = qw(get_config);

sub get_config {
    return {
        host      => '0.0.0.0',
        port      => 8444,
        cert_file => '/etc/ssl/certs/ipfire-api.pem',
        key_file  => '/etc/ssl/private/ipfire-api.key',
    };
}

1;
