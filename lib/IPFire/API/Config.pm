
package IPFire::API::Config;

use strict;
use warnings;

use Exporter 'import';

our @EXPORT_OK = qw(get_config);

sub get_config {
    return {
        host      => $ENV{IPFIRE_API_HOST}      || '127.0.0.1',
        port      => $ENV{IPFIRE_API_PORT}      // 8444,
        cert_file => $ENV{IPFIRE_API_CERT_FILE} // '/etc/httpd/server.crt',
        key_file  => $ENV{IPFIRE_API_KEY_FILE}  // '/etc/httpd/server.key',
    };
}

1;
