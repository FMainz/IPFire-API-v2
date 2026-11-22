
package IPFire::API::Config;

use strict;
use warnings;

use Exporter 'import';

our @EXPORT_OK = qw(get_config);

sub get_config {
    return {
        host             => $ENV{IPFIRE_API_HOST},
        port             => $ENV{IPFIRE_API_PORT}       // 8444,
        cert_file        => $ENV{IPFIRE_API_CERT_FILE}  // '/etc/httpd/server.crt',
        key_file         => $ENV{IPFIRE_API_KEY_FILE}   // '/etc/httpd/server.key',
        client_dir       => $ENV{IPFIRE_API_CLIENT_DIR} // '/var/ipfire/api-v2-clients',
        allowed_networks => $ENV{IPFIRE_API_ALLOWED_NETWORKS},
        network_settings_file => $ENV{IPFIRE_API_NETWORK_SETTINGS_FILE} // '/var/ipfire/api-v2-network.json',
        ethernet_settings_file => $ENV{IPFIRE_API_ETHERNET_SETTINGS_FILE} // '/var/ipfire/ethernet/settings',
        admin_socket => $ENV{IPFIRE_API_ADMIN_SOCKET} // '/run/ipfire-api-v2-admin/control.sock',
    };
}

1;
