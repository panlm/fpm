#!/usr/bin/perl -w
use strict;
use warnings;
use POSIX qw(strftime);
use Data::Dumper;

use Net::Pcap;
use NetPacket::Ethernet qw(:strip);
use NetPacket::IP qw(:strip);
use NetPacket::TCP;
use NetPacket::UDP;

my $err = '';
#my $dev = pcap_lookupdev(\$err);  # find a device

# open the device for live listening
my $filename = 'd.pcap';
my $pcap = pcap_open_offline($filename, \$err) or die "cannot open" ;

# loop over next 10 packets
#pcap_loop($pcap, 2, \&process_packet, "just for the demo");
pcap_loop($pcap, -1, \&process_pkt, ''); #|| die 'Unable to perform packet capture. :( ', $err;

# close the device
pcap_close($pcap);

sub process_pkt {
    my ($user_data, $header, $packet) = @_;
#    my $eth_obj = NetPacket::Ethernet->decode($packet);
#    print Dumper($packet);
#    print Dumper($eth_obj);
#    print("$eth_obj->{src_mac}:$eth_obj->{dest_mac} $eth_obj->{type}\n");

#    my $ip_obj = NetPacket::IP->decode($eth_obj->{data});
#    print("$ip_obj->{src_ip}:$ip_obj->{dest_ip} $ip_obj->{proto}\n");

#    my $tcp_obj = NetPacket::TCP->decode($ip_obj->{data});
#    print("$tcp_obj->{src_port}:$tcp_obj->{dest_port} $tcp_obj->{data}\n");

    my ($eth_obj, $ip_obj, $tcp_obj, $udp_obj) = undef;
    my ($pkt_src_mac, $pkt_dest_mac, $pkt_src_port, $pkt_dest_port) = undef;

    $eth_obj = NetPacket::Ethernet->decode($packet);
    if ($eth_obj->{type} == "2048") {
        $pkt_src_mac = $eth_obj->{src_mac};
        for ($pkt_src_mac) { s/(..)(..)(..)(..)(..)(..)/$1:$2:$3:$4:$5:$6/; }
        $pkt_dest_mac = $eth_obj->{dest_mac};
        for ($pkt_dest_mac) { s/(..)(..)(..)(..)(..)(..)/$1:$2:$3:$4:$5:$6/; }
        #$ip_obj = NetPacket::IP->decode(eth_strip($packet));
        $ip_obj = NetPacket::IP->decode($eth_obj->{data});
            if ($ip_obj->{proto} == "6") {
                #$tcp_obj = NetPacket::TCP->decode(ip_strip(eth_strip($packet)));
                $tcp_obj = NetPacket::TCP->decode($ip_obj->{data});
                $pkt_src_port = $tcp_obj->{src_port};
                $pkt_dest_port = $tcp_obj->{dest_port};
            } elsif ($ip_obj->{proto} == "17") {
                $udp_obj = NetPacket::UDP->decode($ip_obj->{data});
                $pkt_src_port = $udp_obj->{src_port};
                $pkt_dest_port = $udp_obj->{dest_port};
            }
        print strftime("%Y-%m-%d %H:%M:%S.", localtime($header->{tv_sec}));
        print("$header->{tv_usec} $pkt_src_mac->$pkt_dest_mac ".
              "$ip_obj->{src_ip}:$pkt_src_port->$ip_obj->{dest_ip}:$pkt_dest_port \n");
    } else {
        print("not an IP packet.\n");
    }
}
