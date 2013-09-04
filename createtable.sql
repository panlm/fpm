BEGIN TRANSACTION;
create table packet (
tv_sec UNSIGNED BIG INT,
tv_usec UNSIGNED BIG INT,
eth_src_mac varchar(12),
eth_dest_mac varchar(12),
src_ip varchar(15),
dest_ip varchar(15),
ip_proto integer,
ip_length integer,
src_port integer,
dest_port integer
);
COMMIT;
