module DNS_TUNNEL
export {
    redef enum Notice::Type +={ NXDOMAIN_Response };
}
event dns_request (c:connection, msg:dns_msg, query: string ) {
    if ( msg$rcode == 3) {
       NOTICE ([ $note= NXDOMAIN_Response, $msg=fmt("NXDOMAIN Response Detcted: %s", query), $conn=c]);
    }
}
