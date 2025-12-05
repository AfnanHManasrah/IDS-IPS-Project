module DNS_TUNNEL;
export {
    redef enum Notice::Type += { high_entropy_detection };
}
event dns_request( c: connection, msg: dns_msg, query: string ) {
    if ( |query| > 20 ){
       if ( query =~ /[A-Za-z0-9+\/]{20,}\./ ) {
          NOTICE([$note=high_entropy_detection, $msg=fmt(" High Entropy DNS Detected: %s", query), $conn=c]);
       }
    }
}
