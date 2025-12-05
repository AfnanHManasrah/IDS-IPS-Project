module DNS_TUNNEL;
export { 
    redef enum Notice::Type += {Long_TXT_Detection};
}
event dns_request(c: connection, msg: dns_msg, query: string){
    if ( |query| > 70 )
       NOTICE([$note=Long_TXT_Detection, $msg=fmt(Long TXT DNS Detected: %s", query), $conn=c]);
}

