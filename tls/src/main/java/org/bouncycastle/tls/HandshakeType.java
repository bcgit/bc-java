package org.bouncycastle.tls;

public class HandshakeType
{
    /*
     * RFC 2246 7.4
     */
    public static final short hello_request = 0;
    public static final short client_hello = 1;
    public static final short server_hello = 2;
    public static final short certificate = 11;
    public static final short server_key_exchange = 12;
    public static final short certificate_request = 13;
    public static final short server_hello_done = 14;
    public static final short certificate_verify = 15;
    public static final short client_key_exchange = 16;
    public static final short finished = 20;

    /*
     * RFC 3546 2.4
     */
    public static final short certificate_url = 21;
    public static final short certificate_status = 22;

    /*
     * (DTLS) RFC 4347 4.3.2
     */
    public static final short hello_verify_request = 3;

    /*
     * RFC 4680
     */
    public static final short supplemental_data = 23;

    /*
     * RFC 8446
     */
    public static final short new_session_ticket = 4;
    public static final short end_of_early_data = 5;
    public static final short hello_retry_request = 6;
    public static final short encrypted_extensions = 8;
    public static final short key_update = 24;
    public static final short message_hash = 254;
}
