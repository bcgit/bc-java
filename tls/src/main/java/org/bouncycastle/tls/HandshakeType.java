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

    /*
     * RFC 8879 
     */
    public static final short compressed_certificate = 25;

    public static String getName(short handshakeType)
    {
        switch (handshakeType)
        {
        case hello_request:
            return "hello_request";
        case client_hello:
            return "client_hello";
        case server_hello:
            return "server_hello";
        case certificate:
            return "certificate";
        case server_key_exchange:
            return "server_key_exchange";
        case certificate_request:
            return "certificate_request";
        case server_hello_done:
            return "server_hello_done";
        case certificate_verify:
            return "certificate_verify";
        case client_key_exchange:
            return "client_key_exchange";
        case finished:
            return "finished";
        case certificate_url:
            return "certificate_url";
        case certificate_status:
            return "certificate_status";
        case hello_verify_request:
            return "hello_verify_request";
        case supplemental_data:
            return "supplemental_data";
        case new_session_ticket:
            return "new_session_ticket";
        case end_of_early_data:
            return "end_of_early_data";
        case hello_retry_request:
            return "hello_retry_request";
        case encrypted_extensions:
            return "encrypted_extensions";
        case key_update:
            return "key_update";
        case message_hash:
            return "message_hash";
        case compressed_certificate:
            return "compressed_certificate";
        default:
            return "UNKNOWN";
        }
    }

    public static String getText(short handshakeType)
    {
        return getName(handshakeType) + "(" + handshakeType + ")";
    }

    public static boolean isRecognized(short handshakeType)
    {
        switch (handshakeType)
        {
        case hello_request:
        case client_hello:
        case server_hello:
        case certificate:
        case server_key_exchange:
        case certificate_request:
        case server_hello_done:
        case certificate_verify:
        case client_key_exchange:
        case finished:
        case certificate_url:
        case certificate_status:
        case hello_verify_request:
        case supplemental_data:
        case new_session_ticket:
        case end_of_early_data:
        case hello_retry_request:
        case encrypted_extensions:
        case key_update:
        case message_hash:
        case compressed_certificate:
            return true;
        default:
            return false;
        }
    }
}
