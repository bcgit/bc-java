package org.bouncycastle.tls;

/**
 * Base interface for an object sending and receiving DTLS data.
 */
public interface DatagramTransport
    extends DatagramReceiver, DatagramSender, TlsCloseable
{
}
