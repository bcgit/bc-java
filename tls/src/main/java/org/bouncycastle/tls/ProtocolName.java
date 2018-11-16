package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * RFC 7301 Represents a protocol name for use with ALPN.
 */
public final class ProtocolName
{
    public static final ProtocolName asRawBytes(byte[] bytes)
    {
        return new ProtocolName(Arrays.clone(bytes));
    }

    public static final ProtocolName asUtf8Encoding(String name)
    {
        return new ProtocolName(Strings.toUTF8ByteArray(name));
    }

    public static final ProtocolName HTTP_1_1 = asUtf8Encoding("http/1.1");
    public static final ProtocolName SPDY_1 = asUtf8Encoding("spdy/1");
    public static final ProtocolName SPDY_2 = asUtf8Encoding("spdy/2");
    public static final ProtocolName SPDY_3 = asUtf8Encoding("spdy/3");
    public static final ProtocolName STUN_TURN = asUtf8Encoding("stun.turn");
    public static final ProtocolName STUN_NAT_DISCOVERY = asUtf8Encoding("stun.nat-discovery");
    public static final ProtocolName HTTP_2_TLS = asUtf8Encoding("h2");
    public static final ProtocolName HTTP_2_TCP = asUtf8Encoding("h2c");
    public static final ProtocolName WEBRTC = asUtf8Encoding("webrtc");
    public static final ProtocolName WEBRTC_CONFIDENTIAL = asUtf8Encoding("c-webrtc");
    public static final ProtocolName FTP = asUtf8Encoding("ftp");
    public static final ProtocolName IMAP = asUtf8Encoding("imap");
    public static final ProtocolName POP3 = asUtf8Encoding("pop3");
    public static final ProtocolName MANAGESIEVE = asUtf8Encoding("managesieve");
    public static final ProtocolName COAP = asUtf8Encoding("coap");
    public static final ProtocolName XMPP_CLIENT = asUtf8Encoding("xmpp-client");
    public static final ProtocolName XMPP_SERVER = asUtf8Encoding("xmpp-server");

    private final byte[] bytes;

    private ProtocolName(byte[] bytes)
    {
        if (bytes == null)
        {
            throw new IllegalArgumentException("'bytes' cannot be null");
        }
        if (bytes.length < 1 || bytes.length > 255)
        {
            throw new IllegalArgumentException("'bytes' must have length from 1 to 255");
        }

        this.bytes = bytes;
    }

    public byte[] getBytes()
    {
        return Arrays.clone(bytes);
    }

    public String getUtf8Decoding()
    {
        return Strings.fromUTF8ByteArray(bytes);
    }

    /**
     * Encode this {@link ProtocolName} to an {@link OutputStream}.
     * 
     * @param output
     *            the {@link OutputStream} to encode to.
     * @throws IOException
     */
    public void encode(OutputStream output) throws IOException
    {
        TlsUtils.writeOpaque8(bytes, output);
    }

    /**
     * Parse a {@link ProtocolName} from an {@link InputStream}.
     * 
     * @param input
     *            the {@link InputStream} to parse from.
     * @return a {@link ProtocolName} object.
     * @throws IOException
     */
    public static ProtocolName parse(InputStream input) throws IOException
    {
        return new ProtocolName(TlsUtils.readOpaque8(input, 1));
    }

    public boolean equals(Object obj)
    {
        return obj instanceof ProtocolName && Arrays.areEqual(bytes, ((ProtocolName)obj).bytes);
    }

    public int hashCode()
    {
        return Arrays.hashCode(bytes);
    }
}
