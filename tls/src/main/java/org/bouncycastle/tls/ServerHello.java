package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Hashtable;

import org.bouncycastle.util.Arrays;

public class ServerHello
{
    private static final byte[] HELLO_RETRY_REQUEST_MAGIC = {
        (byte)0xCF, (byte)0x21, (byte)0xAD, (byte)0x74, (byte)0xE5, (byte)0x9A, (byte)0x61, (byte)0x11,
        (byte)0xBE, (byte)0x1D, (byte)0x8C, (byte)0x02, (byte)0x1E, (byte)0x65, (byte)0xB8, (byte)0x91,
        (byte)0xC2, (byte)0xA2, (byte)0x11, (byte)0x16, (byte)0x7A, (byte)0xBB, (byte)0x8C, (byte)0x5E,
        (byte)0x07, (byte)0x9E, (byte)0x09, (byte)0xE2, (byte)0xC8, (byte)0xA8, (byte)0x33, (byte)0x9C
    };

    private final ProtocolVersion version;
    private final byte[] random;
    private final byte[] sessionID;
    private final int cipherSuite;
    private final Hashtable extensions;

    public ServerHello(byte[] sessionID, int cipherSuite, Hashtable extensions)
    {
        this(ProtocolVersion.TLSv12, Arrays.clone(HELLO_RETRY_REQUEST_MAGIC), sessionID, cipherSuite, extensions);
    }

    public ServerHello(ProtocolVersion version, byte[] random, byte[] sessionID, int cipherSuite, Hashtable extensions)
    {
        this.version = version;
        this.random = random;
        this.sessionID = sessionID;
        this.cipherSuite = cipherSuite;
        this.extensions = extensions;
    }

    public int getCipherSuite()
    {
        return cipherSuite;
    }

    public Hashtable getExtensions()
    {
        return extensions;
    }

    public byte[] getRandom()
    {
        return random;
    }

    public byte[] getSessionID()
    {
        return sessionID;
    }

    public ProtocolVersion getVersion()
    {
        return version;
    }

    public boolean isHelloRetryRequest()
    {
        return Arrays.areEqual(HELLO_RETRY_REQUEST_MAGIC, random);
    }

    /**
     * Encode this {@link ServerHello} to an {@link OutputStream}.
     * 
     * @param context
     *            the {@link TlsContext} of the current connection.
     * @param output
     *            the {@link OutputStream} to encode to.
     * @throws IOException
     */
    public void encode(TlsContext context, OutputStream output) throws IOException
    {
        TlsUtils.writeVersion(version, output);

        output.write(random);

        TlsUtils.writeOpaque8(sessionID, output);

        TlsUtils.writeUint16(cipherSuite, output);

        TlsUtils.writeUint8(CompressionMethod._null, output);

        TlsProtocol.writeExtensions(output, extensions);
    }

    /**
     * Parse a {@link ServerHello} from a {@link ByteArrayInputStream}.
     *
     * @param input
     *            the {@link ByteArrayInputStream} to parse from.
     * @return a {@link ServerHello} object.
     * @throws IOException
     */
    public static ServerHello parse(ByteArrayInputStream input)
        throws IOException
    {
        ProtocolVersion version = TlsUtils.readVersion(input);

        byte[] random = TlsUtils.readFully(32, input);

        byte[] sessionID = TlsUtils.readOpaque8(input, 0, 32);

        int cipherSuite = TlsUtils.readUint16(input);

        short compressionMethod = TlsUtils.readUint8(input);
        if (CompressionMethod._null != compressionMethod)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        Hashtable extensions = TlsProtocol.readExtensions(input);

        return new ServerHello(version, random, sessionID, cipherSuite, extensions);
    }
}
