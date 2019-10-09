package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Hashtable;

public class ServerHello
{
    private final ProtocolVersion version;
    private final byte[] random;
    private final byte[] sessionID;
    private final int cipherSuite;
    private final Hashtable extensions;

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

    /**
     * Encode this {@link ServerHello} to an {@link OutputStream}.
     * 
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
     * @param messageInput
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
