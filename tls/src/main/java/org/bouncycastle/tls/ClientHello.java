package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Hashtable;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.TeeInputStream;

public class ClientHello
{
    private final ProtocolVersion clientVersion;
    private final byte[] random;
    private final byte[] sessionID;
    private final byte[] cookie;
    private final int[] cipherSuites;
    private final Hashtable extensions;

    public ClientHello(ProtocolVersion clientVersion, byte[] random, byte[] sessionID, byte[] cookie,
        int[] cipherSuites, Hashtable extensions)
    {
        this.clientVersion = clientVersion;
        this.random = random;
        this.sessionID = sessionID;
        this.cookie = cookie;
        this.cipherSuites = cipherSuites;
        this.extensions = extensions;
    }

    public int[] getCipherSuites()
    {
        return cipherSuites;
    }

    public ProtocolVersion getClientVersion()
    {
        return clientVersion;
    }
    
    public byte[] getCookie()
    {
        return cookie;
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

    /**
     * Encode this {@link ClientHello} to an {@link OutputStream}.
     * 
     * @param output
     *            the {@link OutputStream} to encode to.
     * @throws IOException
     */
    public void encode(TlsContext context, OutputStream output) throws IOException
    {
        TlsUtils.writeVersion(clientVersion, output);

        output.write(random);

        TlsUtils.writeOpaque8(sessionID, output);

        if (null != cookie)
        {
            TlsUtils.writeOpaque8(cookie, output);
        }

        TlsUtils.writeUint16ArrayWithUint16Length(cipherSuites, output);

        TlsUtils.writeUint8ArrayWithUint8Length(new short[]{ CompressionMethod._null }, output);

        TlsProtocol.writeExtensions(output, extensions);
    }

    /**
     * Parse a {@link ClientHello} from a {@link ByteArrayInputStream}.
     *
     * @param messageInput
     *            the {@link ByteArrayInputStream} to parse from.
     * @param dtlsOutput
     *            for DTLS this should be non-null; the input is copied to this
     *            {@link OutputStream}, minus the cookie field.
     * @return a {@link Certificate} object.
     * @throws IOException
     */
    public static ClientHello parse(ByteArrayInputStream messageInput, OutputStream dtlsOutput)
        throws TlsFatalAlert
    {
        try
        {
            return implParse(messageInput, dtlsOutput);
        }
        catch (TlsFatalAlert e)
        {
            throw e;
        }
        catch (IOException e)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error, e);
        }
    }

    private static ClientHello implParse(ByteArrayInputStream messageInput, OutputStream dtlsOutput)
        throws IOException
    {
        InputStream input = messageInput;
        if (null != dtlsOutput)
        {
            input = new TeeInputStream(input, dtlsOutput);
        }

        ProtocolVersion clientVersion = TlsUtils.readVersion(input);

        byte[] random = TlsUtils.readFully(32, input);

        byte[] sessionID = TlsUtils.readOpaque8(input, 0, 32);

        byte[] cookie = null;
        if (null != dtlsOutput)
        {
            /*
             * RFC 6347 This specification increases the cookie size limit to 255 bytes for greater
             * future flexibility. The limit remains 32 for previous versions of DTLS.
             */
            int maxCookieLength = ProtocolVersion.DTLSv12.isEqualOrEarlierVersionOf(clientVersion) ? 255 : 32;

            cookie = TlsUtils.readOpaque8(messageInput, 0, maxCookieLength);
        }

        int cipher_suites_length = TlsUtils.readUint16(input);
        if (cipher_suites_length < 2 || (cipher_suites_length & 1) != 0
            || messageInput.available() < cipher_suites_length)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        /*
         * NOTE: "If the session_id field is not empty (implying a session resumption request) this
         * vector must include at least the cipher_suite from that session."
         */
        int[] cipherSuites = TlsUtils.readUint16Array(cipher_suites_length / 2, input);

        int compression_methods_length = TlsUtils.readUint8(input);
        if (compression_methods_length < 1)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        short[] compressionMethods = TlsUtils.readUint8Array(compression_methods_length, input);
        if (!Arrays.contains(compressionMethods, CompressionMethod._null))
        {
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }

        Hashtable extensions = null;
        if (messageInput.available() > 0)
        {
            byte[] extBytes = TlsUtils.readOpaque16(input);

            TlsProtocol.assertEmpty(messageInput);

            extensions = TlsProtocol.readExtensionsData(extBytes);
        }

        return new ClientHello(clientVersion, random, sessionID, cookie, cipherSuites, extensions);
    }
}
