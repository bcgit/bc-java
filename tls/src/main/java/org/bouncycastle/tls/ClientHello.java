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
    private final ProtocolVersion version;
    private final byte[] random;
    private final byte[] sessionID;
    private final byte[] cookie;
    private final int[] cipherSuites;
    private final Hashtable extensions;

    public ClientHello(ProtocolVersion version, byte[] random, byte[] sessionID, byte[] cookie,
        int[] cipherSuites, Hashtable extensions)
    {
        this.version = version;
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

    /**
     * @deprecated Use {@link #getVersion()} instead.
     */
    public ProtocolVersion getClientVersion()
    {
        return version;
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

    public ProtocolVersion getVersion()
    {
        return version;
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
        TlsUtils.writeVersion(version, output);

        output.write(random);

        TlsUtils.writeOpaque8(sessionID, output);

        if (null != cookie)
        {
            TlsUtils.writeOpaque8(cookie, output);
        }

        TlsUtils.writeUint16ArrayWithUint16Length(cipherSuites, output);

        TlsUtils.writeUint8ArrayWithUint8Length(new short[]{ CompressionMethod._null }, output);

        // TODO[tls13] 'pre_shared_key' MUST be the last extension in the ClientHello
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
     * @return a {@link ClientHello} object.
     * @throws TlsFatalAlert
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

        short[] compressionMethods = TlsUtils.readUint8ArrayWithUint8Length(input, 1);
        if (!Arrays.contains(compressionMethods, CompressionMethod._null))
        {
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }

        /*
         * NOTE: Can't use TlsProtocol.readExtensions directly because TeeInputStream a) won't have
         * 'available()' method in the FIPS provider, b) isn't a ByteArrayInputStream.
         */
        Hashtable extensions = null;
        if (messageInput.available() > 0)
        {
            byte[] extBytes = TlsUtils.readOpaque16(input);

            TlsProtocol.assertEmpty(messageInput);

            extensions = TlsProtocol.readExtensionsDataClientHello(extBytes);
        }

        return new ClientHello(clientVersion, random, sessionID, cookie, cipherSuites, extensions);
    }
}
