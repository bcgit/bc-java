package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.openpgp.PGPMarker;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.util.io.Streams;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * Reader for {@link OpenPGPKey OpenPGPKeys} or {@link OpenPGPCertificate OpenPGPCertificates}.
 */
public class OpenPGPKeyReader
{
    private final OpenPGPImplementation implementation;
    private final OpenPGPPolicy policy;

    public OpenPGPKeyReader()
    {
        this(OpenPGPImplementation.getInstance());
    }

    public OpenPGPKeyReader(OpenPGPImplementation implementation)
    {
        this(implementation, implementation.policy());
    }

    public OpenPGPKeyReader(OpenPGPImplementation implementation, OpenPGPPolicy policy)
    {
        this.implementation = implementation;
        this.policy = policy;
    }

    /**
     * Parse a single {@link OpenPGPCertificate} from an ASCII armored string.
     *
     * @param armored ASCII armored string
     * @return parsed certificate
     * @throws IOException if the parsed object is a secret key or if the cert cannot be parsed
     */
    public OpenPGPCertificate parseCertificate(String armored)
            throws IOException
    {
        OpenPGPCertificate certificate = parseCertificateOrKey(armored);
        if (certificate instanceof OpenPGPKey)
        {
            throw new IOException("Could not parse OpenPGPCertificate: Is OpenPGPKey.");
        }
        return certificate;
    }

    /**
     * Parse a single {@link OpenPGPCertificate} from an {@link InputStream}.
     *
     * @param inputStream ASCII armored or binary input stream
     * @return parsed certificate
     * @throws IOException if the parsed object is a secret key or if the cert cannot be parsed
     */
    public OpenPGPCertificate parseCertificate(InputStream inputStream)
            throws IOException
    {
        OpenPGPCertificate certificate = parseCertificateOrKey(inputStream);
        if (certificate instanceof OpenPGPKey)
        {
            throw new IOException("Could not parse OpenPGPCertificate: Is OpenPGPKey.");
        }
        return certificate;
    }

    /**
     * Parse a single {@link OpenPGPCertificate} from bytes.
     *
     * @param bytes ASCII armored or binary bytes
     * @return parsed certificate
     * @throws IOException if the parsed object is a secret key or if the cert cannot be parsed
     */
    public OpenPGPCertificate parseCertificate(byte[] bytes)
            throws IOException
    {
        OpenPGPCertificate certificate = parseCertificateOrKey(bytes);
        if (certificate instanceof OpenPGPKey)
        {
            throw new IOException("Could not parse OpenPGPCertificate: Is OpenPGPKey.");
        }
        return certificate;
    }

    /**
     * Parse a single {@link OpenPGPCertificate} or {@link OpenPGPKey} from an ASCII armored string.
     *
     * @param armored ASCII armored string
     * @return parsed certificate or key
     * @throws IOException if the key or certificate cannot be parsed
     */
    public OpenPGPCertificate parseCertificateOrKey(String armored)
            throws IOException
    {
        return parseCertificateOrKey(armored.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Parse a single {@link OpenPGPCertificate} or {@link OpenPGPKey} from an {@link InputStream}.
     *
     * @param inputStream input stream containing the ASCII armored or binary key or certificate
     * @return parsed certificate or key
     * @throws IOException if the key or certificate cannot be parsed
     */
    public OpenPGPCertificate parseCertificateOrKey(InputStream inputStream)
            throws IOException
    {
        return parseCertificateOrKey(Streams.readAll(inputStream));
    }

    /**
     * Parse a single {@link OpenPGPCertificate} or {@link OpenPGPKey} from bytes.
     *
     * @param bytes ASCII armored or binary key or certificate
     * @return parsed certificate or key
     * @throws IOException if the key or certificate cannot be parsed
     */
    public OpenPGPCertificate parseCertificateOrKey(byte[] bytes)
            throws IOException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(bytes);
        InputStream decoderStream = PGPUtil.getDecoderStream(bIn);
        BCPGInputStream pIn = BCPGInputStream.wrap(decoderStream);
        PGPObjectFactory objectFactory = implementation.pgpObjectFactory(pIn);
        Object object = objectFactory.nextObject();

        while (object instanceof PGPMarker)
        {
            object = objectFactory.nextObject();
        }
        if (object instanceof PGPSecretKeyRing)
        {
            return new OpenPGPKey((PGPSecretKeyRing) object, implementation, policy);
        }
        else if (object instanceof PGPPublicKeyRing)
        {
            return new OpenPGPCertificate((PGPPublicKeyRing) object, implementation, policy);
        }
        else
        {
            throw new IOException("Neither a certificate, nor secret key.");
        }
    }

    /**
     * Parse an {@link OpenPGPKey} from an ASCII armored string.
     *
     * @param armored ASCII armored string
     * @return parsed key
     * @throws IOException if the key cannot be parsed.
     */
    public OpenPGPKey parseKey(String armored)
            throws IOException
    {
        return parseKey(armored.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Parse an {@link OpenPGPKey} from an {@link InputStream}
     *
     * @param inputStream containing the ASCII armored or binary key
     * @return parsed key
     * @throws IOException if the key cannot be parsed.
     */
    public OpenPGPKey parseKey(InputStream inputStream)
            throws IOException
    {
        return parseKey(Streams.readAll(inputStream));
    }

    /**
     * Parse an {@link OpenPGPKey} from bytes.
     *
     * @param bytes ASCII armored or binary key
     * @return parsed key
     * @throws IOException if the key cannot be parsed.
     */
    public OpenPGPKey parseKey(byte[] bytes)
            throws IOException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(bytes);
        InputStream decoderStream = PGPUtil.getDecoderStream(bIn);
        BCPGInputStream pIn = BCPGInputStream.wrap(decoderStream);
        PGPObjectFactory objectFactory = implementation.pgpObjectFactory(pIn);

        Object object = objectFactory.nextObject();
        while (object instanceof PGPMarker)
        {
            object = objectFactory.nextObject();
        }
        if (!(object instanceof PGPSecretKeyRing))
        {
            throw new IOException("Not a secret key.");
        }

        PGPSecretKeyRing keyRing = (PGPSecretKeyRing) object;
        return new OpenPGPKey(keyRing, implementation, policy);
    }
}
