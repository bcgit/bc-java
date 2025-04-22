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
import java.util.ArrayList;
import java.util.List;

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

    public List<OpenPGPCertificate> parseKeysOrCertificates(String armored)
            throws IOException
    {
        return parseKeysOrCertificates(armored.getBytes(StandardCharsets.UTF_8));
    }

    public List<OpenPGPCertificate> parseKeysOrCertificates(InputStream inputStream)
            throws IOException
    {
        return parseKeysOrCertificates(Streams.readAll(inputStream));
    }

    public List<OpenPGPCertificate> parseKeysOrCertificates(byte[] bytes)
            throws IOException
    {
        List<OpenPGPCertificate> certsOrKeys = new ArrayList<>();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bytes);
        InputStream decoderStream = PGPUtil.getDecoderStream(bIn);
        // Call getDecoderStream() twice, to make sure the stream is a BufferedInputStreamExt.
        // This is necessary, so that for streams containing multiple concatenated armored blocks of keys,
        //  we parse all of them and do not quit after reading the first one.
        decoderStream = PGPUtil.getDecoderStream(decoderStream);
        PGPObjectFactory objectFactory = implementation.pgpObjectFactory(decoderStream);
        Object object;

        while ((object = objectFactory.nextObject()) != null)
        {
            if (object instanceof PGPMarker)
            {
                continue;
            }
            if (object instanceof PGPSecretKeyRing)
            {
                certsOrKeys.add(new OpenPGPKey((PGPSecretKeyRing) object, implementation, policy));
            }
            else if (object instanceof PGPPublicKeyRing)
            {
                certsOrKeys.add(new OpenPGPCertificate((PGPPublicKeyRing) object, implementation, policy));
            }
            else
            {
                throw new IOException("Neither a certificate, nor secret key.");
            }
        }
        return certsOrKeys;
    }

    public List<OpenPGPCertificate> parseCertificates(String armored)
            throws IOException
    {
        return parseCertificates(armored.getBytes(StandardCharsets.UTF_8));
    }

    public List<OpenPGPCertificate> parseCertificates(InputStream inputStream)
            throws IOException
    {
        return parseCertificates(Streams.readAll(inputStream));
    }

    public List<OpenPGPCertificate> parseCertificates(byte[] bytes)
            throws IOException
    {
        List<OpenPGPCertificate> certs = new ArrayList<>();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bytes);
        InputStream decoderStream = PGPUtil.getDecoderStream(bIn);
        // Call getDecoderStream() twice, to make sure the stream is a BufferedInputStreamExt.
        // This is necessary, so that for streams containing multiple concatenated armored blocks of certs,
        //  we parse all of them and do not quit after reading the first one.
        decoderStream = PGPUtil.getDecoderStream(decoderStream);
        PGPObjectFactory objectFactory = implementation.pgpObjectFactory(decoderStream);
        Object object;

        while ((object = objectFactory.nextObject()) != null)
        {
            if (object instanceof PGPMarker)
            {
                continue;
            }
            else if (object instanceof PGPPublicKeyRing)
            {
                certs.add(new OpenPGPCertificate((PGPPublicKeyRing) object, implementation, policy));
            }
            else
            {
                throw new IOException("Encountered unexpected packet: " + object.getClass().getName());
            }
        }
        return certs;
    }

    public List<OpenPGPKey> parseKeys(String armored)
            throws IOException
    {
        return parseKeys(armored.getBytes(StandardCharsets.UTF_8));
    }

    public List<OpenPGPKey> parseKeys(InputStream inputStream)
            throws IOException
    {
        return parseKeys(Streams.readAll(inputStream));
    }

    public List<OpenPGPKey> parseKeys(byte[] bytes)
            throws IOException
    {
        List<OpenPGPKey> keys = new ArrayList<>();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bytes);
        InputStream decoderStream = PGPUtil.getDecoderStream(bIn);
        // Call getDecoderStream() twice, to make sure the stream is a BufferedInputStreamExt.
        // This is necessary, so that for streams containing multiple concatenated armored blocks of keys,
        //  we parse all of them and do not quit after reading the first one.
        decoderStream = PGPUtil.getDecoderStream(decoderStream);
        PGPObjectFactory objectFactory = implementation.pgpObjectFactory(decoderStream);
        Object object;

        while ((object = objectFactory.nextObject()) != null)
        {
            if (object instanceof PGPMarker)
            {
                continue;
            }
            else if (object instanceof PGPSecretKeyRing)
            {
                keys.add(new OpenPGPKey((PGPSecretKeyRing) object, implementation, policy));
            }
            else
            {
                throw new IOException("Encountered unexpected packet: " + object.getClass().getName());
            }
        }
        return keys;
    }
}
