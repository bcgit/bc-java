package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.util.io.Streams;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

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

    public OpenPGPCertificate parseCertificateOrKey(String armored)
            throws IOException
    {
        return parseCertificateOrKey(armored.getBytes(StandardCharsets.UTF_8));
    }

    public OpenPGPCertificate parseCertificateOrKey(InputStream inputStream)
            throws IOException
    {
        return parseCertificateOrKey(Streams.readAll(inputStream));
    }

    public OpenPGPCertificate parseCertificateOrKey(byte[] bytes)
            throws IOException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(bytes);
        InputStream decoderStream = PGPUtil.getDecoderStream(bIn);
        BCPGInputStream pIn = BCPGInputStream.wrap(decoderStream);
        PGPObjectFactory objectFactory = implementation.pgpObjectFactory(pIn);
        Object object = objectFactory.nextObject();

        // TODO: Is it dangerous, if we don't explicitly fail upon encountering secret key material here?
        //  Could it lead to a situation where we need to be cautious with the certificate API design to
        //  prevent the user from doing dangerous things like accidentally publishing their private key?

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

    public OpenPGPKey parseKey(String armored)
            throws IOException
    {
        return parseKey(armored.getBytes(StandardCharsets.UTF_8));
    }

    public OpenPGPKey parseKey(InputStream inputStream)
            throws IOException
    {
        return parseKey(Streams.readAll(inputStream));
    }

    public OpenPGPKey parseKey(byte[] bytes)
            throws IOException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(bytes);
        InputStream decoderStream = PGPUtil.getDecoderStream(bIn);
        BCPGInputStream pIn = BCPGInputStream.wrap(decoderStream);
        PGPObjectFactory objectFactory = implementation.pgpObjectFactory(pIn);

        Object object = objectFactory.nextObject();
        if (!(object instanceof PGPSecretKeyRing))
        {
            throw new IOException("Not a secret key.");
        }

        PGPSecretKeyRing keyRing = (PGPSecretKeyRing) object;
        return new OpenPGPKey(keyRing, implementation, policy);
    }
}
