package org.bouncycastle.cbor.c509;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import org.bouncycastle.cbor.CBORDecoder;
import org.bouncycastle.cbor.CBOREncoder;

/**
 * A C509PEM structure (Section 3.6 of draft-ietf-cose-cbor-encoded-cert-20):
 * <pre>
 * C509PEM = [ C509PrivateKey, COSE_C509 / null ]
 * </pre>
 * pairing a private key with the certificates for the corresponding public key.
 * Destroying a C509PEM destroys the private key it holds.
 */
public class C509PEM
    implements Destroyable
{
    private final C509PrivateKey privateKey;
    private final C509Certificate[] certificates;

    /**
     * Base constructor.
     *
     * @param privateKey the private key.
     * @param certificates the certificates for the corresponding public key, or null.
     */
    public C509PEM(C509PrivateKey privateKey, C509Certificate[] certificates)
    {
        if (privateKey == null)
        {
            throw new NullPointerException("'privateKey' cannot be null");
        }
        this.privateKey = privateKey;
        this.certificates = certificates == null ? null : (C509Certificate[])certificates.clone();
    }

    /**
     * Parse a C509PEM structure from its CBOR encoding.
     */
    public static C509PEM getInstance(byte[] encoding)
        throws IOException
    {
        CBORDecoder in = new CBORDecoder(encoding);
        int count = in.readArrayHeader();
        if (count != 2)
        {
            throw new IOException("C509PEM array must have 2 elements");
        }
        int keyFields = in.readArrayHeader();
        if (keyFields != 3)
        {
            throw new IOException("C509PrivateKey array must have 3 elements");
        }
        C509PrivateKey privateKey = C509PrivateKey.parse(in);
        C509Certificate[] certificates = null;
        if (in.nextIsNull())
        {
            in.readNull();
        }
        else
        {
            certificates = COSEC509.decode(in);
        }
        in.expectEnd();
        return new C509PEM(privateKey, certificates);
    }

    /**
     * Return the complete CBOR encoding of this structure.
     */
    public byte[] getEncoded()
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        CBOREncoder out = new CBOREncoder(bOut);
        out.writeArrayHeader(2);
        privateKey.encodeTo(out);
        if (certificates == null)
        {
            out.writeNull();
        }
        else
        {
            COSEC509.encodeTo(out, certificates);
        }
        return bOut.toByteArray();
    }

    /**
     * Return the private key.
     */
    public C509PrivateKey getPrivateKey()
    {
        return privateKey;
    }

    /**
     * Return the certificates, or null if none were carried.
     */
    public C509Certificate[] getCertificates()
    {
        return certificates == null ? null : (C509Certificate[])certificates.clone();
    }

    public void destroy()
        throws DestroyFailedException
    {
        privateKey.destroy();
    }

    public boolean isDestroyed()
    {
        return privateKey.isDestroyed();
    }
}
