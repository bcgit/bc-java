package org.bouncycastle.pkcs.bc;

import java.io.IOException;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;

/**
 * Lightweight extension of {@link PKCS10CertificationRequest} that exposes the request's
 * public key as an {@link AsymmetricKeyParameter} (no JCA dependency).
 */
public class BcPKCS10CertificationRequest
    extends PKCS10CertificationRequest
{
    /**
     * Wrap a parsed {@link CertificationRequest}.
     *
     * @param certificationRequest the underlying request.
     */
    public BcPKCS10CertificationRequest(CertificationRequest certificationRequest)
    {
        super(certificationRequest);
    }

    /**
     * Parse a BER/DER encoded PKCS#10 request.
     *
     * @param encoding the encoded request bytes.
     * @throws IOException if the data is not a valid CertificationRequest.
     */
    public BcPKCS10CertificationRequest(byte[] encoding)
        throws IOException
    {
        super(encoding);
    }

    /**
     * Re-wrap an existing {@link PKCS10CertificationRequest} as a lightweight-aware holder.
     *
     * @param requestHolder the existing holder.
     */
    public BcPKCS10CertificationRequest(PKCS10CertificationRequest requestHolder)
    {
        super(requestHolder.toASN1Structure());
    }

    /**
     * Return the public key carried by the request as a lightweight {@link AsymmetricKeyParameter}.
     *
     * @return the request's public key.
     * @throws PKCSException if the embedded SubjectPublicKeyInfo cannot be decoded.
     */
    public AsymmetricKeyParameter getPublicKey()
        throws PKCSException
    {
        try
        {
            return PublicKeyFactory.createKey(this.getSubjectPublicKeyInfo());
        }
        catch (IOException e)
        {
            throw new PKCSException("error extracting key encoding: " + e.getMessage(), e);
        }
    }
}
