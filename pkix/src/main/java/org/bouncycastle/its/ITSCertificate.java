package org.bouncycastle.its;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.its.operator.ECDSAEncoder;
import org.bouncycastle.its.operator.ITSContentVerifierProvider;
import org.bouncycastle.oer.OEREncoder;
import org.bouncycastle.oer.its.ieee1609dot2.CertificateBase;
import org.bouncycastle.oer.its.ieee1609dot2.IssuerIdentifier;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.PublicEncryptionKey;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Signature;
import org.bouncycastle.oer.its.template.ieee1609dot2.IEEE1609dot2;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.Exceptions;

public class ITSCertificate
    implements Encodable
{
    private final CertificateBase certificate;

    public ITSCertificate(CertificateBase certificate)
    {
        this.certificate = certificate;
    }

    public IssuerIdentifier getIssuer()
    {
        return certificate.getIssuer();
    }

    public ITSValidityPeriod getValidityPeriod()
    {
        return new ITSValidityPeriod(certificate.getToBeSigned().getValidityPeriod());
    }

    /**
     * Return the certificate's public encryption key, if present.
     *
     * @return
     */
    public ITSPublicEncryptionKey getPublicEncryptionKey()
    {
        PublicEncryptionKey encryptionKey = certificate.getToBeSigned().getEncryptionKey();

        if (encryptionKey != null)
        {
            return new ITSPublicEncryptionKey(encryptionKey);
        }

        return null;
    }

    public boolean isSignatureValid(ITSContentVerifierProvider verifierProvider)
        throws Exception
    {
        ContentVerifier contentVerifier = verifierProvider.get(certificate.getSignature().getChoice());

        OutputStream verOut = contentVerifier.getOutputStream();


        verOut.write(
            OEREncoder.toByteArray(certificate.getToBeSigned(),
                IEEE1609dot2.ToBeSignedCertificate.build()));

        verOut.close();

        Signature sig = certificate.getSignature();

        return contentVerifier.verify(ECDSAEncoder.toX962(sig));
    }

    public CertificateBase toASN1Structure()
    {
        return certificate;
    }

    public byte[] getEncoded()
        throws IOException
    {
        return OEREncoder.toByteArray(certificate, IEEE1609dot2.CertificateBase.build());
    }

    /**
     * Return the encoding of this certificate to use when it is hashed, for example to calculate its HashedId8
     * or the signer certificate digest included in a signature calculation.
     * <p>
     * IEEE 1609.2 allows the rSig of a certificate's signature to be any of x-only, compressed-y-0, compressed-y-1
     * or uncompressed, but requires it to be taken to be of form x-only when the certificate is encoded for
     * hashing. The returned encoding is the same as {@link #getEncoded()} with rSig converted to x-only, so
     * every encoding of the same signature hashes to the same value.
     * </p>
     *
     * @return the OER encoding of this certificate with its signature's rSig of form x-only.
     * @throws IOException if the signature cannot be converted or the certificate cannot be encoded.
     */
    public byte[] getCanonicalEncoding()
        throws IOException
    {
        Signature signature = certificate.getSignature();
        if (signature == null)
        {
            return getEncoded();
        }

        Signature xOnly;
        try
        {
            xOnly = ECDSAEncoder.toXOnly(signature);
        }
        catch (IllegalArgumentException e)
        {
            throw Exceptions.ioException("unable to convert certificate signature to form x-only: " + e.getMessage(), e);
        }

        if (xOnly == signature)
        {
            return getEncoded();
        }

        return OEREncoder.toByteArray(new CertificateBase(certificate.getVersion(), certificate.getType(),
            certificate.getIssuer(), certificate.getToBeSigned(), xOnly), IEEE1609dot2.CertificateBase.build());
    }
}
