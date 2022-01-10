package org.bouncycastle.its;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.its.operator.ECDSAEncoder;
import org.bouncycastle.its.operator.ITSContentVerifierProvider;
import org.bouncycastle.oer.OEREncoder;
import org.bouncycastle.oer.its.Certificate;
import org.bouncycastle.oer.its.IssuerIdentifier;
import org.bouncycastle.oer.its.PublicEncryptionKey;
import org.bouncycastle.oer.its.Signature;
import org.bouncycastle.oer.its.template.IEEE1609dot2;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.util.Encodable;

public class ITSCertificate
    implements Encodable
{
    private final Certificate certificate;

    public ITSCertificate(Certificate certificate)
    {
        this.certificate = certificate;
    }

    public IssuerIdentifier getIssuer()
    {
        return certificate.getCertificateBase().getIssuer();
    }

    public ITSValidityPeriod getValidityPeriod()
    {
        return new ITSValidityPeriod(certificate.getCertificateBase().getToBeSignedCertificate().getValidityPeriod());
    }

    /**
     * Return the certificate's public encryption key, if present.
     *
     * @return
     */
    public ITSPublicEncryptionKey getPublicEncryptionKey()
    {
        PublicEncryptionKey encryptionKey = certificate.getCertificateBase().getToBeSignedCertificate().getEncryptionKey();

        if (encryptionKey != null)
        {
            return new ITSPublicEncryptionKey(encryptionKey);
        }

        return null;
    }

    public boolean isSignatureValid(ITSContentVerifierProvider verifierProvider)
        throws Exception
    {
        ContentVerifier contentVerifier = verifierProvider.get(certificate.getCertificateBase().getSignature().getChoice());

        OutputStream verOut = contentVerifier.getOutputStream();


        verOut.write(
            OEREncoder.toByteArray(certificate.getCertificateBase().getToBeSignedCertificate(),
                IEEE1609dot2.ToBeSignedCertificate.build()));

        verOut.close();

        Signature sig = certificate.getCertificateBase().getSignature();

        return contentVerifier.verify(ECDSAEncoder.toX962(sig));
    }

    public Certificate toASN1Structure()
    {
        return certificate;
    }

    public byte[] getEncoded()
        throws IOException
    {
        return OEREncoder.toByteArray(certificate.getCertificateBase(), IEEE1609dot2.Certificate.build());
    }
}
