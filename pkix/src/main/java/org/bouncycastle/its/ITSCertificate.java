package org.bouncycastle.its;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.oer.OEROutputStream;
import org.bouncycastle.oer.its.Certificate;
import org.bouncycastle.oer.its.IssuerIdentifier;
import org.bouncycastle.oer.its.Signature;
import org.bouncycastle.oer.its.oer.IEEE1609dot2;
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

    public AlgorithmIdentifier getSignatureAlgorithmIdentifier()
    {
        return certificate.getCertificateBase().getSignature().getAlgorithmIdentifier();
    }

    public boolean isSignatureValid(ITSContentVerifierProvider verifierProvider)
        throws Exception
    {
        ContentVerifier contentVerifier = verifierProvider.get(certificate.getCertificateBase().getSignature().getAlgorithmIdentifier());

        OutputStream verOut = contentVerifier.getOutputStream();

        verOut.write(
            OEROutputStream.encodeToBytes(certificate.getCertificateBase().getToBeSignedCertificate(),
                IEEE1609dot2.tbsCertificate));

        verOut.close();
        
        Signature sig = certificate.getCertificateBase().getSignature();

        return contentVerifier.verify(sig.getEncoded());
    }

    public Certificate toASN1Structure()
    {
        return certificate;
    }

    public byte[] getEncoded()
        throws IOException
    {
        return OEROutputStream.encodeToBytes(certificate.getCertificateBase(),
                               IEEE1609dot2.certificate);
    }
}
