package org.bouncycastle.its;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.its.operator.ECDSAEncoder;
import org.bouncycastle.its.operator.ITSContentSigner;
import org.bouncycastle.oer.OEREncoder;
import org.bouncycastle.oer.OEROptional;
import org.bouncycastle.oer.its.Certificate;
import org.bouncycastle.oer.its.CertificateBase;
import org.bouncycastle.oer.its.CertificateType;
import org.bouncycastle.oer.its.IssuerIdentifier;
import org.bouncycastle.oer.its.PublicVerificationKey;
import org.bouncycastle.oer.its.Signature;
import org.bouncycastle.oer.its.ToBeSignedCertificate;
import org.bouncycastle.oer.its.template.IEEE1609dot2;
import org.bouncycastle.util.Arrays;

public class ITSCertificateBuilder
{
    private final ToBeSignedCertificate tbsCertificate;

    // TODO: temp constructor to get signing working.
    public ITSCertificateBuilder(ToBeSignedCertificate tbsCertificate)
    {
        this.tbsCertificate = tbsCertificate;
    }

    /**
     * Generate an X509 certificate, based on the current issuer and subject
     * using the passed in signer.
     *
     * @param signer the content signer to be used to generate the signature validating the certificate.
     * @return a holder containing the resulting signed certificate.
     */
    public ITSCertificate build(
        ITSContentSigner signer)
    {
        if (signer.isForSelfSigning())
        {
            //
            // TODO: check issuer ID against self and ITSContentSigner
            //
        }

        OutputStream sOut = signer.getOutputStream();

        try
        {
            sOut.write(OEREncoder.toByteArray(tbsCertificate, IEEE1609dot2.tbsCertificate));

            sOut.close();
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("cannot produce certificate signature");
        }

        ToBeSignedCertificate signerCert = signer.getAssociatedCertificate().toASN1Structure().getCertificateBase().getToBeSignedCertificate();
        Signature sig = null;        // TODO: signature actually optional.
        switch (signerCert.getVerificationKeyIndicator().getChoice())
        {
        case PublicVerificationKey.ecdsaNistP256:
            sig = ECDSAEncoder.toITS(SECObjectIdentifiers.secp256r1, signer.getSignature());
            break;
        case PublicVerificationKey.ecdsaBrainpoolP256r1:
            sig = ECDSAEncoder.toITS(TeleTrusTObjectIdentifiers.brainpoolP256r1, signer.getSignature());
            break;
        case PublicVerificationKey.ecdsaBrainpoolP384r1:
            sig = ECDSAEncoder.toITS(TeleTrusTObjectIdentifiers.brainpoolP384r1, signer.getSignature());
            break;
        default:
            throw new IllegalStateException("unknown key type");
        }

        CertificateBase.Builder baseBldr = new CertificateBase.Builder();

        byte[] parentDigest = signer.getAssociatedCertificateDigest();
        byte[] hashedID = Arrays.copyOfRange(parentDigest, parentDigest.length - 8, parentDigest.length);

        baseBldr.setVersion(new ASN1Integer(3));
        baseBldr.setType(CertificateType.Explicit);
        ASN1ObjectIdentifier digestAlg = signer.getDigestAlgorithm().getAlgorithm();
        if (digestAlg.equals(NISTObjectIdentifiers.id_sha256))
        {
            baseBldr.setIssuer(new IssuerIdentifier(IssuerIdentifier.sha256AndDigest, hashedID));
        }
        else if (digestAlg.equals(NISTObjectIdentifiers.id_sha384))
        {
            baseBldr.setIssuer(new IssuerIdentifier(IssuerIdentifier.sha384AndDigest, hashedID));
        }
        else
        {
            throw new IllegalStateException("unknown digest");
        }

        baseBldr.setToBeSignedCertificate(tbsCertificate);
        baseBldr.setSignature(OEROptional.getInstance(sig));

        Certificate.Builder bldr = new Certificate.Builder();

        bldr.setCertificateBase(baseBldr.createCertificateBase());

        return new ITSCertificate(bldr.createCertificate());
    }
}
