package org.bouncycastle.its;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.its.operator.ECDSAEncoder;
import org.bouncycastle.its.operator.ITSContentSigner;
import org.bouncycastle.oer.OEREncoder;
import org.bouncycastle.oer.its.ieee1609dot2.CertificateBase;
import org.bouncycastle.oer.its.ieee1609dot2.CertificateId;
import org.bouncycastle.oer.its.ieee1609dot2.CertificateType;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashAlgorithm;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId8;
import org.bouncycastle.oer.its.ieee1609dot2.IssuerIdentifier;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Signature;
import org.bouncycastle.oer.its.ieee1609dot2.ToBeSignedCertificate;
import org.bouncycastle.oer.its.ieee1609dot2.VerificationKeyIndicator;
import org.bouncycastle.oer.its.template.ieee1609dot2.IEEE1609dot2;
import org.bouncycastle.util.Arrays;

public class ITSExplicitCertificateBuilder
    extends ITSCertificateBuilder
{
    private final ITSContentSigner signer;

    /**
     * Base constructor for an ITS certificate.
     *
     * @param signer         the content signer to be used to generate the signature validating the certificate.
     * @param tbsCertificate
     */
    // TODO: temp constructor to get signing working.
    public ITSExplicitCertificateBuilder(ITSContentSigner signer, ToBeSignedCertificate.Builder tbsCertificate)
    {
        super(tbsCertificate);
        this.signer = signer;
    }

    public ITSCertificate build(CertificateId certificateId, ITSPublicVerificationKey verificationKey)
    {
        return build(certificateId, verificationKey, null);
    }

    public ITSCertificate build(CertificateId certificateId, ITSPublicVerificationKey verificationKey, ITSPublicEncryptionKey publicEncryptionKey)
    {
        ToBeSignedCertificate.Builder tbsBldr = new ToBeSignedCertificate.Builder(tbsCertificateBuilder);
        
        tbsBldr.setId(certificateId);

        if (publicEncryptionKey != null)
        {
            tbsBldr.setEncryptionKey(publicEncryptionKey.toASN1Structure());
        }

        tbsBldr.setVerifyKeyIndicator(
            VerificationKeyIndicator.verificationKey(verificationKey.toASN1Structure()));

        ToBeSignedCertificate tbsCertificate = tbsBldr.createToBeSignedCertificate();

        OutputStream sOut = signer.getOutputStream();

        try
        {
            sOut.write(OEREncoder.toByteArray(tbsCertificate, IEEE1609dot2.ToBeSignedCertificate.build()));

            sOut.close();
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("cannot produce certificate signature");
        }

        // TODO: signature actually optional.
        Signature sig = ECDSAEncoder.toITS(signer.getCurveID(), signer.getSignature());

        CertificateBase.Builder baseBldr = new CertificateBase.Builder();

        ASN1ObjectIdentifier digestAlg = signer.getDigestAlgorithm().getAlgorithm();

        IssuerIdentifier issuerIdentifier;

        if (signer.isForSelfSigning())
        {

            if (digestAlg.equals(NISTObjectIdentifiers.id_sha256))
            {
                issuerIdentifier = IssuerIdentifier.self(HashAlgorithm.sha256);
            }
            else if (digestAlg.equals(NISTObjectIdentifiers.id_sha384))
            {
                issuerIdentifier = IssuerIdentifier.self(HashAlgorithm.sha384);
            }
            else
            {
                throw new IllegalStateException("unknown digest");
            }
        }
        else
        {
            byte[] parentDigest = signer.getAssociatedCertificateDigest();
            HashedId8 hashedID = new HashedId8(Arrays.copyOfRange(parentDigest, parentDigest.length - 8, parentDigest.length));
            if (digestAlg.equals(NISTObjectIdentifiers.id_sha256))
            {
                issuerIdentifier = IssuerIdentifier.sha256AndDigest(hashedID);
            }
            else if (digestAlg.equals(NISTObjectIdentifiers.id_sha384))
            {
                issuerIdentifier = IssuerIdentifier.sha384AndDigest(hashedID);
            }
            else
            {
                throw new IllegalStateException("unknown digest");
            }
        }

        baseBldr.setVersion(version);
        baseBldr.setType(CertificateType.explicit);
        baseBldr.setIssuer(issuerIdentifier);

        baseBldr.setToBeSigned(tbsCertificate);
        baseBldr.setSignature(sig);



        return new ITSCertificate(baseBldr.createCertificateBase());
    }
}
