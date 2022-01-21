package org.bouncycastle.its.bc;

import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.its.ITSCertificate;
import org.bouncycastle.its.ITSExplicitCertificateBuilder;
import org.bouncycastle.its.ITSPublicEncryptionKey;
import org.bouncycastle.its.operator.ITSContentSigner;
import org.bouncycastle.oer.its.ieee1609dot2.CertificateId;
import org.bouncycastle.oer.its.ieee1609dot2.ToBeSignedCertificate;

public class BcITSExplicitCertificateBuilder
    extends ITSExplicitCertificateBuilder
{
    /**
     * Base constructor for an ITS certificate.
     *
     * @param signer         the content signer to be used to generate the signature validating the certificate.
     * @param tbsCertificate
     */
    public BcITSExplicitCertificateBuilder(ITSContentSigner signer, ToBeSignedCertificate.Builder tbsCertificate)
    {
        super(signer, tbsCertificate);
    }

    public ITSCertificate build(
        CertificateId certificateId,
        ECPublicKeyParameters verificationKey)
    {

        return build(certificateId, verificationKey, null);
    }

    public ITSCertificate build(
        CertificateId certificateId,
        ECPublicKeyParameters verificationKey,
        ECPublicKeyParameters encryptionKey)
    {
        ITSPublicEncryptionKey publicEncryptionKey = null;
        if (encryptionKey != null)
        {
            publicEncryptionKey = new BcITSPublicEncryptionKey(encryptionKey);
        }

        return super.build(certificateId, new BcITSPublicVerificationKey(verificationKey), publicEncryptionKey);
    }
}
