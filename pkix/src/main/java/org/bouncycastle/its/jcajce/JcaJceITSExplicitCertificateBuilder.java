package org.bouncycastle.its.jcajce;

import java.security.interfaces.ECPublicKey;

import org.bouncycastle.its.ITSCertificate;
import org.bouncycastle.its.ITSExplicitCertificateBuilder;
import org.bouncycastle.its.ITSPublicEncryptionKey;
import org.bouncycastle.its.operator.ITSContentSigner;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.oer.its.CertificateId;
import org.bouncycastle.oer.its.ToBeSignedCertificate;

public class JcaJceITSExplicitCertificateBuilder
    extends ITSExplicitCertificateBuilder
{
    private final JcaJceHelper helper;


    /**
     * Base constructor for an ITS certificate.
     *
     * @param signer         the content signer to be used to generate the signature validating the certificate.
     * @param helper         JcaJceHelper
     * @param tbsCertificate
     */
    public JcaJceITSExplicitCertificateBuilder(ITSContentSigner signer, ToBeSignedCertificate.Builder tbsCertificate, JcaJceHelper helper)
    {
        super(signer, tbsCertificate);
        this.helper = helper;
    }

    /**
     * Base constructor for an ITS certificate.
     *
     * @param signer         the content signer to be used to generate the signature validating the certificate.
     * @param tbsCertificate
     */
    public JcaJceITSExplicitCertificateBuilder(ITSContentSigner signer, ToBeSignedCertificate.Builder tbsCertificate)
    {
        this(signer, tbsCertificate, new DefaultJcaJceHelper());
    }


    public ITSCertificate build(
        CertificateId certificateId,
        ECPublicKey verificationKey)
    {

        return build(certificateId, verificationKey, null);
    }

    public ITSCertificate build(
        CertificateId certificateId,
        ECPublicKey verificationKey,
        ECPublicKey encryptionKey)
    {
        ITSPublicEncryptionKey publicEncryptionKey = null;
        if (encryptionKey != null)
        {
            publicEncryptionKey = new JcaJceITSPublicEncryptionKey(encryptionKey, helper);
        }

        return super.build(certificateId, new JcaJceITSPublicVerificationKey(verificationKey, helper), publicEncryptionKey);
    }


}
