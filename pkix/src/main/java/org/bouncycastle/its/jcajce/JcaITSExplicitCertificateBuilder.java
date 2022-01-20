package org.bouncycastle.its.jcajce;

import java.security.Provider;
import java.security.interfaces.ECPublicKey;

import org.bouncycastle.its.ITSCertificate;
import org.bouncycastle.its.ITSExplicitCertificateBuilder;
import org.bouncycastle.its.ITSPublicEncryptionKey;
import org.bouncycastle.its.operator.ITSContentSigner;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.oer.its.ieee1609dot2.CertificateId;
import org.bouncycastle.oer.its.ieee1609dot2.ToBeSignedCertificate;

public class JcaITSExplicitCertificateBuilder
    extends ITSExplicitCertificateBuilder
{
    private JcaJceHelper helper;

    /**
     * Base constructor for an ITS certificate.
     *
     * @param signer         the content signer to be used to generate the signature validating the certificate.
     * @param tbsCertificate
     */
    public JcaITSExplicitCertificateBuilder(ITSContentSigner signer, ToBeSignedCertificate.Builder tbsCertificate)
    {
        this(signer, tbsCertificate, new DefaultJcaJceHelper());
    }

    private JcaITSExplicitCertificateBuilder(ITSContentSigner signer, ToBeSignedCertificate.Builder tbsCertificate, JcaJceHelper helper)
    {
        super(signer, tbsCertificate);
        this.helper = helper;
    }

    public JcaITSExplicitCertificateBuilder setProvider(Provider provider)
    {
        this.helper = new ProviderJcaJceHelper(provider);
        return this;
    }

    public JcaITSExplicitCertificateBuilder setProvider(String providerName)
    {
        this.helper = new NamedJcaJceHelper(providerName);
        return this;
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
            publicEncryptionKey = new JceITSPublicEncryptionKey(encryptionKey, helper);
        }

        return super.build(certificateId, new JcaITSPublicVerificationKey(verificationKey, helper), publicEncryptionKey);
    }
}
