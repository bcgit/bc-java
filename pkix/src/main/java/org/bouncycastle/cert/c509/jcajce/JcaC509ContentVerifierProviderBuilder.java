package org.bouncycastle.cert.c509.jcajce;

import java.security.Provider;
import java.security.PublicKey;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.c509.C509CertificateHolder;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

/**
 * JCA/JCE builder of {@link ContentVerifierProvider}s for checking C509 certificate
 * and certification request signatures. The provider is built on the signer's public
 * key - for a certificate the issuer's, for a certification request the subject's -
 * with the C509 form of the key (including a compressed point) already expanded into
 * a standard SubjectPublicKeyInfo.
 */
public class JcaC509ContentVerifierProviderBuilder
{
    private final JcaContentVerifierProviderBuilder builder = new JcaContentVerifierProviderBuilder();

    public JcaC509ContentVerifierProviderBuilder setProvider(Provider provider)
    {
        builder.setProvider(provider);
        return this;
    }

    public JcaC509ContentVerifierProviderBuilder setProvider(String providerName)
    {
        builder.setProvider(providerName);
        return this;
    }

    /**
     * Build a verifier provider on the subject public key of the given certificate -
     * the issuer certificate of whatever is being verified.
     */
    public ContentVerifierProvider build(C509CertificateHolder issuerCertificate)
        throws OperatorCreationException
    {
        return build(issuerCertificate.getSubjectPublicKeyInfo());
    }

    /**
     * Build a verifier provider on the given public key info.
     */
    public ContentVerifierProvider build(SubjectPublicKeyInfo publicKeyInfo)
        throws OperatorCreationException
    {
        return builder.build(publicKeyInfo);
    }

    /**
     * Build a verifier provider on the given public key.
     */
    public ContentVerifierProvider build(PublicKey publicKey)
        throws OperatorCreationException
    {
        return builder.build(publicKey);
    }
}
