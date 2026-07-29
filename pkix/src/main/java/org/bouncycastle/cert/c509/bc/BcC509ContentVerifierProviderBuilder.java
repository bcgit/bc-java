package org.bouncycastle.cert.c509.bc;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.c509.C509CertificateHolder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcECContentVerifierProviderBuilder;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;

/**
 * Lightweight builder of {@link ContentVerifierProvider}s for checking C509
 * certificate and certification request signatures, dispatching on the key's
 * algorithm to the matching lightweight operator builder. RSA and elliptic curve
 * keys - the algorithms the C509 registries centre on - are supported; use the
 * JCA/JCE builder for anything else.
 */
public class BcC509ContentVerifierProviderBuilder
{
    private final DefaultDigestAlgorithmIdentifierFinder digestAlgorithmFinder =
        new DefaultDigestAlgorithmIdentifierFinder();

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
        ASN1ObjectIdentifier keyAlgorithm = publicKeyInfo.getAlgorithm().getAlgorithm();
        AsymmetricKeyParameter publicKey;
        try
        {
            publicKey = PublicKeyFactory.createKey(publicKeyInfo);
        }
        catch (IOException e)
        {
            throw new OperatorCreationException("unable to process public key: " + e.getMessage(), e);
        }
        if (X9ObjectIdentifiers.id_ecPublicKey.equals(keyAlgorithm))
        {
            return new BcECContentVerifierProviderBuilder(digestAlgorithmFinder).build(publicKey);
        }
        if (PKCSObjectIdentifiers.rsaEncryption.equals(keyAlgorithm)
            || PKCSObjectIdentifiers.id_RSASSA_PSS.equals(keyAlgorithm))
        {
            return new BcRSAContentVerifierProviderBuilder(digestAlgorithmFinder).build(publicKey);
        }
        throw new OperatorCreationException("unsupported key algorithm: " + keyAlgorithm);
    }
}
