package org.bouncycastle.operator.bc;

import java.io.IOException;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;

/**
 * Builder for creating content verifier providers that support the HSS/LMS Hash-Based Signature Algorithm.
 *
 * <b>Reference:</b> Use of the HSS/LMS Hash-Based Signature Algorithm in the Cryptographic Message Syntax (CMS)
 * <a href="https://datatracker.ietf.org/doc/rfc9708/">RFC 9708</a>.
 * </p>
 */
public class BcHssLmsContentVerifierProviderBuilder
    extends BcContentVerifierProviderBuilder
{
    public BcHssLmsContentVerifierProviderBuilder()
    {
    }

    protected Signer createSigner(AlgorithmIdentifier sigAlgId)
        throws OperatorCreationException
    {
        return new BcHssLmsContentSignerBuilder.HssSigner();
    }

    protected AsymmetricKeyParameter extractKeyParameters(SubjectPublicKeyInfo publicKeyInfo)
        throws IOException
    {
        return PublicKeyFactory.createKey(publicKeyInfo);
    }
}
