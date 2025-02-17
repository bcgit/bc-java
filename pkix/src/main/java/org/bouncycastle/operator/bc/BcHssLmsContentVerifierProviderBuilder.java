package org.bouncycastle.operator.bc;

import java.io.IOException;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.operator.OperatorCreationException;

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
