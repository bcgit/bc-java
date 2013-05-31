package org.bouncycastle.operator.bc;

import java.security.SecureRandom;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.operator.SymmetricKeyWrapper;

public class BcSymmetricKeyWrapper
    extends SymmetricKeyWrapper
{
    private SecureRandom random;
    private Wrapper wrapper;
    private KeyParameter wrappingKey;

    public BcSymmetricKeyWrapper(AlgorithmIdentifier wrappingAlgorithm, Wrapper wrapper, KeyParameter wrappingKey)
    {
        super(wrappingAlgorithm);

        this.wrapper = wrapper;
        this.wrappingKey = wrappingKey;
    }

    public BcSymmetricKeyWrapper setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    public byte[] generateWrappedKey(GenericKey encryptionKey)
        throws OperatorException
    {
        byte[] contentEncryptionKeySpec = OperatorUtils.getKeyBytes(encryptionKey);

        if (random == null)
        {
            wrapper.init(true, wrappingKey);
        }
        else
        {
            wrapper.init(true, new ParametersWithRandom(wrappingKey, random));
        }

        return wrapper.wrap(contentEncryptionKeySpec, 0, contentEncryptionKeySpec.length);
    }
}
