package org.bouncycastle.operator.bc;

import java.security.SecureRandom;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.operator.SymmetricKeyUnwrapper;

public class BcSymmetricKeyUnwrapper
    extends SymmetricKeyUnwrapper
{
    private SecureRandom random;
    private Wrapper wrapper;
    private KeyParameter wrappingKey;

    public BcSymmetricKeyUnwrapper(AlgorithmIdentifier wrappingAlgorithm, Wrapper wrapper, KeyParameter wrappingKey)
    {
        super(wrappingAlgorithm);

        this.wrapper = wrapper;
        this.wrappingKey = wrappingKey;
    }

    public BcSymmetricKeyUnwrapper setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    public GenericKey generateUnwrappedKey(AlgorithmIdentifier encryptedKeyAlgorithm, byte[] encryptedKey)
        throws OperatorException
    {
        wrapper.init(false, wrappingKey);

        try
        {
            return new GenericKey(encryptedKeyAlgorithm, wrapper.unwrap(encryptedKey, 0, encryptedKey.length));
        }
        catch (InvalidCipherTextException e)
        {
            throw new OperatorException("unable to unwrap key: " + e.getMessage(), e);
        }
    }
}
