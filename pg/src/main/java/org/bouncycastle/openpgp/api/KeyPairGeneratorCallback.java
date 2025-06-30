package org.bouncycastle.openpgp.api;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator;

/**
 * Callback to generate a {@link PGPKeyPair} from a {@link PGPKeyPairGenerator} instance.
 */
public interface KeyPairGeneratorCallback
{
    /**
     * Generate a {@link PGPKeyPair} by calling a factory method on a given generator instance.
     *
     * @param generator PGPKeyPairGenerator
     * @return generated key pair
     * @throws PGPException
     */
    PGPKeyPair generateFrom(PGPKeyPairGenerator generator)
        throws PGPException;

    static class Util
    {
        public static KeyPairGeneratorCallback primaryKey()
        {
            return new KeyPairGeneratorCallback()
            {
                @Override
                public PGPKeyPair generateFrom(PGPKeyPairGenerator generator)
                    throws PGPException
                {
                    return generator.generatePrimaryKey();
                }
            };
        }

        public static KeyPairGeneratorCallback encryptionKey()
        {
            return new KeyPairGeneratorCallback()
            {
                @Override
                public PGPKeyPair generateFrom(PGPKeyPairGenerator generator)
                    throws PGPException
                {
                    return generator.generateEncryptionSubkey();
                }
            };
        }

        public static KeyPairGeneratorCallback signingKey()
        {
            return new KeyPairGeneratorCallback()
            {
                @Override
                public PGPKeyPair generateFrom(PGPKeyPairGenerator generator)
                    throws PGPException
                {
                    return generator.generateSigningSubkey();
                }
            };
        }
    }
}
