package org.bouncycastle.openpgp.operator.bc;

import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;

/**
 * A {@link PBEDataDecryptorFactory} for handling PBE decryption operations using the Bouncy Castle
 * lightweight API to implement cryptographic primitives.
 */
public class BcPBEDataDecryptorFactory
    extends PBEDataDecryptorFactory
{
    /**
     * Base constructor.
     *
     * @param pass  the passphrase to use as the primary source of key material.
     * @param calculatorProvider   a digest calculator provider to provide calculators to support the key generation calculation required.
     */
    public BcPBEDataDecryptorFactory(char[] pass, BcPGPDigestCalculatorProvider calculatorProvider)
    {
        super(pass, calculatorProvider);
    }

    protected BcPBEDataDecryptorFactory()
    {
        super();
    }

    public byte[] recoverSessionData(int keyAlgorithm, byte[] key, byte[] secKeyData)
        throws PGPException
    {
        try
        {
            if (secKeyData != null && secKeyData.length > 0)
            {
                BlockCipher engine = BcImplProvider.createBlockCipher(keyAlgorithm);
                BufferedBlockCipher cipher = BcUtil.createSymmetricKeyWrapper(false, engine, key, new byte[engine.getBlockSize()]);

                byte[] out = new byte[secKeyData.length];

                int len = cipher.processBytes(secKeyData, 0, secKeyData.length, out, 0);

                len += cipher.doFinal(out, len);

                return out;
            }
            else
            {
                byte[] keyBytes = new byte[key.length + 1];

                keyBytes[0] = (byte)keyAlgorithm;
                System.arraycopy(key, 0, keyBytes, 1, key.length);

                return keyBytes;
            }
        }
        catch (Exception e)
        {
            throw new PGPException("Exception recovering session info", e);
        }
    }

    public PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key)
        throws PGPException
    {
        BlockCipher engine = BcImplProvider.createBlockCipher(encAlgorithm);

        return BcUtil.createDataDecryptor(withIntegrityPacket, engine, key);
    }

    /**
     * Create an instance of the {@link BcPBEDataDecryptorFactory} which is based on the provided session key.
     * This factory will not source the session key from decrypting a symmetric key encrypted session key packet (SKESK)
     * with a passphrase, but instead use the provided session key directly to decrypt the data.
     *
     * @param sessionKeyAlgorithm session key algorithm
     * @param sessionKey session key
     * @return decryptor factory
     */
    public static BcPBEDataDecryptorFactory createFactoryFromSessionKey(int sessionKeyAlgorithm, byte[] sessionKey)
    {
        return new BcPBEDataDecryptorFactory()
        {
            @Override
            public byte[] makeKeyFromPassPhrase(int keyAlgorithm, S2K s2k) throws PGPException
            {
                if (keyAlgorithm != sessionKeyAlgorithm)
                {
                    throw new PGPException("Unexpected symmetric key algorithm encountered. Expected " + sessionKeyAlgorithm + ", got " + keyAlgorithm);
                }
                return sessionKey;
            }
        };
    }
}
