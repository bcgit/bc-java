package org.bouncycastle.openpgp.operator.bc;

import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.bcpg.AEADUtils;
import org.bouncycastle.bcpg.PacketTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.AEADSecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;

public class BcAEADSecretKeyEncryptorBuilder
    implements AEADSecretKeyEncryptorBuilder
{
    private int aeadAlgorithm;
    private int symmetricAlgorithm;
    private S2K.Argon2Params argon2Params;
    private SecureRandom random = new SecureRandom();

    public BcAEADSecretKeyEncryptorBuilder(int aeadAlgorithm, int symmetricAlgorithm, S2K.Argon2Params argon2Params)
    {
        this.aeadAlgorithm = aeadAlgorithm;
        this.symmetricAlgorithm = symmetricAlgorithm;
        this.argon2Params = argon2Params;
    }

    public BcAEADSecretKeyEncryptorBuilder setSecureRandom(SecureRandom random)
    {
        this.random = random;
        return this;
    }

    public PBESecretKeyEncryptor build(char[] passphrase, final PublicKeyPacket pubKey)
    {
        return new PBESecretKeyEncryptor(symmetricAlgorithm, aeadAlgorithm, argon2Params, random, passphrase)
        {
            private byte[] iv;

            {
                iv = new byte[AEADUtils.getIVLength(aeadAlgorithm)];
                random.nextBytes(iv);
            }

            @Override
            public byte[] encryptKeyData(byte[] key, byte[] keyData, int keyOff, int keyLen)
                throws PGPException
            {
                try
                {
                    return BcAEADUtil.processAeadKeyData(true,
                        encAlgorithm,
                        aeadAlgorithm,
                        getKey(),
                        getCipherIV(),
                        pubKey.getPacketTag() == PacketTags.PUBLIC_KEY ? PacketTags.SECRET_KEY : PacketTags.SECRET_SUBKEY,
                        pubKey.getVersion(),
                        keyData,
                        keyOff,
                        keyLen,
                        pubKey.getEncodedContents());
                }
                catch (IOException e)
                {
                    throw new PGPException("Exception AEAD protecting private key material", e);
                }
            }

            @Override
            public byte[] getCipherIV()
            {
                return iv;
            }
        };
    }
}
