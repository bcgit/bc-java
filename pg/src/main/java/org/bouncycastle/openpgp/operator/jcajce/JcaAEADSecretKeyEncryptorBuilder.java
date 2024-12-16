package org.bouncycastle.openpgp.operator.jcajce;

import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.Cipher;

import org.bouncycastle.bcpg.AEADUtils;
import org.bouncycastle.bcpg.PacketTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.AEADSecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;

public class JcaAEADSecretKeyEncryptorBuilder
    implements AEADSecretKeyEncryptorBuilder
{
    private int aeadAlgorithm;
    private int symmetricAlgorithm;
    private S2K.Argon2Params argon2Params;

    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
    private JceAEADUtil aeadUtil = new JceAEADUtil(helper);

    public JcaAEADSecretKeyEncryptorBuilder(int aeadAlgorithm, int symmetricAlgorithm, S2K.Argon2Params argon2Params)
    {
        this.aeadAlgorithm = aeadAlgorithm;
        this.symmetricAlgorithm = symmetricAlgorithm;
        this.argon2Params = argon2Params;
    }

    public JcaAEADSecretKeyEncryptorBuilder setProvider(Provider provider)
    {
        this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));
        this.aeadUtil = new JceAEADUtil(helper);

        return this;
    }

    public JcaAEADSecretKeyEncryptorBuilder setProvider(String providerName)
    {
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));
        this.aeadUtil = new JceAEADUtil(helper);

        return this;
    }

    public PBESecretKeyEncryptor build(char[] passphrase, final PublicKeyPacket pubKey)
    {
        return new PBESecretKeyEncryptor(symmetricAlgorithm, aeadAlgorithm, argon2Params, new SecureRandom(), passphrase)
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
                    return JceAEADUtil.processAeadKeyData(
                        aeadUtil,
                        Cipher.ENCRYPT_MODE,
                        encAlgorithm,
                        aeadAlgorithm,
                        getKey(),
                        iv,
                        pubKey.getPacketTag() == PacketTags.PUBLIC_KEY ? PacketTags.SECRET_KEY : PacketTags.SECRET_SUBKEY,
                        pubKey.getVersion(),
                        keyData,
                        keyOff,
                        keyLen,
                        pubKey.getEncodedContents());
                }
                catch (Exception e)
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
