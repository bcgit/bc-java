package org.bouncycastle.openpgp.operator.jcajce;

import org.bouncycastle.bcpg.AEADUtils;
import org.bouncycastle.bcpg.PacketTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SymmetricKeyUtils;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Provider;
import java.security.SecureRandom;

public class JcaAEADSecretKeyEncryptorBuilder
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

    public PBESecretKeyEncryptor build(char[] passphrase, PublicKeyPacket pubKey)
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
                int packetTag = pubKey.getPacketTag() == PacketTags.PUBLIC_KEY ? PacketTags.SECRET_KEY : PacketTags.SECRET_SUBKEY;
                byte[] hkdfInfo = new byte[] {
                        (byte) (0xC0 | packetTag),
                        (byte) pubKey.getVersion(),
                        (byte) symmetricAlgorithm,
                        (byte) aeadAlgorithm
                };

                HKDFParameters hkdfParameters = new HKDFParameters(
                        getKey(),
                        null,
                        hkdfInfo);

                HKDFBytesGenerator hkdfGen = new HKDFBytesGenerator(new SHA256Digest());
                hkdfGen.init(hkdfParameters);
                key = new byte[SymmetricKeyUtils.getKeyLengthInOctets(encAlgorithm)];
                hkdfGen.generateBytes(key, 0, key.length);

                try
                {
                    byte[] aad = Arrays.prepend(pubKey.getEncodedContents(), (byte) (0xC0 | packetTag));
                    SecretKey secretKey = new SecretKeySpec(key, PGPUtil.getSymmetricCipherName(encAlgorithm));
                    final Cipher c = aeadUtil.createAEADCipher(encAlgorithm, aeadAlgorithm);

                    JceAEADCipherUtil.setUpAeadCipher(c, secretKey, Cipher.ENCRYPT_MODE, iv, 128, aad);
                    byte[] data = c.doFinal(keyData);
                    return data;
                }
                catch (IOException | InvalidAlgorithmParameterException | InvalidKeyException |
                       IllegalBlockSizeException | BadPaddingException e)
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
