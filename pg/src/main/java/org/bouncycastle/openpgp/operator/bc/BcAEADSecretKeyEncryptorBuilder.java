package org.bouncycastle.openpgp.operator.bc;

import org.bouncycastle.bcpg.AEADUtils;
import org.bouncycastle.bcpg.PacketTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SymmetricKeyUtils;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.util.Arrays;

import java.io.IOException;
import java.security.SecureRandom;

public class BcAEADSecretKeyEncryptorBuilder
{

    private int aeadAlgorithm;
    private int symmetricAlgorithm;
    private S2K.Argon2Params argon2Params;

    public BcAEADSecretKeyEncryptorBuilder(int aeadAlgorithm, int symmetricAlgorithm, S2K.Argon2Params argon2Params)
    {
        this.aeadAlgorithm = aeadAlgorithm;
        this.symmetricAlgorithm = symmetricAlgorithm;
        this.argon2Params = argon2Params;
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
                    AEADBlockCipher cipher = BcAEADUtil.createAEADCipher(encAlgorithm, aeadAlgorithm);
                    cipher.init(true, new AEADParameters(
                            new KeyParameter(key),
                            128,
                            getCipherIV(),
                            aad
                    ));
                    int dataLen = cipher.getOutputSize(keyData.length);
                    byte[] encKey = new byte[dataLen];
                    dataLen = cipher.processBytes(keyData, 0, keyData.length, encKey, 0);

                    cipher.doFinal(encKey, dataLen);
                    return encKey;
                }
                catch (IOException | InvalidCipherTextException e)
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
