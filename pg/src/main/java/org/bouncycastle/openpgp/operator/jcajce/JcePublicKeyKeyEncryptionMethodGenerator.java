package org.bouncycastle.openpgp.operator.jcajce;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.bcpg.MPInteger;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jcajce.spec.HybridValueParameterSpec;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PGPPad;
import org.bouncycastle.openpgp.operator.PublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.RFC6637Utils;
import org.bouncycastle.util.Arrays;

public class JcePublicKeyKeyEncryptionMethodGenerator
    extends PublicKeyKeyEncryptionMethodGenerator
{
    private static final byte X_HDR = 0x40;

    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
    private SecureRandom random;
    private JcaPGPKeyConverter keyConverter = new JcaPGPKeyConverter();

    /**
     * Create a public key encryption method generator with the method to be based on the passed in key.
     *
     * @param key the public key to use for encryption.
     */
    public JcePublicKeyKeyEncryptionMethodGenerator(PGPPublicKey key)
    {
        super(key);
    }

    public JcePublicKeyKeyEncryptionMethodGenerator setProvider(Provider provider)
    {
        this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

        keyConverter.setProvider(provider);

        return this;
    }

    public JcePublicKeyKeyEncryptionMethodGenerator setProvider(String providerName)
    {
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

        keyConverter.setProvider(providerName);

        return this;
    }

    /**
     * Provide a user defined source of randomness.
     *
     * @param random the secure random to be used.
     * @return the current generator.
     */
    public JcePublicKeyKeyEncryptionMethodGenerator setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    protected byte[] encryptSessionInfo(PGPPublicKey pubKey,
                                        byte[] sessionKey,
                                        byte optSymAlgId,
                                        boolean isV3)
        throws PGPException
    {
        try
        {
            PublicKey cryptoPublicKey = keyConverter.getPublicKey(pubKey);

            // ECDH
            if (pubKey.getAlgorithm() == PublicKeyAlgorithmTags.ECDH)
            {
                byte[] sessionInfo = createSessionInfo(isV3 ? optSymAlgId : (byte)0, sessionKey);
                final ECDHPublicBCPGKey ecKey = (ECDHPublicBCPGKey)pubKey.getPublicKeyPacket().getKey();
                String keyEncryptionOID = RFC6637Utils.getKeyEncryptionOID(ecKey.getSymmetricKeyAlgorithm()).getId();
                PublicKeyPacket pubKeyPacket = pubKey.getPublicKeyPacket();

                // Legacy X25519
                if (JcaJcePGPUtil.isX25519(ecKey.getCurveOID()))
                {
                    return encryptSessionInfoWithECDHKey(getKeyPair("X25519",255),pubKeyPacket, cryptoPublicKey, keyEncryptionOID,
                        ecKey.getSymmetricKeyAlgorithm(), sessionInfo, RFC6637Utils.getXDHAlgorithm(pubKeyPacket), optSymAlgId,
                        new EphPubEncoding()
                        {
                            @Override
                            public byte[] getEphPubEncoding(byte[] publicKeyData)
                            {
                                return Arrays.prepend(publicKeyData, X_HDR);
                            }
                        });
                }

                // Legacy X448
                else if (ecKey.getCurveOID().equals(EdECObjectIdentifiers.id_X448))
                {
                    return encryptSessionInfoWithECDHKey(getKeyPair("X448",448), pubKeyPacket, cryptoPublicKey, keyEncryptionOID,
                        ecKey.getSymmetricKeyAlgorithm(), sessionInfo, RFC6637Utils.getXDHAlgorithm(pubKeyPacket), optSymAlgId,
                        new EphPubEncoding()
                        {
                            @Override
                            public byte[] getEphPubEncoding(byte[] publicKeyData)
                            {
                                return Arrays.prepend(publicKeyData, X_HDR);
                            }
                        });
                }

                // Other ECDH curves
                else
                {
                    KeyPairGenerator kpGen = helper.createKeyPairGenerator("EC");
                    AlgorithmParameters ecAlgParams = helper.createAlgorithmParameters("EC");
                    ecAlgParams.init(new X962Parameters(ecKey.getCurveOID()).getEncoded());
                    kpGen.initialize(ecAlgParams.getParameterSpec(AlgorithmParameterSpec.class), random);
                    KeyPair ephKP = kpGen.generateKeyPair();
                    return encryptSessionInfoWithECDHKey(ephKP, pubKeyPacket, cryptoPublicKey, keyEncryptionOID,
                        ecKey.getSymmetricKeyAlgorithm(), sessionInfo, RFC6637Utils.getAgreementAlgorithm(pubKeyPacket), optSymAlgId,
                        new EphPubEncoding()
                        {
                            @Override
                            public byte[] getEphPubEncoding(byte[] ephPubEncoding)
                            {
                                if (null == ephPubEncoding || ephPubEncoding.length < 1 || ephPubEncoding[0] != 0x04)
                                {
                                    ephPubEncoding = JcaJcePGPUtil.getX9Parameters(ecKey.getCurveOID()).getCurve().decodePoint(ephPubEncoding).getEncoded(false);
                                }
                                return ephPubEncoding;
                            }
                        });
                }
            }

            // X25519
            else if (pubKey.getAlgorithm() == PublicKeyAlgorithmTags.X25519)
            {
                return encryptSessionInfoWithX25519X448Key(pubKey, "X25519", cryptoPublicKey, NISTObjectIdentifiers.id_aes128_wrap.getId(),
                    SymmetricKeyAlgorithmTags.AES_128, sessionKey, "X25519withSHA256HKDF", 255, optSymAlgId, isV3);
            }

            // X448
            else if (pubKey.getAlgorithm() == PublicKeyAlgorithmTags.X448)
            {
                return encryptSessionInfoWithX25519X448Key(pubKey, "X448", cryptoPublicKey, NISTObjectIdentifiers.id_aes256_wrap.getId(),
                    SymmetricKeyAlgorithmTags.AES_256, sessionKey, "X448withSHA512HKDF", 448, optSymAlgId, isV3);
            }

            // RSA / ElGamal etc.
            else
            {
                Cipher c = helper.createPublicKeyCipher(pubKey.getAlgorithm());

                c.init(Cipher.ENCRYPT_MODE, cryptoPublicKey, random);
                byte[] sessionInfo = createSessionInfo(isV3 ? optSymAlgId : (byte)0, sessionKey);
                return c.doFinal(sessionInfo);
            }
        }
        catch (IllegalBlockSizeException e)
        {
            throw new PGPException("illegal block size: " + e.getMessage(), e);
        }
        catch (BadPaddingException e)
        {
            throw new PGPException("bad padding: " + e.getMessage(), e);
        }
        catch (InvalidKeyException e)
        {
            throw new PGPException("key invalid: " + e.getMessage(), e);
        }
        catch (IOException e)
        {
            throw new PGPException("unable to encode MPI: " + e.getMessage(), e);
        }
        catch (GeneralSecurityException e)
        {
            throw new PGPException("unable to set up ephemeral keys: " + e.getMessage(), e);
        }
    }

    @FunctionalInterface
    private interface EphPubEncoding
    {
        byte[] getEphPubEncoding(byte[] publicKeyData);
    }

    private byte[] encryptSessionInfoWithECDHKey(KeyPair ephKP, PublicKeyPacket pubKeyPacket, PublicKey cryptoPublicKey, String keyEncryptionOID,
                                                 int symmetricKeyAlgorithm, byte[] sessionInfo, String agreementName, byte symAlgId,
                                                 EphPubEncoding getEncoding)
        throws GeneralSecurityException, IOException, PGPException
    {
        // Prepare shared-secret public key
        UserKeyingMaterialSpec ukmSpec = new UserKeyingMaterialSpec(RFC6637Utils.createUserKeyingMaterial(pubKeyPacket,
            new JcaKeyFingerprintCalculator()));
        Key secret = JcaJcePGPUtil.getSecret(helper, cryptoPublicKey, keyEncryptionOID, agreementName, ukmSpec, ephKP.getPrivate());

        byte[] ephPubEncoding = getEncoding.getEphPubEncoding(SubjectPublicKeyInfo.getInstance(ephKP.getPublic().getEncoded()).getPublicKeyData().getBytes());

        // session info is padded to 8-octet granulatiry using the method described in RFC8018.
        byte[] paddedSessionData = PGPPad.padSessionData(sessionInfo, sessionKeyObfuscation);

        // wrap the padded session info using the shared-secret public key
        // https://www.rfc-editor.org/rfc/rfc9580.html#section-11.5-16
        return getSessionInfo(new MPInteger(new BigInteger(1, ephPubEncoding)).getEncoded(),
            (byte)0, getWrapper(symmetricKeyAlgorithm, symAlgId, secret, paddedSessionData));
    }

    /**
     * Note that unlike ECDH, no checksum or padding are appended to the
     * session key before key wrapping.  Finally, note that unlike the other
     * public-key algorithms, in the case of a v3 PKESK packet, the
     * symmetric algorithm ID is not encrypted.  Instead, it is prepended to
     * the encrypted session key in plaintext.  In this case, the symmetric
     * algorithm used MUST be AES-128, AES-192 or AES-256 (algorithm ID 7, 8
     * or 9).
     */
    private byte[] encryptSessionInfoWithX25519X448Key(PGPPublicKey pgpPublicKey, String algorithmName, PublicKey cryptoPublicKey, String keyEncryptionOID,
                                                       int symmetricKeyAlgorithm, byte[] sessionKey, String agreementAlgorithmName, int keySize,
                                                       byte optSymAlgId, boolean isV3)
        throws GeneralSecurityException, IOException, PGPException
    {
        KeyPair ephKP = getKeyPair(algorithmName, keySize);
        byte[] ephPubEncoding = SubjectPublicKeyInfo.getInstance(ephKP.getPublic().getEncoded()).getPublicKeyData().getBytes();
        HybridValueParameterSpec ukmSpec = JcaJcePGPUtil.getHybridValueParameterSpecWithPrepend(ephPubEncoding, pgpPublicKey.getPublicKeyPacket(), algorithmName);
        Key secret = JcaJcePGPUtil.getSecret(helper, cryptoPublicKey, keyEncryptionOID, agreementAlgorithmName, ukmSpec, ephKP.getPrivate());
        return getSessionInfo(ephPubEncoding, isV3 ? optSymAlgId : (byte)0, getWrapper(symmetricKeyAlgorithm, optSymAlgId, secret, sessionKey));
    }

    private KeyPair getKeyPair(String algorithmName, int keySize)
        throws GeneralSecurityException
    {
        KeyPairGenerator kpGen = helper.createKeyPairGenerator(algorithmName);
        kpGen.initialize(keySize, random);
        return kpGen.generateKeyPair();
    }

    private byte[] getWrapper(int symmetricKeyAlgorithm, byte optSymAlgId, Key secret, byte[] sessionData)
        throws PGPException, InvalidKeyException, IllegalBlockSizeException
    {
        Cipher c = helper.createKeyWrapper(symmetricKeyAlgorithm);
        c.init(Cipher.WRAP_MODE, secret, random);
        return c.wrap(new SecretKeySpec(sessionData, PGPUtil.getSymmetricCipherName(optSymAlgId)));
    }
}
