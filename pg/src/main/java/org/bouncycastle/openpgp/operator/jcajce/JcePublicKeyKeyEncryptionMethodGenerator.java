package org.bouncycastle.openpgp.operator.jcajce;

import java.io.IOException;
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
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
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

    protected byte[] encryptSessionInfo(PGPPublicKey pubKey, byte[] sessionInfo)
        throws PGPException
    {
        try
        {
            PublicKey cryptoPublicKey = keyConverter.getPublicKey(pubKey);

            if (pubKey.getAlgorithm() == PublicKeyAlgorithmTags.ECDH || pubKey.getAlgorithm() == PublicKeyAlgorithmTags.X448
                || pubKey.getAlgorithm() == PublicKeyAlgorithmTags.X25519)
            {
                PublicKeyPacket pubKeyPacket = pubKey.getPublicKeyPacket();
                ECDHPublicBCPGKey ecKey = (ECDHPublicBCPGKey)pubKeyPacket.getKey();

                UserKeyingMaterialSpec ukmSpec = new UserKeyingMaterialSpec(
                    RFC6637Utils.createUserKeyingMaterial(pubKeyPacket, new JcaKeyFingerprintCalculator()));
                String keyEncryptionOID = RFC6637Utils.getKeyEncryptionOID(ecKey.getSymmetricKeyAlgorithm()).getId();

                if (ecKey.getCurveOID().equals(CryptlibObjectIdentifiers.curvey25519))
                {
                    return getEncryptSessionInfo("X25519", RFC6637Utils.getXDHAlgorithm(pubKeyPacket), ukmSpec, cryptoPublicKey, keyEncryptionOID,
                        ecKey, sessionInfo, (kpGen) -> kpGen.initialize(255, random),
                        (ephPubEncoding) -> Arrays.prepend(ephPubEncoding, X_HDR));
                }
                else if (ecKey.getCurveOID().equals(EdECObjectIdentifiers.id_X448))
                {
                    return getEncryptSessionInfo("X448", RFC6637Utils.getXDHAlgorithm(pubKeyPacket), ukmSpec, cryptoPublicKey, keyEncryptionOID,
                        ecKey, sessionInfo, (kpGen) -> kpGen.initialize(448, random), (ephPubEncoding) -> ephPubEncoding);
                }
                else
                {
                    return getEncryptSessionInfo("EC", RFC6637Utils.getAgreementAlgorithm(pubKeyPacket), ukmSpec, cryptoPublicKey, keyEncryptionOID,
                        ecKey, sessionInfo, (kpGen) ->
                        {
                            AlgorithmParameters ecAlgParams = helper.createAlgorithmParameters("EC");
                            ecAlgParams.init(new X962Parameters(ecKey.getCurveOID()).getEncoded());
                            kpGen.initialize(ecAlgParams.getParameterSpec(AlgorithmParameterSpec.class), random);
                        }, (ephPubEncoding) ->
                        {
                            if (null == ephPubEncoding || ephPubEncoding.length < 1 || ephPubEncoding[0] != 0x04)
                            {
                                ephPubEncoding = JcaJcePGPUtil.getX9Parameters(ecKey.getCurveOID()).getCurve().decodePoint(ephPubEncoding).getEncoded(false);
                            }
                            return ephPubEncoding;
                        });
                }
            }
            else
            {
                Cipher c = helper.createPublicKeyCipher(pubKey.getAlgorithm());

                c.init(Cipher.ENCRYPT_MODE, cryptoPublicKey, random);

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
    private interface KeyPairGeneratorOperation
    {
        void initialize(KeyPairGenerator kpGen)
            throws GeneralSecurityException, IOException;
    }

    @FunctionalInterface
    private interface EphPubEncoding
    {
        byte[] getEphPubEncoding(byte[] publicKeyData);
    }

    private byte[] getEncryptSessionInfo(String algorithmName, String algorithm, UserKeyingMaterialSpec ukmSpec,
                                         PublicKey cryptoPublicKey, String keyEncryptionOID, ECDHPublicBCPGKey ecKey, byte[] sessionInfo,
                                         KeyPairGeneratorOperation kpOperation, EphPubEncoding getEncoding)
        throws GeneralSecurityException, IOException, PGPException
    {
        KeyPairGenerator kpGen = helper.createKeyPairGenerator(algorithmName);
        kpOperation.initialize(kpGen);
        KeyPair ephKP = kpGen.generateKeyPair();
        KeyAgreement agreement = helper.createKeyAgreement(algorithm);
        agreement.init(ephKP.getPrivate(), ukmSpec);
        agreement.doPhase(cryptoPublicKey, true);
        Key secret = agreement.generateSecret(keyEncryptionOID);
        byte[] ephPubEncoding = getEncoding.getEphPubEncoding(SubjectPublicKeyInfo.getInstance(ephKP.getPublic().getEncoded()).getPublicKeyData().getBytes());
        return encryptSessionInfo(ecKey, sessionInfo, secret, ephPubEncoding);
    }

    private byte[] encryptSessionInfo(ECDHPublicBCPGKey ecKey, byte[] sessionInfo, Key secret, byte[] ephPubEncoding)
        throws GeneralSecurityException, IOException, PGPException
    {
        byte[] paddedSessionData = PGPPad.padSessionData(sessionInfo, sessionKeyObfuscation);

        Cipher c = helper.createKeyWrapper(ecKey.getSymmetricKeyAlgorithm());
        c.init(Cipher.WRAP_MODE, secret, random);
        byte[] C = c.wrap(new SecretKeySpec(paddedSessionData, PGPUtil.getSymmetricCipherName(sessionInfo[0])));

        return getSessionInfo(ephPubEncoding, C);
    }
}
