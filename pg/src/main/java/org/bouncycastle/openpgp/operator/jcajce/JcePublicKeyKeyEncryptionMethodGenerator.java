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
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.bcpg.MPInteger;
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

            if (pubKey.getAlgorithm() == PublicKeyAlgorithmTags.ECDH)
            {
                PublicKeyPacket pubKeyPacket = pubKey.getPublicKeyPacket();
                ECDHPublicBCPGKey ecKey = (ECDHPublicBCPGKey)pubKeyPacket.getKey();

                UserKeyingMaterialSpec ukmSpec = new UserKeyingMaterialSpec(
                    RFC6637Utils.createUserKeyingMaterial(pubKeyPacket, new JcaKeyFingerprintCalculator()));
                String keyEncryptionOID = RFC6637Utils.getKeyEncryptionOID(ecKey.getSymmetricKeyAlgorithm()).getId();

                if (ecKey.getCurveOID().equals(CryptlibObjectIdentifiers.curvey25519))
                {
                    KeyPairGenerator kpGen = helper.createKeyPairGenerator("X25519");
                    kpGen.initialize(255, random);

                    KeyPair ephKP = kpGen.generateKeyPair();

                    KeyAgreement agreement = helper.createKeyAgreement(RFC6637Utils.getXDHAlgorithm(pubKeyPacket));
                    agreement.init(ephKP.getPrivate(), ukmSpec);
                    agreement.doPhase(cryptoPublicKey, true);
                    Key secret = agreement.generateSecret(keyEncryptionOID);

                    SubjectPublicKeyInfo epPubKey = SubjectPublicKeyInfo.getInstance(ephKP.getPublic().getEncoded());
                    byte[] ephPubEncoding = Arrays.prepend(epPubKey.getPublicKeyData().getBytes(), X_HDR);

                    return encryptSessionInfo(ecKey, sessionInfo, secret, ephPubEncoding); 
                }
                else
                {
                    AlgorithmParameters ecAlgParams = helper.createAlgorithmParameters("EC");
                    ecAlgParams.init(new X962Parameters(ecKey.getCurveOID()).getEncoded());

                    KeyPairGenerator kpGen = helper.createKeyPairGenerator("EC");
                    kpGen.initialize(ecAlgParams.getParameterSpec(AlgorithmParameterSpec.class), random);

                    KeyPair ephKP = kpGen.generateKeyPair();

                    KeyAgreement agreement = helper.createKeyAgreement(RFC6637Utils.getAgreementAlgorithm(pubKeyPacket));
                    agreement.init(ephKP.getPrivate(), ukmSpec);
                    agreement.doPhase(cryptoPublicKey, true);
                    Key secret = agreement.generateSecret(keyEncryptionOID);

                    SubjectPublicKeyInfo ephPubKey = SubjectPublicKeyInfo.getInstance(ephKP.getPublic().getEncoded());
                    byte[] ephPubEncoding = ephPubKey.getPublicKeyData().getBytes();
                    if (null == ephPubEncoding || ephPubEncoding.length < 1 || ephPubEncoding[0] != 0x04)
                    {
                        X9ECParameters x9Params = JcaJcePGPUtil.getX9Parameters(ecKey.getCurveOID());

                        ephPubEncoding = x9Params.getCurve().decodePoint(ephPubEncoding).getEncoded(false);
                    }

                    return encryptSessionInfo(ecKey, sessionInfo, secret, ephPubEncoding); 
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

    private byte[] encryptSessionInfo(ECDHPublicBCPGKey ecKey, byte[] sessionInfo, Key secret, byte[] ephPubEncoding)
        throws GeneralSecurityException, IOException, PGPException
    {
        byte[] paddedSessionData = PGPPad.padSessionData(sessionInfo, sessionKeyObfuscation);

        Cipher c = helper.createKeyWrapper(ecKey.getSymmetricKeyAlgorithm());
        c.init(Cipher.WRAP_MODE, secret, random);
        byte[] C = c.wrap(new SecretKeySpec(paddedSessionData, PGPUtil.getSymmetricCipherName(sessionInfo[0])));

        byte[] VB = new MPInteger(new BigInteger(1, ephPubEncoding)).getEncoded();

        byte[] rv = new byte[VB.length + 1 + C.length];
        System.arraycopy(VB, 0, rv, 0, VB.length);
        rv[VB.length] = (byte)C.length;
        System.arraycopy(C, 0, rv, VB.length + 1, C.length);
        return rv;
    }
}
