package org.bouncycastle.openpgp.operator.jcajce;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.bcpg.MPInteger;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PGPPad;
import org.bouncycastle.openpgp.operator.PublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.RFC6637Utils;

public class JcePublicKeyKeyEncryptionMethodGenerator
    extends PublicKeyKeyEncryptionMethodGenerator
{
    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
    private SecureRandom random;
    private JcaPGPKeyConverter keyConverter = new JcaPGPKeyConverter();
    private JcaPGPDigestCalculatorProviderBuilder digestCalculatorProviderBuilder = new JcaPGPDigestCalculatorProviderBuilder();

    /**
     * Create a public key encryption method generator with the method to be based on the passed in key.
     *
     * @param key   the public key to use for encryption.
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
     * @param random  the secure random to be used.
     * @return  the current generator.
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
            if (pubKey.getAlgorithm() == PublicKeyAlgorithmTags.ECDH)
            {
                ECDHPublicBCPGKey ecKey = (ECDHPublicBCPGKey)pubKey.getPublicKeyPacket().getKey();
                X9ECParameters x9Params = JcaJcePGPUtil.getX9Parameters(ecKey.getCurveOID());
                AlgorithmParameters ecAlgParams = helper.createAlgorithmParameters("EC");

                ecAlgParams.init(new X962Parameters(ecKey.getCurveOID()).getEncoded());

                org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi.EC kpGen = (org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi.EC)helper.createKeyPairGenerator("EC");

                kpGen.initialize(ecAlgParams.getParameterSpec(AlgorithmParameterSpec.class), random);

                KeyPair ephKP = kpGen.generateKeyPair();

                // Generate the ephemeral key pair
                KeyAgreement agreement = helper.createKeyAgreement(RFC6637Utils.getAgreementAlgorithm(pubKey.getPublicKeyPacket()));

                agreement.init(ephKP.getPrivate(), new UserKeyingMaterialSpec(RFC6637Utils.createUserKeyingMaterial(pubKey.getPublicKeyPacket(), new JcaKeyFingerprintCalculator())));

                agreement.doPhase(keyConverter.getPublicKey(pubKey), true);

                Key key = agreement.generateSecret(RFC6637Utils.getKeyEncryptionOID(ecKey.getSymmetricKeyAlgorithm()).getId());

                Cipher c = helper.createKeyWrapper(ecKey.getSymmetricKeyAlgorithm());

                c.init(Cipher.WRAP_MODE, key, random);

                byte[] paddedSessionData = PGPPad.padSessionData(sessionInfo);

                byte[] C = c.wrap(new SecretKeySpec(paddedSessionData, PGPUtil.getSymmetricCipherName(sessionInfo[0])));

                SubjectPublicKeyInfo epPubKey = SubjectPublicKeyInfo.getInstance(ephKP.getPublic().getEncoded());

                X9ECPoint derQ = new X9ECPoint(x9Params.getCurve(), epPubKey.getPublicKeyData().getBytes());

                ECPoint publicPoint = derQ.getPoint();

                byte[] VB = new MPInteger(new BigInteger(1, publicPoint.getEncoded(false))).getEncoded();

                byte[] rv = new byte[VB.length + 1 + C.length];

                System.arraycopy(VB, 0, rv, 0, VB.length);
                rv[VB.length] = (byte)C.length;
                System.arraycopy(C, 0, rv, VB.length + 1, C.length);

                return rv;
            }
            else
            {
                Cipher c = helper.createPublicKeyCipher(pubKey.getAlgorithm());

                Key key = keyConverter.getPublicKey(pubKey);

                c.init(Cipher.ENCRYPT_MODE, key, random);

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
        catch (NoSuchAlgorithmException e)
        {
            throw new PGPException("unable to set up ephemeral keys: " + e.getMessage(), e);
        }
        catch (NoSuchProviderException e)
        {
            throw new PGPException("unable to set up ephemeral keys: " + e.getMessage(), e);
        }
        catch (GeneralSecurityException e)
        {
            throw new PGPException("unable to set up ephemeral keys: " + e.getMessage(), e);
        }
    }
}
