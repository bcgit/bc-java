package org.bouncycastle.openpgp.operator.jcajce;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.bcpg.MPInteger;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.crypto.EphemeralKeyPair;
import org.bouncycastle.crypto.KeyEncoder;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.EphemeralKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.NamedJcaJceHelper;
import org.bouncycastle.jcajce.ProviderJcaJceHelper;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.PublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.RFC6637KDFCalculator;

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
                X9ECParameters x9Params = NISTNamedCurves.getByOID(ecKey.getCurveOID());
                ECDomainParameters ecParams = new ECDomainParameters(x9Params.getCurve(), x9Params.getG(), x9Params.getN());

                // Generate the ephemeral key pair
                ECKeyPairGenerator gen = new ECKeyPairGenerator();
                gen.init(new ECKeyGenerationParameters(ecParams, random));

                EphemeralKeyPairGenerator kGen = new EphemeralKeyPairGenerator(gen, new KeyEncoder()
                {
                    public byte[] getEncoded(AsymmetricKeyParameter keyParameter)
                    {
                        return ((ECPublicKeyParameters)keyParameter).getQ().getEncoded(false);
                    }
                });

                EphemeralKeyPair ephKp = kGen.generate();

                ECPrivateKeyParameters ephPriv = (ECPrivateKeyParameters)ephKp.getKeyPair().getPrivate();

                ECPoint S = ecKey.getPoint().multiply(ephPriv.getD()).normalize();

                RFC6637KDFCalculator rfc6637KDFCalculator = new RFC6637KDFCalculator(digestCalculatorProviderBuilder.build().get(ecKey.getHashAlgorithm()), ecKey.getSymmetricKeyAlgorithm());

                Key key = new SecretKeySpec(rfc6637KDFCalculator.createKey(ecKey.getCurveOID(), S, pubKey.getFingerprint()), "AESWrap");

                Cipher c = helper.createKeyWrapper(ecKey.getSymmetricKeyAlgorithm());

                c.init(Cipher.WRAP_MODE, key, random);

                byte[] paddedSessionData = PGPUtil.padSessionData(sessionInfo);

                byte[] C = c.wrap(new SecretKeySpec(paddedSessionData, PGPUtil.getSymmetricCipherName(sessionInfo[0])));
                byte[] VB = new MPInteger(new BigInteger(1, ephKp.getEncodedPublicKey())).getEncoded();

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
    }
}
