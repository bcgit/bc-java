package org.bouncycastle.pqc.jcajce.provider.cmce;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.ARIAEngine;
import org.bouncycastle.crypto.engines.CamelliaEngine;
import org.bouncycastle.crypto.engines.RFC3394WrapEngine;
import org.bouncycastle.crypto.engines.RFC5649WrapEngine;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jcajce.provider.util.DigestFactory;
import org.bouncycastle.jcajce.spec.KEMParameterSpec;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.pqc.crypto.cmce.CMCEKEMExtractor;
import org.bouncycastle.pqc.crypto.cmce.CMCEKEMGenerator;
import org.bouncycastle.util.Arrays;

class CMCECipherSpi
    extends CipherSpi
{
    private final String algorithmName;
    private CMCEKEMGenerator kemGen;
    private KEMParameterSpec kemParameterSpec;
    private BCCMCEPublicKey wrapKey;
    private BCCMCEPrivateKey unwrapKey;
    private SecureRandom random;

    private AlgorithmParameters engineParams;

    CMCECipherSpi(String algorithmName)
        throws NoSuchAlgorithmException
    {
        this.algorithmName = algorithmName;
    }

    @Override
    protected void engineSetMode(String mode)
        throws NoSuchAlgorithmException
    {
        throw new NoSuchAlgorithmException("Cannot support mode " + mode);
    }

    @Override
    protected void engineSetPadding(String padding)
        throws NoSuchPaddingException
    {
        throw new NoSuchPaddingException("Padding " + padding + " unknown");
    }

    protected int engineGetKeySize(
        Key key)
    {
        return 2048; // TODO
        //throw new IllegalArgumentException("not an valid key!");
    }

    @Override
    protected int engineGetBlockSize()
    {
        return 0;
    }

    @Override
    protected int engineGetOutputSize(int i)
    {
        return -1;        // can't use with update/doFinal
    }

    @Override
    protected byte[] engineGetIV()
    {
        return null;
    }

    @Override
    protected AlgorithmParameters engineGetParameters()
    {
        if (engineParams == null)
        {
            try
            {
                engineParams = AlgorithmParameters.getInstance(algorithmName, "BCPQC");

                engineParams.init(kemParameterSpec);
            }
            catch (Exception e)
            {
                throw new IllegalStateException(e.toString(), e);
            }
        }

        return engineParams;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random)
        throws InvalidKeyException
    {
        try
        {
            engineInit(opmode, key, (AlgorithmParameterSpec)null, random);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec paramSpec, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (random == null)
        {
            this.random = CryptoServicesRegistrar.getSecureRandom();
        }

        if (paramSpec == null)
        {
            // TODO: default should probably use shake.
            kemParameterSpec = new KEMParameterSpec("AES-KWP");
        }
        else
        {
            if (!(paramSpec instanceof KEMParameterSpec))
            {
                throw new InvalidAlgorithmParameterException(algorithmName + " can only accept KTSParameterSpec");
            }

            kemParameterSpec = (KEMParameterSpec)paramSpec;
        }

        if (opmode == Cipher.WRAP_MODE)
        {
            if (key instanceof BCCMCEPublicKey)
            {
                wrapKey = (BCCMCEPublicKey)key;
                kemGen = new CMCEKEMGenerator(random);
            }
            else
            {
                throw new InvalidKeyException("Only an RSA public key can be used for wrapping");
            }
        }
        else if (opmode == Cipher.UNWRAP_MODE)
        {
            if (key instanceof BCCMCEPrivateKey)
            {
                unwrapKey = (BCCMCEPrivateKey)key;
            }
            else
            {
                throw new InvalidKeyException("Only an RSA private key can be used for unwrapping");
            }
        }
        else
        {
            throw new InvalidParameterException("Cipher only valid for wrapping/unwrapping");
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters algorithmParameters, SecureRandom secureRandom)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        AlgorithmParameterSpec paramSpec = null;

        if (algorithmParameters != null)
        {
            try
            {
                paramSpec = algorithmParameters.getParameterSpec(KTSParameterSpec.class);
            }
            catch (Exception e)
            {
                throw new InvalidAlgorithmParameterException("can't handle parameter " + algorithmParameters.toString());
            }
        }

        engineInit(opmode, key, paramSpec, random);
    }

    @Override
    protected byte[] engineUpdate(byte[] bytes, int i, int i1)
    {
        throw new IllegalStateException("Not supported in a wrapping mode");
    }

    @Override
    protected int engineUpdate(byte[] bytes, int i, int i1, byte[] bytes1, int i2)
        throws ShortBufferException
    {
        throw new IllegalStateException("Not supported in a wrapping mode");
    }

    @Override
    protected byte[] engineDoFinal(byte[] bytes, int i, int i1)
        throws IllegalBlockSizeException, BadPaddingException
    {
        throw new IllegalStateException("Not supported in a wrapping mode");
    }

    @Override
    protected int engineDoFinal(byte[] bytes, int i, int i1, byte[] bytes1, int i2)
        throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
    {
        throw new IllegalStateException("Not supported in a wrapping mode");
    }

    protected byte[] engineWrap(
        Key key)
        throws IllegalBlockSizeException, InvalidKeyException
    {
        byte[] encoded = key.getEncoded();
        if (encoded == null)
        {
            throw new InvalidKeyException("Cannot wrap key, null encoding.");
        }

        try
        {
            SecretWithEncapsulation secEnc = kemGen.generateEncapsulated(wrapKey.getKeyParams());

            Wrapper kWrap = getWrapper(kemParameterSpec.getWrappingKeyAlgorithmName());

            KeyParameter keyParameter = new KeyParameter(secEnc.getSecret());

            kWrap.init(true, keyParameter);

            byte[] encapsulation = secEnc.getEncapsulation();

            secEnc.destroy();

            byte[] keyToWrap = key.getEncoded();
            
            byte[] rv = Arrays.concatenate(encapsulation, kWrap.wrap(keyToWrap, 0, keyToWrap.length));

            Arrays.clear(keyToWrap);

            return rv;
        }
        catch (IllegalArgumentException e)
        {
            throw new IllegalBlockSizeException("unable to generate KTS secret: " + e.getMessage());
        }
        catch (DestroyFailedException e)
        {
            throw new IllegalBlockSizeException("unable to destroy interim values: " + e.getMessage());
        }
    }

    protected Key engineUnwrap(
        byte[] wrappedKey,
        String wrappedKeyAlgorithm,
        int wrappedKeyType)
        throws InvalidKeyException, NoSuchAlgorithmException
    {
        // TODO: add support for other types.
        if (wrappedKeyType != Cipher.SECRET_KEY)
        {
            throw new InvalidKeyException("only SECRET_KEY supported");
        }
        try
        {
            CMCEKEMExtractor kemExt = new CMCEKEMExtractor(unwrapKey.getKeyParams());

            byte[] secret = kemExt.extractSecret(Arrays.copyOfRange(wrappedKey, 0, kemExt.getInputSize()));

            Wrapper kWrap = getWrapper(kemParameterSpec.getWrappingKeyAlgorithmName());

            KeyParameter keyParameter = new KeyParameter(secret);

            Arrays.clear(secret);

            kWrap.init(false, keyParameter);

            byte[] keyEncBytes = Arrays.copyOfRange(wrappedKey, kemExt.getInputSize(), wrappedKey.length);

            SecretKey rv = new SecretKeySpec(kWrap.unwrap(keyEncBytes, 0, keyEncBytes.length), wrappedKeyAlgorithm);

            Arrays.clear(keyParameter.getKey());

            return rv;
        }
        catch (IllegalArgumentException e)
        {
            throw new NoSuchAlgorithmException("unable to extract KTS secret: " + e.getMessage());
        }
        catch (InvalidCipherTextException e)
        {
            throw new InvalidKeyException("unable to extract KTS secret: " + e.getMessage());
        }
    }

    private Wrapper getWrapper(String keyAlgorithmName)
    {
        Wrapper kWrap;

        if (keyAlgorithmName.equalsIgnoreCase("AES"))
        {
            kWrap = new RFC3394WrapEngine(new AESEngine());
        }
        else if (keyAlgorithmName.equalsIgnoreCase("Camellia"))
        {
            kWrap = new RFC3394WrapEngine(new CamelliaEngine());
        }
        else if (keyAlgorithmName.equalsIgnoreCase("ARIA"))
        {
            kWrap = new RFC3394WrapEngine(new ARIAEngine());
        }
        else if (keyAlgorithmName.equalsIgnoreCase("AES-KWP"))
        {
            kWrap = new RFC5649WrapEngine(new AESEngine());
        }
        else if (keyAlgorithmName.equalsIgnoreCase("Camellia-KWP"))
        {
            kWrap = new RFC5649WrapEngine(new CamelliaEngine());
        }
        else if (keyAlgorithmName.equalsIgnoreCase("ARIA-KWP"))
        {
            kWrap = new RFC5649WrapEngine(new ARIAEngine());
        }
        else
        {
            throw new UnsupportedOperationException("unknown key algorithm: " + keyAlgorithmName);
        }
        return kWrap;
    }

    static boolean isNotNull(ASN1Encodable parameters)
    {
        return parameters != null && !DERNull.INSTANCE.equals(parameters.toASN1Primitive());
    }

    private byte[] makeKeyBytes(AlgorithmIdentifier kdfAlgorithm, byte[] secret, int keyLength, byte[] otherInfo)
        throws InvalidKeySpecException
    {
        AlgorithmIdentifier digAlg = AlgorithmIdentifier.getInstance(kdfAlgorithm.getParameters());
        if (isNotNull(digAlg.getParameters()))
        {
            throw new InvalidKeySpecException("Digest algorithm identifier cannot have parameters");
        }

        // TODO: need to add support for SHAKE!
        DerivationFunction kdfCalculator;
        if (X9ObjectIdentifiers.id_kdf_kdf2.equals(kdfAlgorithm.getAlgorithm()))
        {
            kdfCalculator = new KDF2BytesGenerator(DigestFactory.getDigest(digAlg.getAlgorithm().getId()));
            kdfCalculator.init(new KDFParameters(secret, otherInfo));
        }
        else if (X9ObjectIdentifiers.id_kdf_kdf3.equals(kdfAlgorithm.getAlgorithm()))
        {
            kdfCalculator = new ConcatenationKDFGenerator(DigestFactory.getDigest(digAlg.getAlgorithm().getId()));
            kdfCalculator.init(new KDFParameters(secret, otherInfo));
        }
        else
        {
            throw new InvalidKeySpecException("Unrecognized KDF: " + kdfAlgorithm.getAlgorithm());
        }

        byte[] keyBytes = new byte[(keyLength + 7) / 8];

        kdfCalculator.generateBytes(keyBytes, 0, keyBytes.length);

        Arrays.fill(secret, (byte)0);

        return keyBytes;
    }

    public static class Base
        extends CMCECipherSpi
    {
        public Base()
            throws NoSuchAlgorithmException
        {
            super("CMCE");
        }
    }
}
