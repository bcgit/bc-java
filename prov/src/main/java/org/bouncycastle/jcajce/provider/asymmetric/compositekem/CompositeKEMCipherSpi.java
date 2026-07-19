package org.bouncycastle.jcajce.provider.asymmetric.compositekem;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.WrapUtil;
import org.bouncycastle.jcajce.provider.util.SecurityExceptions;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;

/**
 * KEM Cipher (KTS wrap/unwrap) for Composite ML-KEM (draft-ietf-lamps-pq-composite-kem), enabling
 * composite recipients in CMS via JceKEMRecipientInfoGenerator / JceKEMEnvelopedRecipient. The
 * composite OID is taken from the key, so a single generic Base SPI covers all parameter sets.
 */
public class CompositeKEMCipherSpi
    extends CipherSpi
{
    private final String algorithmName;

    private KTSParameterSpec kemParameterSpec;
    private CompositeMLKEMEngine engine;
    private CompositePublicKey wrapKey;
    private CompositePrivateKey unwrapKey;

    public CompositeKEMCipherSpi(String algorithmName)
    {
        this.algorithmName = algorithmName;
    }

    protected void engineSetMode(String mode)
        throws NoSuchAlgorithmException
    {
        throw new NoSuchAlgorithmException("Cannot support mode " + mode);
    }

    protected void engineSetPadding(String padding)
        throws NoSuchPaddingException
    {
        throw new NoSuchPaddingException("Padding " + padding + " unknown");
    }

    protected int engineGetKeySize(Key key)
    {
        return 2048; // TODO
    }

    protected int engineGetBlockSize()
    {
        return 0;
    }

    protected int engineGetOutputSize(int i)
    {
        return -1;        // can't use with update/doFinal
    }

    protected byte[] engineGetIV()
    {
        return null;
    }

    protected AlgorithmParameters engineGetParameters()
    {
        return null;
    }

    protected void engineInit(int opmode, Key key, SecureRandom random)
        throws InvalidKeyException
    {
        try
        {
            engineInit(opmode, key, (AlgorithmParameterSpec)null, random);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw Exceptions.illegalArgumentException(e.getMessage(), e);
        }
    }

    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec paramSpec, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (paramSpec == null)
        {
            kemParameterSpec = new KTSParameterSpec.Builder("AES-KWP", 256).build();
        }
        else
        {
            if (!(paramSpec instanceof KTSParameterSpec))
            {
                throw new InvalidAlgorithmParameterException(algorithmName + " can only accept KTSParameterSpec");
            }

            kemParameterSpec = (KTSParameterSpec)paramSpec;
        }

        if (opmode == Cipher.WRAP_MODE)
        {
            if (key instanceof CompositePublicKey)
            {
                wrapKey = (CompositePublicKey)key;
                engine = new CompositeMLKEMEngine(wrapKey.getAlgorithmIdentifier().getAlgorithm(),
                    (random != null) ? random : CryptoServicesRegistrar.getSecureRandom());
            }
            else
            {
                throw new InvalidKeyException("Only a composite public key can be used for wrapping");
            }
        }
        else if (opmode == Cipher.UNWRAP_MODE)
        {
            if (key instanceof CompositePrivateKey)
            {
                unwrapKey = (CompositePrivateKey)key;
                engine = new CompositeMLKEMEngine(unwrapKey.getAlgorithmIdentifier().getAlgorithm());
            }
            else
            {
                throw new InvalidKeyException("Only a composite private key can be used for unwrapping");
            }
        }
        else
        {
            throw new InvalidParameterException("Cipher only valid for wrapping/unwrapping");
        }
    }

    protected void engineInit(int opmode, Key key, AlgorithmParameters algorithmParameters, SecureRandom random)
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

    protected byte[] engineUpdate(byte[] bytes, int i, int i1)
    {
        throw new IllegalStateException("Not supported in a wrapping mode");
    }

    protected int engineUpdate(byte[] bytes, int i, int i1, byte[] bytes1, int i2)
        throws ShortBufferException
    {
        throw new IllegalStateException("Not supported in a wrapping mode");
    }

    protected byte[] engineDoFinal(byte[] bytes, int i, int i1)
        throws IllegalBlockSizeException, BadPaddingException
    {
        throw new IllegalStateException("Not supported in a wrapping mode");
    }

    protected int engineDoFinal(byte[] bytes, int i, int i1, byte[] bytes1, int i2)
        throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
    {
        throw new IllegalStateException("Not supported in a wrapping mode");
    }

    protected byte[] engineWrap(Key key)
        throws IllegalBlockSizeException, InvalidKeyException
    {
        byte[] encoded = key.getEncoded();
        if (encoded == null)
        {
            throw new InvalidKeyException("Cannot wrap key, null encoding.");
        }

        SecretWithEncapsulation secEnc = null;
        try
        {
            secEnc = engine.encapsulate(wrapKey);

            Wrapper kWrap = WrapUtil.getKeyWrapper(kemParameterSpec, secEnc.getSecret());

            byte[] encapsulation = secEnc.getEncapsulation();

            byte[] keyToWrap = key.getEncoded();

            try
            {
                return Arrays.concatenate(encapsulation, kWrap.wrap(keyToWrap, 0, keyToWrap.length));
            }
            finally
            {
                Arrays.clear(keyToWrap);
            }
        }
        catch (IllegalArgumentException e)
        {
            throw SecurityExceptions.illegalBlockSizeException("unable to generate KTS secret: " + e.getMessage(), e);
        }
        finally
        {
            try
            {
                if (secEnc != null)
                {
                    secEnc.destroy();
                }
            }
            catch (DestroyFailedException e)
            {
                // ignore
            }
        }
    }

    protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType)
        throws InvalidKeyException, NoSuchAlgorithmException
    {
        if (wrappedKeyType != Cipher.SECRET_KEY)
        {
            throw new InvalidKeyException("only SECRET_KEY supported");
        }

        byte[] secret = null;
        try
        {
            int encapsulationLength = engine.getEncapsulationLength(unwrapKey);

            secret = engine.decapsulate(unwrapKey, Arrays.copyOfRange(wrappedKey, 0, encapsulationLength));

            Wrapper kWrap = WrapUtil.getKeyUnwrapper(kemParameterSpec, secret);

            byte[] keyEncBytes = Arrays.copyOfRange(wrappedKey, encapsulationLength, wrappedKey.length);

            return new SecretKeySpec(kWrap.unwrap(keyEncBytes, 0, keyEncBytes.length), wrappedKeyAlgorithm);
        }
        catch (InvalidCipherTextException e)
        {
            throw SecurityExceptions.invalidKeyException("unable to extract KTS secret: " + e.getMessage(), e);
        }
        catch (InvalidKeyException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw SecurityExceptions.invalidKeyException("unable to extract KTS secret: " + e.getMessage(), e);
        }
        finally
        {
            Arrays.clear(secret);
        }
    }

    public static class Base
        extends CompositeKEMCipherSpi
    {
        public Base()
        {
            super("COMPOSITE-KEM");
        }
    }
}
