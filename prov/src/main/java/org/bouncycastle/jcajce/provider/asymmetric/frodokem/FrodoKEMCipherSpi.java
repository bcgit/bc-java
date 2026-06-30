package org.bouncycastle.jcajce.provider.asymmetric.frodokem;

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

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.kems.FrodoKEMExtractor;
import org.bouncycastle.crypto.kems.FrodoKEMGenerator;
import org.bouncycastle.crypto.params.FrodoKEMParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.WrapUtil;
import org.bouncycastle.jcajce.provider.util.SecurityExceptions;
import org.bouncycastle.jcajce.spec.FrodoKEMParameterSpec;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;

public class FrodoKEMCipherSpi
    extends CipherSpi
{
    private final FrodoKEMParameters frodoKEMParameters;
    private final String algorithmName;

    private FrodoKEMGenerator kemGen;
    private KTSParameterSpec kemParameterSpec;
    private BCFrodoKEMPublicKey wrapKey;
    private BCFrodoKEMPrivateKey unwrapKey;

    private AlgorithmParameters engineParams;

    public FrodoKEMCipherSpi(String algorithmName)
    {
        this.frodoKEMParameters = null;
        this.algorithmName = algorithmName;
    }

    public FrodoKEMCipherSpi(FrodoKEMParameters frodoKEMParameters)
    {
        this.frodoKEMParameters = frodoKEMParameters;
        this.algorithmName = frodoKEMParameters.getName();
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
        if (engineParams == null)
        {
            try
            {
                engineParams = AlgorithmParameters.getInstance(algorithmName, "BC");

                engineParams.init(kemParameterSpec);
            }
            catch (Exception e)
            {
                throw Exceptions.illegalStateException(e.toString(), e);
            }
        }

        return engineParams;
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
            if (key instanceof BCFrodoKEMPublicKey)
            {
                wrapKey = (BCFrodoKEMPublicKey)key;
                kemGen = new FrodoKEMGenerator(random);
            }
            else
            {
                throw new InvalidKeyException("Only a " + algorithmName + " public key can be used for wrapping");
            }
        }
        else if (opmode == Cipher.UNWRAP_MODE)
        {
            if (key instanceof BCFrodoKEMPrivateKey)
            {
                unwrapKey = (BCFrodoKEMPrivateKey)key;
            }
            else
            {
                throw new InvalidKeyException("Only a " + algorithmName + " private key can be used for unwrapping");
            }
        }
        else
        {
            throw new InvalidParameterException("Cipher only valid for wrapping/unwrapping");
        }

        if (frodoKEMParameters != null)
        {
            String canonicalAlgName = FrodoKEMParameterSpec.fromName(frodoKEMParameters.getName()).getName();
            if (!canonicalAlgName.equals(key.getAlgorithm()))
            {
                throw new InvalidKeyException("cipher locked to " + canonicalAlgName);
            }
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

    protected byte[] engineWrap(
        Key key)
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
            secEnc = kemGen.generateEncapsulated(wrapKey.getKeyParams());

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

        byte[] secret = null;
        try
        {
            FrodoKEMExtractor kemExt = new FrodoKEMExtractor(unwrapKey.getKeyParams());

            secret = kemExt.extractSecret(Arrays.copyOfRange(wrappedKey, 0, kemExt.getEncapsulationLength()));

            Wrapper kWrap = WrapUtil.getKeyUnwrapper(kemParameterSpec, secret);

            byte[] keyEncBytes = Arrays.copyOfRange(wrappedKey, kemExt.getEncapsulationLength(), wrappedKey.length);

            SecretKey rv = new SecretKeySpec(kWrap.unwrap(keyEncBytes, 0, keyEncBytes.length), wrappedKeyAlgorithm);

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
        finally
        {
            Arrays.clear(secret);
        }
    }

    public static class Base
        extends FrodoKEMCipherSpi
    {
        public Base()
        {
            super("FRODOKEM");
        }
    }

    public static class Frodokem976Shake
        extends FrodoKEMCipherSpi
    {
        public Frodokem976Shake()
        {
            super(FrodoKEMParameters.frodokem976shake);
        }
    }

    public static class Frodokem1344Shake
        extends FrodoKEMCipherSpi
    {
        public Frodokem1344Shake()
        {
            super(FrodoKEMParameters.frodokem1344shake);
        }
    }

    public static class EFrodokem976Shake
        extends FrodoKEMCipherSpi
    {
        public EFrodokem976Shake()
        {
            super(FrodoKEMParameters.efrodokem976shake);
        }
    }

    public static class EFrodokem1344Shake
        extends FrodoKEMCipherSpi
    {
        public EFrodokem1344Shake()
        {
            super(FrodoKEMParameters.efrodokem1344shake);
        }
    }

    public static class Frodokem976Aes
        extends FrodoKEMCipherSpi
    {
        public Frodokem976Aes()
        {
            super(FrodoKEMParameters.frodokem976aes);
        }
    }

    public static class Frodokem1344Aes
        extends FrodoKEMCipherSpi
    {
        public Frodokem1344Aes()
        {
            super(FrodoKEMParameters.frodokem1344aes);
        }
    }

    public static class EFrodokem976Aes
        extends FrodoKEMCipherSpi
    {
        public EFrodokem976Aes()
        {
            super(FrodoKEMParameters.efrodokem976aes);
        }
    }

    public static class EFrodokem1344Aes
        extends FrodoKEMCipherSpi
    {
        public EFrodokem1344Aes()
        {
            super(FrodoKEMParameters.efrodokem1344aes);
        }
    }
}
