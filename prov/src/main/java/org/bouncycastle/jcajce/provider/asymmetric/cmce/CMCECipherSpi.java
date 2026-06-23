package org.bouncycastle.jcajce.provider.asymmetric.cmce;

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
import org.bouncycastle.crypto.kems.CMCEKEMExtractor;
import org.bouncycastle.crypto.kems.CMCEKEMGenerator;
import org.bouncycastle.crypto.params.CMCEParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.WrapUtil;
import org.bouncycastle.jcajce.provider.util.SecurityExceptions;
import org.bouncycastle.jcajce.spec.CMCEParameterSpec;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;

public class CMCECipherSpi
    extends CipherSpi
{
    private final CMCEParameters cmceParameters;
    private final String algorithmName;

    private CMCEKEMGenerator kemGen;
    private KTSParameterSpec kemParameterSpec;
    private BCCMCEPublicKey wrapKey;
    private BCCMCEPrivateKey unwrapKey;

    private AlgorithmParameters engineParams;

    public CMCECipherSpi(String algorithmName)
    {
        this.cmceParameters = null;
        this.algorithmName = algorithmName;
    }

    public CMCECipherSpi(CMCEParameters cmceParameters)
    {
        this.cmceParameters = cmceParameters;
        this.algorithmName = cmceParameters.getName();
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
            if (key instanceof BCCMCEPublicKey)
            {
                wrapKey = (BCCMCEPublicKey)key;
                kemGen = new CMCEKEMGenerator(random);
            }
            else
            {
                throw new InvalidKeyException("Only a " + algorithmName + " public key can be used for wrapping");
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
                throw new InvalidKeyException("Only a " + algorithmName + " private key can be used for unwrapping");
            }
        }
        else
        {
            throw new InvalidParameterException("Cipher only valid for wrapping/unwrapping");
        }

        if (cmceParameters != null)
        {
            String canonicalAlgName = CMCEParameterSpec.fromName(cmceParameters.getName()).getName();
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
            CMCEKEMExtractor kemExt = new CMCEKEMExtractor(unwrapKey.getKeyParams());

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
        extends CMCECipherSpi
    {
        public Base()
        {
            super("CMCE");
        }
    }

    public static class Mceliece460896
        extends CMCECipherSpi
    {
        public Mceliece460896()
        {
            super(CMCEParameters.mceliece460896);
        }
    }

    public static class Mceliece460896F
        extends CMCECipherSpi
    {
        public Mceliece460896F()
        {
            super(CMCEParameters.mceliece460896f);
        }
    }

    public static class Mceliece460896Pc
        extends CMCECipherSpi
    {
        public Mceliece460896Pc()
        {
            super(CMCEParameters.mceliece460896pc);
        }
    }

    public static class Mceliece460896Pcf
        extends CMCECipherSpi
    {
        public Mceliece460896Pcf()
        {
            super(CMCEParameters.mceliece460896pcf);
        }
    }

    public static class Mceliece6688128
        extends CMCECipherSpi
    {
        public Mceliece6688128()
        {
            super(CMCEParameters.mceliece6688128);
        }
    }

    public static class Mceliece6688128F
        extends CMCECipherSpi
    {
        public Mceliece6688128F()
        {
            super(CMCEParameters.mceliece6688128f);
        }
    }

    public static class Mceliece6688128Pc
        extends CMCECipherSpi
    {
        public Mceliece6688128Pc()
        {
            super(CMCEParameters.mceliece6688128pc);
        }
    }

    public static class Mceliece6688128Pcf
        extends CMCECipherSpi
    {
        public Mceliece6688128Pcf()
        {
            super(CMCEParameters.mceliece6688128pcf);
        }
    }

    public static class Mceliece6960119
        extends CMCECipherSpi
    {
        public Mceliece6960119()
        {
            super(CMCEParameters.mceliece6960119);
        }
    }

    public static class Mceliece6960119F
        extends CMCECipherSpi
    {
        public Mceliece6960119F()
        {
            super(CMCEParameters.mceliece6960119f);
        }
    }

    public static class Mceliece6960119Pc
        extends CMCECipherSpi
    {
        public Mceliece6960119Pc()
        {
            super(CMCEParameters.mceliece6960119pc);
        }
    }

    public static class Mceliece6960119Pcf
        extends CMCECipherSpi
    {
        public Mceliece6960119Pcf()
        {
            super(CMCEParameters.mceliece6960119pcf);
        }
    }

    public static class Mceliece8192128
        extends CMCECipherSpi
    {
        public Mceliece8192128()
        {
            super(CMCEParameters.mceliece8192128);
        }
    }

    public static class Mceliece8192128F
        extends CMCECipherSpi
    {
        public Mceliece8192128F()
        {
            super(CMCEParameters.mceliece8192128f);
        }
    }

    public static class Mceliece8192128Pc
        extends CMCECipherSpi
    {
        public Mceliece8192128Pc()
        {
            super(CMCEParameters.mceliece8192128pc);
        }
    }

    public static class Mceliece8192128Pcf
        extends CMCECipherSpi
    {
        public Mceliece8192128Pcf()
        {
            super(CMCEParameters.mceliece8192128pcf);
        }
    }
}
