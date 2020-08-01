package org.bouncycastle.jcajce.provider.symmetric.util;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;
import javax.crypto.spec.RC5ParameterSpec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jcajce.PKCS12Key;
import org.bouncycastle.jcajce.PKCS12KeyWithParameters;

public class BaseStreamCipher
    extends BaseWrapCipher
    implements PBE
{
    //
    // specs we can handle.
    //
    private Class[]                 availableSpecs =
                                    {
                                        RC2ParameterSpec.class,
                                        RC5ParameterSpec.class,
                                        IvParameterSpec.class,
                                        PBEParameterSpec.class
                                    };

    private StreamCipher       cipher;
    private int keySizeInBits;
    private int digest;
    private ParametersWithIV   ivParam;

    private int                     ivLength = 0;

    private PBEParameterSpec        pbeSpec = null;
    private String                  pbeAlgorithm = null;

    protected BaseStreamCipher(
        StreamCipher engine,
        int ivLength)
    {
        this(engine, ivLength, -1, -1);
    }

    protected BaseStreamCipher(
        StreamCipher engine,
        int ivLength,
        int keySizeInBits)
    {
        this(engine, ivLength, keySizeInBits, -1);
    }

    protected BaseStreamCipher(
        StreamCipher engine,
        int ivLength,
        int keySizeInBits,
        int digest)
    {
        cipher = engine;
        this.ivLength = ivLength;
        this.keySizeInBits = keySizeInBits;
        this.digest = digest;
    }

    protected int engineGetBlockSize()
    {
        return 0;
    }

    protected byte[] engineGetIV()
    {
        return (ivParam != null) ? ivParam.getIV() : null;
    }

    protected int engineGetKeySize(
        Key     key)
    {
        return key.getEncoded().length * 8;
    }

    protected int engineGetOutputSize(
        int     inputLen)
    {
        return inputLen;
    }

    protected AlgorithmParameters engineGetParameters()
    {
        if (engineParams == null)
        {
            if (pbeSpec != null)
            {
                try
                {
                    AlgorithmParameters engineParams = createParametersInstance(pbeAlgorithm);
                    engineParams.init(pbeSpec);

                    return engineParams;
                }
                catch (Exception e)
                {
                    return null;
                }
            }
            else if (ivParam != null)
            {
                String  name = cipher.getAlgorithmName();

                if (name.indexOf('/') >= 0)
                {
                    name = name.substring(0, name.indexOf('/'));
                }
                if (name.startsWith("ChaCha7539"))
                {
                    name = "ChaCha7539";
                }
                else if (name.startsWith("Grain"))
                {
                    name = "Grainv1";
                }
                else if (name.startsWith("HC"))
                {
                    int endIndex = name.indexOf('-');
                    name = name.substring(0, endIndex) + name.substring(endIndex + 1);
                }

                try
                {
                    engineParams = createParametersInstance(name);
                    engineParams.init(new IvParameterSpec(ivParam.getIV()));
                }
                catch (Exception e)
                {
                    throw new RuntimeException(e.toString());
                }
            }
        }

        return engineParams;
    }

    /**
     * should never be called.
     */
    protected void engineSetMode(
        String  mode)
        throws NoSuchAlgorithmException
    {
        if (!(mode.equalsIgnoreCase("ECB") || mode.equals("NONE")))
        {
            throw new NoSuchAlgorithmException("can't support mode " + mode);
        }
    }

    /**
     * should never be called.
     */
    protected void engineSetPadding(
        String  padding)
    throws NoSuchPaddingException
    {
        if (!padding.equalsIgnoreCase("NoPadding"))
        {
            throw new NoSuchPaddingException("Padding " + padding + " unknown.");
        }
    }

    protected void engineInit(
        int                     opmode,
        Key                     key,
        AlgorithmParameterSpec  params,
        SecureRandom            random)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        CipherParameters        param;

        this.pbeSpec = null;
        this.pbeAlgorithm = null;

        this.engineParams = null;

        //
        // basic key check
        //
        if (!(key instanceof SecretKey))
        {
            throw new InvalidKeyException("Key for algorithm " + key.getAlgorithm() + " not suitable for symmetric enryption.");
        }

        if (key instanceof PKCS12Key)
        {
            PKCS12Key k = (PKCS12Key)key;
            pbeSpec = (PBEParameterSpec)params;
            if (k instanceof PKCS12KeyWithParameters && pbeSpec == null)
            {
                pbeSpec = new PBEParameterSpec(((PKCS12KeyWithParameters)k).getSalt(), ((PKCS12KeyWithParameters)k).getIterationCount());
            }

            param = PBE.Util.makePBEParameters(k.getEncoded(), PKCS12, digest, keySizeInBits, ivLength * 8, pbeSpec, cipher.getAlgorithmName());
        }
        else if (key instanceof BCPBEKey)
        {
            BCPBEKey k = (BCPBEKey)key;

            if (k.getOID() != null)
            {
                pbeAlgorithm = k.getOID().getId();
            }
            else
            {
                pbeAlgorithm = k.getAlgorithm();
            }

            if (k.getParam() != null)
            {
                param = k.getParam();
                pbeSpec = new PBEParameterSpec(k.getSalt(), k.getIterationCount());
            }
            else if (params instanceof PBEParameterSpec)
            {
                param = PBE.Util.makePBEParameters(k, params, cipher.getAlgorithmName());
                pbeSpec = (PBEParameterSpec)params;
            }
            else
            {
                throw new InvalidAlgorithmParameterException("PBE requires PBE parameters to be set.");
            }
            
            if (k.getIvSize() != 0)
            {
                ivParam = (ParametersWithIV)param;
            }
        }
        else if (params == null)
        {
            if (digest > 0)
            {
                throw new InvalidKeyException("Algorithm requires a PBE key");
            }
            param = new KeyParameter(key.getEncoded());
        }
        else if (params instanceof IvParameterSpec)
        {
            param = new ParametersWithIV(new KeyParameter(key.getEncoded()), ((IvParameterSpec)params).getIV());
            ivParam = (ParametersWithIV)param;
        }
        else
        {
            throw new InvalidAlgorithmParameterException("unknown parameter type.");
        }

        if ((ivLength != 0) && !(param instanceof ParametersWithIV))
        {
            SecureRandom    ivRandom = random;

            if (ivRandom == null)
            {
                ivRandom = CryptoServicesRegistrar.getSecureRandom();
            }

            if ((opmode == Cipher.ENCRYPT_MODE) || (opmode == Cipher.WRAP_MODE))
            {
                byte[]  iv = new byte[ivLength];

                ivRandom.nextBytes(iv);
                param = new ParametersWithIV(param, iv);
                ivParam = (ParametersWithIV)param;
            }
            else
            {
                throw new InvalidAlgorithmParameterException("no IV set when one expected");
            }
        }

        try
        {
            switch (opmode)
            {
            case Cipher.ENCRYPT_MODE:
            case Cipher.WRAP_MODE:
                cipher.init(true, param);
                break;
            case Cipher.DECRYPT_MODE:
            case Cipher.UNWRAP_MODE:
                cipher.init(false, param);
                break;
            default:
                throw new InvalidParameterException("unknown opmode " + opmode + " passed");
            }
        }
        catch (Exception e)
        {
            throw new InvalidKeyException(e.getMessage());
        }
    }

    protected void engineInit(
        int                 opmode,
        Key                 key,
        AlgorithmParameters params,
        SecureRandom        random) 
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        AlgorithmParameterSpec  paramSpec = null;

        if (params != null)
        {
            paramSpec = SpecUtil.extractSpec(params, availableSpecs);

            if (paramSpec == null)
            {
                throw new InvalidAlgorithmParameterException("can't handle parameter " + params.toString());
            }
        }

        engineInit(opmode, key, paramSpec, random);
        engineParams = params;
    }

    protected void engineInit(
        int                 opmode,
        Key                 key,
        SecureRandom        random) 
        throws InvalidKeyException
    {
        try
        {
            engineInit(opmode, key, (AlgorithmParameterSpec)null, random);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new InvalidKeyException(e.getMessage());
        }
    }

    protected byte[] engineUpdate(
        byte[]  input,
        int     inputOffset,
        int     inputLen) 
    {
        byte[]  out = new byte[inputLen];

        cipher.processBytes(input, inputOffset, inputLen, out, 0);

        return out;
    }

    protected int engineUpdate(
        byte[]  input,
        int     inputOffset,
        int     inputLen,
        byte[]  output,
        int     outputOffset) 
        throws ShortBufferException 
    {
        if (outputOffset + inputLen > output.length)
        {
            throw new ShortBufferException("output buffer too short for input.");
        }

        try
        {
            cipher.processBytes(input, inputOffset, inputLen, output, outputOffset);

            return inputLen;
        }
        catch (DataLengthException e)
        {
            // should never happen
            throw new IllegalStateException(e.getMessage());
        }
    }

    protected byte[] engineDoFinal(
        byte[]  input,
        int     inputOffset,
        int     inputLen) 
    {
        if (inputLen != 0)
        {
            byte[] out = engineUpdate(input, inputOffset, inputLen);

            cipher.reset();
            
            return out;
        }

        cipher.reset();
        
        return new byte[0];
    }

    protected int engineDoFinal(
        byte[]  input,
        int     inputOffset,
        int     inputLen,
        byte[]  output,
        int     outputOffset)
        throws ShortBufferException
    {
        if (outputOffset + inputLen > output.length)
        {
            throw new ShortBufferException("output buffer too short for input.");
        }

        if (inputLen != 0)
        {
            cipher.processBytes(input, inputOffset, inputLen, output, outputOffset);
        }

        cipher.reset();
        
        return inputLen;
    }
}
