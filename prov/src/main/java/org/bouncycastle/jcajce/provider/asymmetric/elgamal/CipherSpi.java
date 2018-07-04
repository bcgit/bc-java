package org.bouncycastle.jcajce.provider.asymmetric.elgamal;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.interfaces.DHKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.ISO9796d1Encoding;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.ElGamalEngine;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseCipherSpi;
import org.bouncycastle.jcajce.provider.util.BadBlockException;
import org.bouncycastle.jcajce.provider.util.DigestFactory;
import org.bouncycastle.jce.interfaces.ElGamalKey;
import org.bouncycastle.util.Strings;

public class CipherSpi
    extends BaseCipherSpi
{
    private AsymmetricBlockCipher   cipher;
    private AlgorithmParameterSpec  paramSpec;
    private AlgorithmParameters     engineParams;
    private ErasableOutputStream    bOut = new ErasableOutputStream();

    public CipherSpi(
        AsymmetricBlockCipher engine)
    {
        cipher = engine;
    }
   
    private void initFromSpec(
        OAEPParameterSpec pSpec) 
        throws NoSuchPaddingException
    {
        MGF1ParameterSpec   mgfParams = (MGF1ParameterSpec)pSpec.getMGFParameters();
        Digest              digest = DigestFactory.getDigest(mgfParams.getDigestAlgorithm());
        
        if (digest == null)
        {
            throw new NoSuchPaddingException("no match on OAEP constructor for digest algorithm: "+ mgfParams.getDigestAlgorithm());
        }

        cipher = new OAEPEncoding(new ElGamalEngine(), digest, ((PSource.PSpecified)pSpec.getPSource()).getValue());
        paramSpec = pSpec;
    }
    
    protected int engineGetBlockSize() 
    {
        return cipher.getInputBlockSize();
    }

    protected int engineGetKeySize(
        Key     key) 
    {
        if (key instanceof ElGamalKey)
        {
            ElGamalKey   k = (ElGamalKey)key;

            return k.getParameters().getP().bitLength();
        }
        else if (key instanceof DHKey)
        {
            DHKey   k = (DHKey)key;

            return k.getParams().getP().bitLength();
        }

        throw new IllegalArgumentException("not an ElGamal key!");
    }

    protected int engineGetOutputSize(
        int     inputLen) 
    {
        return cipher.getOutputBlockSize();
    }

    protected AlgorithmParameters engineGetParameters() 
    {
        if (engineParams == null)
        {
            if (paramSpec != null)
            {
                try
                {
                    engineParams = createParametersInstance("OAEP");
                    engineParams.init(paramSpec);
                }
                catch (Exception e)
                {
                    throw new RuntimeException(e.toString());
                }
            }
        }

        return engineParams;
    }

    protected void engineSetMode(
        String  mode)
        throws NoSuchAlgorithmException
    {
        String md = Strings.toUpperCase(mode);
        
        if (md.equals("NONE") || md.equals("ECB"))
        {
            return;
        }
        
        throw new NoSuchAlgorithmException("can't support mode " + mode);
    }

    protected void engineSetPadding(
        String  padding) 
        throws NoSuchPaddingException
    {
        String pad = Strings.toUpperCase(padding);

        if (pad.equals("NOPADDING"))
        {
            cipher = new ElGamalEngine();
        }
        else if (pad.equals("PKCS1PADDING"))
        {
            cipher = new PKCS1Encoding(new ElGamalEngine());
        }
        else if (pad.equals("ISO9796-1PADDING"))
        {
            cipher = new ISO9796d1Encoding(new ElGamalEngine());
        }
        else if (pad.equals("OAEPPADDING"))
        {
            initFromSpec(OAEPParameterSpec.DEFAULT);
        }
        else if (pad.equals("OAEPWITHMD5ANDMGF1PADDING"))
        {
            initFromSpec(new OAEPParameterSpec("MD5", "MGF1", new MGF1ParameterSpec("MD5"), PSource.PSpecified.DEFAULT));
        }
        else if (pad.equals("OAEPWITHSHA1ANDMGF1PADDING"))
        {
            initFromSpec(OAEPParameterSpec.DEFAULT);
        }
        else if (pad.equals("OAEPWITHSHA224ANDMGF1PADDING"))
        {
            initFromSpec(new OAEPParameterSpec("SHA-224", "MGF1", new MGF1ParameterSpec("SHA-224"), PSource.PSpecified.DEFAULT));
        }
        else if (pad.equals("OAEPWITHSHA256ANDMGF1PADDING"))
        {
            initFromSpec(new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
        }
        else if (pad.equals("OAEPWITHSHA384ANDMGF1PADDING"))
        {
            initFromSpec(new OAEPParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, PSource.PSpecified.DEFAULT));
        }
        else if (pad.equals("OAEPWITHSHA512ANDMGF1PADDING"))
        {
            initFromSpec(new OAEPParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, PSource.PSpecified.DEFAULT));
        }
        else if (pad.equals("OAEPWITHSHA3-224ANDMGF1PADDING"))
        {
            initFromSpec(new OAEPParameterSpec("SHA3-224", "MGF1", new MGF1ParameterSpec("SHA3-224"), PSource.PSpecified.DEFAULT));
        }
        else if (pad.equals("OAEPWITHSHA3-256ANDMGF1PADDING"))
        {
            initFromSpec(new OAEPParameterSpec("SHA3-256", "MGF1", new MGF1ParameterSpec("SHA3-256"), PSource.PSpecified.DEFAULT));
        }
        else if (pad.equals("OAEPWITHSHA3-384ANDMGF1PADDING"))
        {
            initFromSpec(new OAEPParameterSpec("SHA3-384", "MGF1", new MGF1ParameterSpec("SHA3-384"), PSource.PSpecified.DEFAULT));
        }
        else if (pad.equals("OAEPWITHSHA3-512ANDMGF1PADDING"))
        {
            initFromSpec(new OAEPParameterSpec("SHA3-512", "MGF1", new MGF1ParameterSpec("SHA3-512"), PSource.PSpecified.DEFAULT));
        }
        else
        {
            throw new NoSuchPaddingException(padding + " unavailable with ElGamal.");
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

        if (key instanceof DHPublicKey)
        {
            param = ElGamalUtil.generatePublicKeyParameter((PublicKey)key);
        }
        else if (key instanceof DHPrivateKey)
        {
            param = ElGamalUtil.generatePrivateKeyParameter((PrivateKey)key);
        }
        else
        {
            throw new InvalidKeyException("unknown key type passed to ElGamal");
        }

        if (params instanceof OAEPParameterSpec)
        {
            OAEPParameterSpec spec = (OAEPParameterSpec)params;

            paramSpec = params;

            if (!spec.getMGFAlgorithm().equalsIgnoreCase("MGF1") && !spec.getMGFAlgorithm().equals(PKCSObjectIdentifiers.id_mgf1.getId()))
            {
                throw new InvalidAlgorithmParameterException("unknown mask generation function specified");
            }

            if (!(spec.getMGFParameters() instanceof MGF1ParameterSpec))
            {
                throw new InvalidAlgorithmParameterException("unkown MGF parameters");
            }

            Digest digest = DigestFactory.getDigest(spec.getDigestAlgorithm());

            if (digest == null)
            {
                throw new InvalidAlgorithmParameterException("no match on digest algorithm: "+ spec.getDigestAlgorithm());
            }

            MGF1ParameterSpec mgfParams = (MGF1ParameterSpec)spec.getMGFParameters();
            Digest mgfDigest = DigestFactory.getDigest(mgfParams.getDigestAlgorithm());

            if (mgfDigest == null)
            {
                throw new InvalidAlgorithmParameterException("no match on MGF digest algorithm: "+ mgfParams.getDigestAlgorithm());
            }

            cipher = new OAEPEncoding(new ElGamalEngine(), digest, mgfDigest, ((PSource.PSpecified)spec.getPSource()).getValue());
        }
        else if (params != null)
        {
            throw new InvalidAlgorithmParameterException("unknown parameter type.");
        }

        if (random != null)
        {
            param = new ParametersWithRandom(param, random);
        }

        switch (opmode)
        {
        case javax.crypto.Cipher.ENCRYPT_MODE:
        case javax.crypto.Cipher.WRAP_MODE:
            cipher.init(true, param);
            break;
        case javax.crypto.Cipher.DECRYPT_MODE:
        case javax.crypto.Cipher.UNWRAP_MODE:
            cipher.init(false, param);
            break;
        default:
            throw new InvalidParameterException("unknown opmode " + opmode + " passed to ElGamal");
        }
    }

    protected void engineInit(
        int                 opmode,
        Key                 key,
        AlgorithmParameters params,
        SecureRandom        random) 
    throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        throw new InvalidAlgorithmParameterException("can't handle parameters in ElGamal");
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
            // this shouldn't happen
            throw new InvalidKeyException("Eeeek! " + e.toString(), e);
        }
    }

    protected byte[] engineUpdate(
        byte[]  input,
        int     inputOffset,
        int     inputLen) 
    {
        bOut.write(input, inputOffset, inputLen);
        return null;
    }

    protected int engineUpdate(
        byte[]  input,
        int     inputOffset,
        int     inputLen,
        byte[]  output,
        int     outputOffset) 
    {
        bOut.write(input, inputOffset, inputLen);
        return 0;
    }


    protected byte[] engineDoFinal(
        byte[]  input,
        int     inputOffset,
        int     inputLen)
        throws IllegalBlockSizeException, BadPaddingException
    {
        if (input != null)
        {
            bOut.write(input, inputOffset, inputLen);
        }

        if (cipher instanceof ElGamalEngine)
        {
            if (bOut.size() > cipher.getInputBlockSize() + 1)
            {
                throw new ArrayIndexOutOfBoundsException("too much data for ElGamal block");
            }
        }
        else
        {
            if (bOut.size() > cipher.getInputBlockSize())
            {
                throw new ArrayIndexOutOfBoundsException("too much data for ElGamal block");
            }
        }

        return getOutput();
    }

    protected int engineDoFinal(
        byte[]  input,
        int     inputOffset,
        int     inputLen,
        byte[]  output,
        int     outputOffset)
        throws IllegalBlockSizeException, BadPaddingException, ShortBufferException
    {
        if (outputOffset + engineGetOutputSize(inputLen) > output.length)
        {
            throw new ShortBufferException("output buffer too short for input.");
        }

        if (input != null)
        {
            bOut.write(input, inputOffset, inputLen);
        }

        if (cipher instanceof ElGamalEngine)
        {
            if (bOut.size() > cipher.getInputBlockSize() + 1)
            {
                throw new ArrayIndexOutOfBoundsException("too much data for ElGamal block");
            }
        }
        else
        {
            if (bOut.size() > cipher.getInputBlockSize())
            {
                throw new ArrayIndexOutOfBoundsException("too much data for ElGamal block");
            }
        }

        byte[]  out = getOutput();

        for (int i = 0; i != out.length; i++)
        {
            output[outputOffset + i] = out[i];
        }

        return out.length;
    }

    private byte[] getOutput()
        throws BadPaddingException
    {
        try
        {
            return cipher.processBlock(bOut.getBuf(), 0, bOut.size());
        }
        catch (InvalidCipherTextException e)
        {
            throw new BadBlockException("unable to decrypt block", e);
        }
        catch (ArrayIndexOutOfBoundsException e)
        {
            throw new BadBlockException("unable to decrypt block", e);
        }
        finally
        {
            bOut.erase();
        }
    }

    /**
     * classes that inherit from us.
     */
    static public class NoPadding
        extends CipherSpi
    {
        public NoPadding()
        {
            super(new ElGamalEngine());
        }
    }
    
    static public class PKCS1v1_5Padding
        extends CipherSpi
    {
        public PKCS1v1_5Padding()
        {
            super(new PKCS1Encoding(new ElGamalEngine()));
        }
    }
}
