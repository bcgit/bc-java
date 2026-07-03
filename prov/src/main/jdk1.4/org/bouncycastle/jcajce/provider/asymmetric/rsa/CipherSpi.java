package org.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.encodings.ISO9796d1Encoding;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.tls.TlsRsaKeyExchange;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseCipherSpi;
import org.bouncycastle.jcajce.provider.util.BadBlockException;
import org.bouncycastle.jcajce.spec.TLSRSAPremasterSecretParameterSpec;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.util.Strings;

public class CipherSpi
    extends BaseCipherSpi
{
    private final JcaJceHelper helper = new BCJcaJceHelper();

    private AsymmetricBlockCipher   cipher;
    private AlgorithmParameterSpec  paramSpec;
    private AlgorithmParameters     engineParams;
    private boolean                 publicKeyOnly = false;
    private boolean                 privateKeyOnly = false;
    private ErasableOutputStream    bOut = new ErasableOutputStream();
    private TLSRSAPremasterSecretParameterSpec tlsRsaSpec = null;
    private CipherParameters param = null;

    public CipherSpi(
        AsymmetricBlockCipher engine)
    {
        cipher = engine;
    }

    public CipherSpi(
        boolean publicKeyOnly,
        boolean privateKeyOnly,
        AsymmetricBlockCipher engine)
    {
        this.publicKeyOnly = publicKeyOnly;
        this.privateKeyOnly = privateKeyOnly;
        cipher = engine;
    }

    protected int engineGetBlockSize()
    {
        try
        {
            return cipher.getInputBlockSize();
        }
        catch (NullPointerException e)
        {
            throw Exceptions.illegalStateException("RSA Cipher not initialised", e);
        }
    }

    protected int engineGetKeySize(
        Key key)
    {
        if (key instanceof RSAPrivateKey)
        {
            RSAPrivateKey k = (RSAPrivateKey)key;

            return k.getModulus().bitLength();
        }
        else if (key instanceof RSAPublicKey)
        {
            RSAPublicKey k = (RSAPublicKey)key;

            return k.getModulus().bitLength();
        }

        throw new IllegalArgumentException("not an RSA key!");
    }

    protected int engineGetOutputSize(
        int     inputLen)
    {
        if (tlsRsaSpec != null)
        {
            return TlsRsaKeyExchange.PRE_MASTER_SECRET_LENGTH;
        }

        try
        {
            return cipher.getOutputBlockSize();
        }
        catch (NullPointerException e)
        {
            throw Exceptions.illegalStateException("RSA Cipher not initialised", e);
        }
    }

    protected AlgorithmParameters engineGetParameters()
    {
        if (engineParams == null)
        {
            if (paramSpec != null)
            {
                try
                {
                    engineParams = helper.createAlgorithmParameters("OAEP");
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
        String mode)
        throws NoSuchAlgorithmException
    {
        String md = Strings.toUpperCase(mode);

        if (md.equals("NONE") || md.equals("ECB"))
        {
            return;
        }

        if (md.equals("1"))
        {
            privateKeyOnly = true;
            publicKeyOnly = false;
            return;
        }
        else if (md.equals("2"))
        {
            privateKeyOnly = false;
            publicKeyOnly = true;
            return;
        }

        throw new NoSuchAlgorithmException("can't support mode " + mode);
    }

    protected void engineSetPadding(
        String padding)
        throws NoSuchPaddingException
    {
        String pad = Strings.toUpperCase(padding);

        if (pad.equals("NOPADDING"))
        {
            cipher = new RSABlindedEngine();
        }
        else if (pad.equals("PKCS1PADDING"))
        {
            cipher = new CustomPKCS1Encoding(new RSABlindedEngine());
        }
        else if (pad.equals("ISO9796-1PADDING"))
        {
            cipher = new ISO9796d1Encoding(new RSABlindedEngine());
        }
        else if (pad.equals("OAEPPADDING"))
        {
            cipher = new OAEPEncoding(new RSABlindedEngine());
        }
        else if (pad.equals("OAEPWITHSHA1ANDMGF1PADDING") || pad.equals("OAEPWITHSHA-1ANDMGF1PADDING"))
        {
            cipher = new OAEPEncoding(new RSABlindedEngine());
        }
        else if (pad.equals("OAEPWITHSHA224ANDMGF1PADDING") || pad.equals("OAEPWITHSHA-224ANDMGF1PADDING"))
        {
            cipher = new OAEPEncoding(new RSABlindedEngine(), new SHA224Digest());
        }
        else if (pad.equals("OAEPWITHSHA256ANDMGF1PADDING") || pad.equals("OAEPWITHSHA-256ANDMGF1PADDING"))
        {
            cipher = new OAEPEncoding(new RSABlindedEngine(), new SHA256Digest());
        }
        else if (pad.equals("OAEPWITHSHA384ANDMGF1PADDING") || pad.equals("OAEPWITHSHA-384ANDMGF1PADDING"))
        {
            cipher = new OAEPEncoding(new RSABlindedEngine(), new SHA384Digest());
        }
        else if (pad.equals("OAEPWITHSHA512ANDMGF1PADDING") || pad.equals("OAEPWITHSHA-512ANDMGF1PADDING"))
        {
            cipher = new OAEPEncoding(new RSABlindedEngine(), new SHA512Digest());
        }
        else if (pad.equals("OAEPWITHMD5ANDMGF1PADDING"))
        {
            cipher = new OAEPEncoding(new RSABlindedEngine(), new MD5Digest());
        }
        else
        {
            throw new NoSuchPaddingException(padding + " unavailable with RSA.");
        }
    }

    protected void engineInit(
        int                     opmode,
        Key key,
        AlgorithmParameterSpec params,
        SecureRandom random)
    throws InvalidKeyException, InvalidAlgorithmParameterException
    {

        this.tlsRsaSpec = null;

        if (params == null
            || params instanceof TLSRSAPremasterSecretParameterSpec)
        {
            if (key instanceof RSAPublicKey)
            {
                if (privateKeyOnly && opmode == Cipher.ENCRYPT_MODE)
                {
                    throw new InvalidKeyException(
                                "mode 1 requires RSAPrivateKey");
                }

                param = RSAUtil.generatePublicKeyParameter((RSAPublicKey)key);
            }
            else if (key instanceof RSAPrivateKey)
            {
                if (publicKeyOnly && opmode == Cipher.ENCRYPT_MODE)
                {
                    throw new InvalidKeyException(
                                "mode 2 requires RSAPublicKey");
                }

                param = RSAUtil.generatePrivateKeyParameter((RSAPrivateKey)key);
            }
            else
            {
                throw new InvalidKeyException("unknown key type passed to RSA");
            }

            if (params instanceof TLSRSAPremasterSecretParameterSpec)
            {
                // TODO Restrict mode to DECRYPT_MODE (and/or UNWRAP_MODE)
                if (!(param instanceof RSAKeyParameters) || !((RSAKeyParameters)param).isPrivate())
                {
                    throw new InvalidKeyException("RSA private key required for TLS decryption");
                }

                this.tlsRsaSpec = (TLSRSAPremasterSecretParameterSpec)params;
            }
        }
        else
        {
            throw new InvalidAlgorithmParameterException("unknown parameter type: " + params.getClass().getName());
        }

        if (random != null)
        {
            param = new ParametersWithRandom(param, random);
        }
        else
        {
            // TODO Remove after checking all AsymmetricBlockCipher init methods?
            param = new ParametersWithRandom(param, CryptoServicesRegistrar.getSecureRandom());
        }

        bOut.reset();

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
            throw new InvalidParameterException("unknown opmode " + opmode + " passed to RSA");
        }
    }

    protected void engineInit(
        int                 opmode,
        Key key,
        AlgorithmParameters params,
        SecureRandom random)
    throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        AlgorithmParameterSpec paramSpec = null;

        if (params != null)
        {
            throw new InvalidAlgorithmParameterException("cannot recognise parameters.");
        }

        engineParams = params;
        engineInit(opmode, key, paramSpec, random);
    }

    protected void engineInit(
        int                 opmode,
        Key key,
        SecureRandom random)
    throws InvalidKeyException
    {
        try
        {
            engineInit(opmode, key, (AlgorithmParameterSpec)null, random);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            // this shouldn't happen
            throw new InvalidKeyException("Eeeek! " + e.toString());
        }
    }

    protected byte[] engineUpdate(
        byte[]  input,
        int     inputOffset,
        int     inputLen)
    {
        if (inputLen > getInputLimit() - bOut.size())
        {
            throw new ArrayIndexOutOfBoundsException("too much data for RSA block");
        }

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
        engineUpdate(input, inputOffset, inputLen);
        return 0;
    }

    protected byte[] engineDoFinal(
        byte[]  input,
        int     inputOffset,
        int     inputLen)
        throws IllegalBlockSizeException, BadPaddingException
    {
        // TODO Can input actually be null?
        if (input != null)
        {
            engineUpdate(input, inputOffset, inputLen);
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
        // TODO Can input actually be null?
        int outputSize = engineGetOutputSize(input == null ? 0 : inputLen);
        if (outputOffset > output.length - outputSize)
        {
            throw new ShortBufferException("output buffer too short for input.");
        }

        byte[] out = engineDoFinal(input, inputOffset, inputLen);
        System.arraycopy(out, 0, output, outputOffset, out.length);
        return out.length;
    }

    private int getInputLimit()
    {
        if (tlsRsaSpec != null)
        {
            ParametersWithRandom pWithR = (ParametersWithRandom)param;
            return TlsRsaKeyExchange.getInputLimit((RSAKeyParameters)pWithR.getParameters());
        }
        else if (cipher instanceof RSABlindedEngine)
        {
            return cipher.getInputBlockSize() + 1;
        }
        else
        {
            return cipher.getInputBlockSize();
        }
    }

    private byte[] getOutput()
        throws BadPaddingException
    {
        try
        {
            if (tlsRsaSpec != null)
            {
                ParametersWithRandom pWithR = (ParametersWithRandom)param;
                return TlsRsaKeyExchange.decryptPreMasterSecret(bOut.getBuf(), 0, bOut.size(),
                    (RSAKeyParameters)pWithR.getParameters(), tlsRsaSpec.getProtocolVersion(), pWithR.getRandom());
            }

            byte[] output;
            try
            {
                output = cipher.processBlock(bOut.getBuf(), 0, bOut.size());
            }
            catch (InvalidCipherTextException e)
            {
                throw new BadBlockException("unable to decrypt block", e);
            }
            catch (ArrayIndexOutOfBoundsException e)
            {
                throw new BadBlockException("unable to decrypt block", e);
            }

            if (output == null)
            {
                throw new BadBlockException("unable to decrypt block", null);
            }

            return output;
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
            super(new RSABlindedEngine());
        }
    }

    static public class PKCS1v1_5Padding
        extends CipherSpi
    {
        public PKCS1v1_5Padding()
        {
            super(new CustomPKCS1Encoding(new RSABlindedEngine()));
        }
    }

    static public class PKCS1v1_5Padding_PrivateOnly
        extends CipherSpi
    {
        public PKCS1v1_5Padding_PrivateOnly()
        {
            super(false, true, new CustomPKCS1Encoding(new RSABlindedEngine()));
        }
    }

    static public class PKCS1v1_5Padding_PublicOnly
        extends CipherSpi
    {
        public PKCS1v1_5Padding_PublicOnly()
        {
            super(true, false, new CustomPKCS1Encoding(new RSABlindedEngine()));
        }
    }

    static public class OAEPPadding
        extends CipherSpi
    {
        public OAEPPadding()
        {
            super(new OAEPEncoding(new RSABlindedEngine()));
        }
    }

    static public class ISO9796d1Padding
        extends CipherSpi
    {
        public ISO9796d1Padding()
        {
            super(new ISO9796d1Encoding(new RSABlindedEngine()));
        }
    }
}
