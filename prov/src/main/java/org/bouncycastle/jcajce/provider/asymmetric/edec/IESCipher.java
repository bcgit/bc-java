package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyEncoder;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.agreement.XDHBasicAgreement;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.IESEngine;
import org.bouncycastle.crypto.generators.EphemeralKeyPairGenerator;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.X448KeyPairGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.IESWithCipherParameters;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.crypto.parsers.XIESPublicKeyParser;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.jcajce.interfaces.XDHKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseCipherSpi;
import org.bouncycastle.jcajce.provider.asymmetric.util.IESUtil;
import org.bouncycastle.jcajce.provider.util.BadBlockException;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.Strings;

public class IESCipher
    extends BaseCipherSpi
{
    private final JcaJceHelper helper = new BCJcaJceHelper();

    private int ivLength;
    private IESEngine engine;
    private int state = -1;
    private ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private AlgorithmParameters engineParam = null;
    private IESParameterSpec engineSpec = null;
    private AsymmetricKeyParameter key;
    private SecureRandom random;
    private boolean dhaesMode = false;
    private AsymmetricKeyParameter otherKeyParameter = null;

    public IESCipher(IESEngine engine)
    {
        this.engine = engine;
        this.ivLength = 0;
    }

    public IESCipher(IESEngine engine, int ivLength)
    {
        this.engine = engine;
        this.ivLength = ivLength;
    }

    public int engineGetBlockSize()
    {
        BufferedBlockCipher cipher = engine.getCipher();
        return cipher == null ? 0 : cipher.getBlockSize();
    }

    public int engineGetKeySize(Key key)
    {
        if (key instanceof XDHKey)
        {
            String algorithm = ((XDHKey)key).getAlgorithm();
            if ("X25519".equalsIgnoreCase(algorithm))
            {
                return 256;
            }
            else if ("X448".equalsIgnoreCase(algorithm))
            {
                return 448;
            }
            else
            {
                throw new IllegalArgumentException("unknown XDH key algorithm " + algorithm);
            }
        }
        else
        {
            throw new IllegalArgumentException("not an XDH key");
        }
    }

    public byte[] engineGetIV()
    {
        if (engineSpec != null)
        {
            return engineSpec.getNonce();
        }
        return null;
    }

    public AlgorithmParameters engineGetParameters()
    {
        if (engineParam == null && engineSpec != null)
        {
            try
            {
                engineParam = helper.createAlgorithmParameters("IES");
                engineParam.init(engineSpec);
            }
            catch (Exception e)
            {
                throw new RuntimeException(e.toString());
            }
        }

        return engineParam;
    }


    public void engineSetMode(String mode)
        throws NoSuchAlgorithmException
    {
        String modeName = Strings.toUpperCase(mode);

        if (modeName.equals("NONE"))
        {
            dhaesMode = false;
        }
        else if (modeName.equals("DHAES"))
        {
            dhaesMode = true;
        }
        else
        {
            throw new IllegalArgumentException("can't support mode " + mode);
        }
    }


    public int engineGetOutputSize(int inputLen)
    {
        int len1, len2, len3;

        if (key == null)
        {
            throw new IllegalStateException("cipher not initialised");
        }

        len1 = engine.getMac().getMacSize();

        if (otherKeyParameter == null)
        {
            ECCurve c = ((ECKeyParameters)key).getParameters().getCurve();
            int feSize = (c.getFieldSize() + 7) / 8;
            len2 = 2 * feSize;
        }
        else
        {
            len2 = 0;
        }

        int inLen = buffer.size() + inputLen;
        if (engine.getCipher() == null)
        {
            len3 = inLen;
        }
        else if (state == Cipher.ENCRYPT_MODE || state == Cipher.WRAP_MODE)
        {
            len3 = engine.getCipher().getOutputSize(inLen);
        }
        else if (state == Cipher.DECRYPT_MODE || state == Cipher.UNWRAP_MODE)
        {
            len3 = engine.getCipher().getOutputSize(inLen - len1 - len2);
        }
        else
        {
            throw new IllegalStateException("cipher not initialised");
        }

        if (state == Cipher.ENCRYPT_MODE || state == Cipher.WRAP_MODE)
        {
            return len1 + len2 + len3;
        }
        else if (state == Cipher.DECRYPT_MODE || state == Cipher.UNWRAP_MODE)
        {
            return len3;
        }
        else
        {
            throw new IllegalStateException("cipher not initialised");
        }
    }

    public void engineSetPadding(String padding)
        throws NoSuchPaddingException
    {
        String paddingName = Strings.toUpperCase(padding);

        // TDOD: make this meaningful...
        if (paddingName.equals("NOPADDING"))
        {

        }
        else if (paddingName.equals("PKCS5PADDING") || paddingName.equals("PKCS7PADDING"))
        {

        }
        else
        {
            throw new NoSuchPaddingException("padding not available with IESCipher");
        }
    }


    // Initialisation methods

    public void engineInit(
        int opmode,
        Key key,
        AlgorithmParameters params,
        SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        AlgorithmParameterSpec paramSpec = null;

        if (params != null)
        {
            try
            {
                paramSpec = params.getParameterSpec(IESParameterSpec.class);
            }
            catch (Exception e)
            {
                throw new InvalidAlgorithmParameterException("cannot recognise parameters: " + e.toString());
            }
        }

        engineParam = params;
        engineInit(opmode, key, paramSpec, random);

    }


    public void engineInit(
        int opmode,
        Key key,
        AlgorithmParameterSpec engineSpec,
        SecureRandom random)
        throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        otherKeyParameter = null;

        // NOTE: For secure usage, sender and receiver should agree on a fixed value for the nonce.
        if (engineSpec == null && ivLength == 0)
        {
            this.engineSpec = IESUtil.guessParameterSpec(engine.getCipher(), null);
        }
        else if (engineSpec instanceof IESParameterSpec)
        {
            this.engineSpec = (IESParameterSpec)engineSpec;
        }
        else
        {
            throw new InvalidAlgorithmParameterException("must be passed IES parameters");
        }

        byte[] nonce = this.engineSpec.getNonce();

        if (ivLength != 0 && (nonce == null || nonce.length != ivLength))
        {
            throw new InvalidAlgorithmParameterException("NONCE in IES Parameters needs to be " + ivLength + " bytes long");
        }

        // Parse the recipient's key
        if (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE)
        {
            if (key instanceof PublicKey)
            {
                this.key = EdECUtil.generatePublicKeyParameter((PublicKey)key);
            }
            else
            {
                throw new InvalidKeyException("must be passed recipient's public XDH key for encryption");
            }
        }
        else if (opmode == Cipher.DECRYPT_MODE || opmode == Cipher.UNWRAP_MODE)
        {
            if (key instanceof PrivateKey)
            {
                this.key = EdECUtil.generatePrivateKeyParameter((PrivateKey)key);
            }
            else
            {
                throw new InvalidKeyException("must be passed recipient's private XDH key for decryption");
            }
        }
        else
        {
            throw new InvalidKeyException("must be passed XDH key");
        }


        this.random = random;
        this.state = opmode;
        buffer.reset();

    }


    public void engineInit(
        int opmode,
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
            throw new IllegalArgumentException("cannot handle supplied parameter spec: " + e.getMessage());
        }

    }


    // Update methods - buffer the input

    public byte[] engineUpdate(
        byte[] input,
        int inputOffset,
        int inputLen)
    {
        buffer.write(input, inputOffset, inputLen);
        return null;
    }


    public int engineUpdate(
        byte[] input,
        int inputOffset,
        int inputLen,
        byte[] output,
        int outputOffset)
    {
        buffer.write(input, inputOffset, inputLen);
        return 0;
    }


    // Finalisation methods

    public byte[] engineDoFinal(
        byte[] input,
        int inputOffset,
        int inputLen)
        throws IllegalBlockSizeException, BadPaddingException
    {
        if (inputLen != 0)
        {
            buffer.write(input, inputOffset, inputLen);
        }

        final byte[] in = buffer.toByteArray();
        buffer.reset();

        // Convert parameters for use in IESEngine
        CipherParameters params = new IESWithCipherParameters(engineSpec.getDerivationV(),
            engineSpec.getEncodingV(),
            engineSpec.getMacKeySize(),
            engineSpec.getCipherKeySize());

        byte[] engineSpecNonce = engineSpec.getNonce();
        if (engineSpecNonce != null)
        {
            params = new ParametersWithIV(params, engineSpecNonce);
        }

        if (otherKeyParameter != null)
        {
            try
            {
                if (state == Cipher.ENCRYPT_MODE || state == Cipher.WRAP_MODE)
                {
                    engine.init(true, otherKeyParameter, key, params);
                }
                else
                {
                    engine.init(false, key, otherKeyParameter, params);
                }
                return engine.processBlock(in, 0, in.length);
            }
            catch (Exception e)
            {
                throw new BadBlockException("unable to process block", e);
            }
        }

        final boolean isX25519 = key instanceof X25519PublicKeyParameters || key instanceof X25519PrivateKeyParameters;
        final int fieldSize = isX25519 ? 256 : 448;

        if (state == Cipher.ENCRYPT_MODE || state == Cipher.WRAP_MODE)
        {
            // Generate the ephemeral key pair - cast due to JVM compatibility
            AsymmetricCipherKeyPairGenerator kpGen = isX25519 ? (AsymmetricCipherKeyPairGenerator)new X25519KeyPairGenerator() : (AsymmetricCipherKeyPairGenerator)new X448KeyPairGenerator();
            kpGen.init(new KeyGenerationParameters(random, fieldSize));
            EphemeralKeyPairGenerator epKpGen = new EphemeralKeyPairGenerator(kpGen, new KeyEncoder()
            {
                public byte[] getEncoded(AsymmetricKeyParameter keyParameter)
                {
                    return isX25519 ? ((X25519PublicKeyParameters)keyParameter).getEncoded()
                        : ((X448PublicKeyParameters)keyParameter).getEncoded();
                }
            });

            // Encrypt the buffer
            try
            {
                engine.init(key, params, epKpGen);

                return engine.processBlock(in, 0, in.length);
            }
            catch (final Exception e)
            {
                throw new BadBlockException("unable to process block", e);
            }
        }
        else if (state == Cipher.DECRYPT_MODE || state == Cipher.UNWRAP_MODE)
        {
            // Decrypt the buffer
            try
            {
                engine.init(key, params, new XIESPublicKeyParser(isX25519));

                return engine.processBlock(in, 0, in.length);
            }
            catch (InvalidCipherTextException e)
            {
                throw new BadBlockException("unable to process block", e);
            }
        }
        else
        {
            throw new IllegalStateException("cipher not initialised");
        }

    }

    public int engineDoFinal(
        byte[] input,
        int inputOffset,
        int inputLength,
        byte[] output,
        int outputOffset)
        throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
    {

        byte[] buf = engineDoFinal(input, inputOffset, inputLength);

        System.arraycopy(buf, 0, output, outputOffset, buf.length);
        return buf.length;
    }

    /**
     * Classes that inherit from us
     */

    static public class XIES
        extends IESCipher
    {
        public XIES()
        {
            this(DigestFactory.createSHA1(), DigestFactory.createSHA1());
        }

        public XIES(Digest kdfDigest, Digest macDigest)
        {
            super(new IESEngine(new XDHBasicAgreement(),
                new KDF2BytesGenerator(kdfDigest),
                new HMac(macDigest)));
        }
    }

    static public class XIESwithSHA256
        extends XIES
    {
        public XIESwithSHA256()
        {
            super(DigestFactory.createSHA256(), DigestFactory.createSHA256());
        }
    }

    static public class XIESwithSHA384
        extends XIES
    {
        public XIESwithSHA384()
        {
            super(DigestFactory.createSHA384(), DigestFactory.createSHA384());
        }
    }

    static public class XIESwithSHA512
        extends XIES
    {
        public XIESwithSHA512()
        {
            super(DigestFactory.createSHA512(), DigestFactory.createSHA512());
        }
    }

    static public class XIESwithCipher
        extends IESCipher
    {
        public XIESwithCipher(BlockCipher cipher, int ivLength)
        {
            this(cipher, ivLength, DigestFactory.createSHA1(), DigestFactory.createSHA1());
        }

        public XIESwithCipher(BlockCipher cipher, int ivLength, Digest kdfDigest, Digest macDigest)
        {
            super(new IESEngine(new XDHBasicAgreement(),
                new KDF2BytesGenerator(kdfDigest),
                new HMac(macDigest),
                new PaddedBufferedBlockCipher(cipher)), ivLength);
        }
    }

    static public class XIESwithDESedeCBC
        extends XIESwithCipher
    {
        public XIESwithDESedeCBC()
        {
            super(CBCBlockCipher.newInstance(new DESedeEngine()), 8);
        }
    }

    static public class XIESwithSHA256andDESedeCBC
        extends XIESwithCipher
    {
        public XIESwithSHA256andDESedeCBC()
        {
            super(CBCBlockCipher.newInstance(new DESedeEngine()), 8, DigestFactory.createSHA256(), DigestFactory.createSHA256());
        }
    }

    static public class XIESwithSHA384andDESedeCBC
        extends XIESwithCipher
    {
        public XIESwithSHA384andDESedeCBC()
        {
            super(CBCBlockCipher.newInstance(new DESedeEngine()), 8, DigestFactory.createSHA384(), DigestFactory.createSHA384());
        }
    }

    static public class XIESwithSHA512andDESedeCBC
        extends XIESwithCipher
    {
        public XIESwithSHA512andDESedeCBC()
        {
            super(CBCBlockCipher.newInstance(new DESedeEngine()), 8, DigestFactory.createSHA512(), DigestFactory.createSHA512());
        }
    }

    static public class XIESwithAESCBC
        extends XIESwithCipher
    {
        public XIESwithAESCBC()
        {
            super(CBCBlockCipher.newInstance(AESEngine.newInstance()), 16);
        }
    }

    static public class XIESwithSHA256andAESCBC
        extends XIESwithCipher
    {
        public XIESwithSHA256andAESCBC()
        {
            super(CBCBlockCipher.newInstance(AESEngine.newInstance()), 16, DigestFactory.createSHA256(), DigestFactory.createSHA256());
        }
    }

    static public class XIESwithSHA384andAESCBC
        extends XIESwithCipher
    {
        public XIESwithSHA384andAESCBC()
        {
            super(CBCBlockCipher.newInstance(AESEngine.newInstance()), 16, DigestFactory.createSHA384(), DigestFactory.createSHA384());
        }
    }

    static public class XIESwithSHA512andAESCBC
        extends XIESwithCipher
    {
        public XIESwithSHA512andAESCBC()
        {
            super(CBCBlockCipher.newInstance(AESEngine.newInstance()), 16, DigestFactory.createSHA512(), DigestFactory.createSHA512());
        }
    }
}