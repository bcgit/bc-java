package org.bouncycastle.jcajce.provider.asymmetric.ec;

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

import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.EphemeralKeyPair;
import org.bouncycastle.crypto.KeyEncoder;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.agreement.ECDHCBasicAgreement;
import org.bouncycastle.crypto.engines.IESEngine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.EphemeralKeyPairGenerator;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseCipherSpi;
import org.bouncycastle.jcajce.spec.IESKEMParameterSpec;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jce.interfaces.ECKey;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

public class IESKEMCipher
    extends BaseCipherSpi
{
    private static final X9IntegerConverter converter = new X9IntegerConverter();

    private final JcaJceHelper helper = new BCJcaJceHelper();
    private final ECDHCBasicAgreement agreement;
    private final KDF2BytesGenerator kdf;
    private final Mac hMac;
    private final int macKeyLength;
    private final int macLength;

    private int ivLength;
    private IESEngine engine;
    private int state = -1;
    private ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private AlgorithmParameters engineParam = null;
    private IESKEMParameterSpec engineSpec = null;
    private AsymmetricKeyParameter key;
    private SecureRandom random;
    private boolean dhaesMode = false;
    private AsymmetricKeyParameter otherKeyParameter = null;

    public IESKEMCipher(ECDHCBasicAgreement agreement, KDF2BytesGenerator kdf, Mac hMac, int macKeyLength, int macLength)
    {
        this.agreement = agreement;
        this.kdf = kdf;
        this.hMac = hMac;
        this.macKeyLength = macKeyLength;
        this.macLength = macLength;
    }

    public int engineGetBlockSize()
    {
        return 0;
    }


    public int engineGetKeySize(Key key)
    {
        if (key instanceof ECKey)
        {
            return ((ECKey)key).getParameters().getCurve().getFieldSize();
        }
        else
        {
            throw new IllegalArgumentException("not an EC key");
        }
    }


    public byte[] engineGetIV()
    {
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
        throw new NoSuchAlgorithmException("can't support mode " + mode);
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
        throw new NoSuchPaddingException("padding not available with IESCipher");
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
        this.engineSpec = (IESKEMParameterSpec)engineSpec;
        // Parse the recipient's key
        if (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE)
        {
            if (key instanceof PublicKey)
            {
                this.key = ECUtils.generatePublicKeyParameter((PublicKey)key);
            }
            else
            {
                throw new InvalidKeyException("must be passed recipient's public EC key for encryption");
            }
        }
        else if (opmode == Cipher.DECRYPT_MODE || opmode == Cipher.UNWRAP_MODE)
        {
            if (key instanceof PrivateKey)
            {
                this.key = ECUtils.generatePrivateKeyParameter((PrivateKey)key);
            }
            else
            {
                throw new InvalidKeyException("must be passed recipient's private EC key for decryption");
            }
        }
        else
        {
            throw new InvalidKeyException("must be passed EC key");
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

        final ECDomainParameters ecParams = ((ECKeyParameters)key).getParameters();

        if (state == Cipher.ENCRYPT_MODE || state == Cipher.WRAP_MODE)
        {
            // Generate the ephemeral key pair
            ECKeyPairGenerator gen = new ECKeyPairGenerator();
            gen.init(new ECKeyGenerationParameters(ecParams, random));

            final boolean usePointCompression = engineSpec.hasUsePointCompression();
            EphemeralKeyPairGenerator kGen = new EphemeralKeyPairGenerator(gen, new KeyEncoder()
            {
                public byte[] getEncoded(AsymmetricKeyParameter keyParameter)
                {
                    return ((ECPublicKeyParameters)keyParameter).getQ().getEncoded(usePointCompression);
                }
            });

            EphemeralKeyPair kp = kGen.generate();

            agreement.init(kp.getKeyPair().getPrivate());

            byte[] secret = converter.integerToBytes(agreement.calculateAgreement(key), converter.getByteLength(ecParams.getCurve()));
            byte[] out = new byte[inputLen + macKeyLength];

            kdf.init(new KDFParameters(secret, engineSpec.getRecipientInfo()));

            kdf.generateBytes(out, 0, out.length);

            byte[] enc = new byte[inputLen + macLength];
            for (int i = 0; i != inputLen; i++)
            {
                enc[i] = (byte)(input[inputOffset + i] ^ out[i]);
            }

            KeyParameter macKey = new KeyParameter(out, inputLen, out.length - inputLen);
            hMac.init(macKey);

            hMac.update(enc, 0, inputLen);

            byte[] mac = new byte[hMac.getMacSize()];

            hMac.doFinal(mac, 0);

            Arrays.clear(macKey.getKey());
            Arrays.clear(out);

            System.arraycopy(mac, 0, enc, inputLen, macLength);

            return Arrays.concatenate(kp.getEncodedPublicKey(), enc);
        }
        else if (state == Cipher.DECRYPT_MODE || state == Cipher.UNWRAP_MODE)
        {
            ECPrivateKeyParameters k = (ECPrivateKeyParameters)key;
            ECCurve curve = k.getParameters().getCurve();

            int pEncLength = (curve.getFieldSize() + 7) / 8;
            if (input[inputOffset] == 0x04)
            {
                pEncLength = 1 + 2 * pEncLength;
            }
            else
            {
                pEncLength = 1 + pEncLength;
            }

            int keyLength = inputLen - (pEncLength + macLength);

            ECPoint q = curve.decodePoint(Arrays.copyOfRange(input, inputOffset, inputOffset + pEncLength));
            // Decrypt the buffer
            agreement.init(key);

            byte[] secret = converter.integerToBytes(
                agreement.calculateAgreement(new ECPublicKeyParameters(q, k.getParameters())),
                converter.getByteLength(ecParams.getCurve()));
            byte[] out = new byte[keyLength + macKeyLength];

            kdf.init(new KDFParameters(secret, engineSpec.getRecipientInfo()));

            kdf.generateBytes(out, 0, out.length);

            byte[] dec = new byte[keyLength];
            for (int i = 0; i != dec.length; i++)
            {
                dec[i] = (byte)(input[inputOffset + pEncLength + i] ^ out[i]);
            }

            KeyParameter macKey = new KeyParameter(out, keyLength, out.length - keyLength);

            hMac.init(macKey);

            hMac.update(input, inputOffset + pEncLength, dec.length);

            byte[] mac = new byte[hMac.getMacSize()];

            hMac.doFinal(mac, 0);

            Arrays.clear(macKey.getKey());
            Arrays.clear(out);

            if (!Arrays.constantTimeAreEqual(macLength, mac, 0, input, inputOffset + (inputLen - macLength)))
            {
                throw new BadPaddingException("mac field");
            }

            return dec;
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

    static public class KEM
        extends IESKEMCipher
    {
        public KEM(Digest kdfDigest, Digest macDigest, int macKeyLength, int macLength)
        {
            super(new ECDHCBasicAgreement(), new KDF2BytesGenerator(kdfDigest), new HMac(macDigest), macKeyLength, macLength);
        }
    }

    static public class KEMwithSHA256
            extends KEM
    {
        public KEMwithSHA256()
        {
            super(DigestFactory.createSHA256(), DigestFactory.createSHA256(), 32, 16);
        }
    }
}