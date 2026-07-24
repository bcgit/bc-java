package org.bouncycastle.jcajce.provider.asymmetric.sm9;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
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
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import org.bouncycastle.asn1.gm.SM9Cipher;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.SM9EncPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncPublicKeyParameters;
import org.bouncycastle.crypto.engines.SM9Engine;
import org.bouncycastle.jcajce.provider.util.SecurityExceptions;
import org.bouncycastle.jcajce.spec.SM9ParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * JCA {@link javax.crypto.Cipher} for SM9 public-key encryption (GM/T 0044.4).
 * <p>
 * Encrypt with a {@link BCSM9EncMasterPublicKey} plus the recipient identity in
 * an {@link SM9ParameterSpec}; decrypt with a {@link BCSM9EncPrivateKey}. The
 * ciphertext is a DER {@link SM9Cipher} whose {@code enType} records the
 * data-encapsulation mode, so decryption selects the mode automatically. The
 * default encryption mode is SM4/ECB/PKCS#7 ({@code enType} = 1); call
 * {@code setMode("XOR")} for the KDF stream mode.
 * <p>
 * The ciphertext is the GM/T 0080-2020 SM9Cipher structure (see {@link org.bouncycastle.asn1.gm.SM9Cipher}).
 */
public class CipherSpi
    extends javax.crypto.CipherSpi
{
    private final SM9Engine engine = new SM9Engine();
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    private int state = -1;
    private int mode = SM9Engine.MODE_SM4;
    private SM9EncPublicKeyParameters recipient;
    private SM9EncPrivateKeyParameters userKey;
    private SecureRandom random;

    protected void engineSetMode(String modeName)
        throws NoSuchAlgorithmException
    {
        String m = modeName == null ? "" : Strings.toUpperCase(modeName);
        if (m.equals("SM4") || m.equals("ECB") || m.equals(""))
        {
            mode = SM9Engine.MODE_SM4;
        }
        else if (m.equals("XOR") || m.equals("STREAM") || m.equals("KDF"))
        {
            mode = SM9Engine.MODE_STREAM;
        }
        else
        {
            throw new NoSuchAlgorithmException("unsupported SM9 mode: " + modeName);
        }
    }

    protected void engineSetPadding(String padding)
        throws NoSuchPaddingException
    {
        if (padding != null && !padding.equalsIgnoreCase("NoPadding"))
        {
            throw new NoSuchPaddingException("padding not supported: " + padding);
        }
    }

    protected int engineGetBlockSize()
    {
        return 0;
    }

    protected int engineGetOutputSize(int inputLen)
    {
        // C1 point + C3 MAC + C2 (+ SM4 block rounding) + DER overhead; over-estimate.
        return inputLen + 256;
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
            throw SecurityExceptions.invalidKeyException(e.getMessage(), e);
        }
    }

    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        this.state = opmode;
        this.random = CryptoServicesRegistrar.getSecureRandom(random);
        this.recipient = null;
        this.userKey = null;
        buffer.reset();

        if (opmode == Cipher.ENCRYPT_MODE)
        {
            if (!(key instanceof BCSM9EncMasterPublicKey))
            {
                throw new InvalidKeyException("SM9 encryption requires an SM9 encryption master public key");
            }
            if (!(params instanceof SM9ParameterSpec))
            {
                throw new InvalidAlgorithmParameterException("SM9 encryption requires the recipient identity in an SM9ParameterSpec");
            }
            recipient = new SM9EncPublicKeyParameters(
                ((BCSM9EncMasterPublicKey)key).getKeyParameters(), ((SM9ParameterSpec)params).getId());
        }
        else if (opmode == Cipher.DECRYPT_MODE)
        {
            if (!(key instanceof BCSM9EncPrivateKey))
            {
                throw new InvalidKeyException("SM9 decryption requires an SM9 user decryption key");
            }
            userKey = ((BCSM9EncPrivateKey)key).getKeyParameters();
        }
        else
        {
            throw new InvalidParameterException("SM9 cipher supports only ENCRYPT_MODE and DECRYPT_MODE");
        }
    }

    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (params != null)
        {
            throw new InvalidAlgorithmParameterException("AlgorithmParameters not supported for SM9; use SM9ParameterSpec");
        }
        engineInit(opmode, key, (AlgorithmParameterSpec)null, random);
    }

    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen)
    {
        if (input != null && inputLen > 0)
        {
            buffer.write(input, inputOffset, inputLen);
        }
        return new byte[0];
    }

    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
    {
        engineUpdate(input, inputOffset, inputLen);
        return 0;
    }

    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
        throws IllegalBlockSizeException, BadPaddingException
    {
        if (input != null && inputLen > 0)
        {
            buffer.write(input, inputOffset, inputLen);
        }
        byte[] data = buffer.toByteArray();
        buffer.reset();

        try
        {
            if (state == Cipher.ENCRYPT_MODE)
            {
                byte[] raw = engine.encrypt(mode, recipient, data, random);   // C1(64) || C3(32) || C2
                byte[] c1 = new byte[65];
                c1[0] = 0x04;
                System.arraycopy(raw, 0, c1, 1, 64);
                byte[] c3 = Arrays.copyOfRange(raw, 64, 96);
                byte[] c2 = Arrays.copyOfRange(raw, 96, raw.length);
                return new SM9Cipher(mode, c1, c3, c2).getEncoded();
            }
            else
            {
                SM9Cipher c = SM9Cipher.getInstance(data);
                byte[] c1 = c.getC1();   // 0x04 || x || y
                byte[] raw = Arrays.concatenate(Arrays.copyOfRange(c1, 1, 65), c.getC3(), c.getC2());
                return engine.decrypt(c.getEnType(), userKey, raw);
            }
        }
        catch (InvalidCipherTextException e)
        {
            throw SecurityExceptions.badPaddingException("SM9 decryption failed: " + e.getMessage(), e);
        }
        catch (IOException e)
        {
            throw SecurityExceptions.badPaddingException("SM9 ciphertext malformed: " + e.getMessage(), e);
        }
        catch (RuntimeException e)
        {
            // a crafted ciphertext can surface ArithmeticException / IllegalStateException /
            // ArrayIndexOutOfBoundsException from the ASN.1 / slicing layer; all are malformed input.
            throw SecurityExceptions.badPaddingException("SM9 ciphertext malformed: " + e.getMessage(), e);
        }
    }

    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
        throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
    {
        byte[] result = engineDoFinal(input, inputOffset, inputLen);
        if (outputOffset + result.length > output.length)
        {
            throw new ShortBufferException("output buffer too short for SM9 result");
        }
        System.arraycopy(result, 0, output, outputOffset, result.length);
        return result.length;
    }
}
