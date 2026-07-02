package org.bouncycastle.crypto.engines;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.EphemeralKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyParser;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.generators.EphemeralKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.IESParameters;
import org.bouncycastle.crypto.params.IESWithCipherParameters;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Pack;

/**
 * Support class for constructing integrated encryption ciphers
 * for doing basic message exchanges on top of key agreement ciphers.
 * Follows the description given in IEEE Std 1363a.
 */
public class IESEngine
{
    BasicAgreement agree;
    DerivationFunction kdf;
    Mac mac;
    BufferedBlockCipher cipher;
    byte[] macBuf;

    boolean forEncryption;
    CipherParameters privParam, pubParam;
    IESParameters param;

    byte[] V;
    private EphemeralKeyPairGenerator keyPairGenerator;
    private KeyParser keyParser;
    private byte[] IV;

    /**
     * Set up for use with stream mode, where the key derivation function
     * is used to provide a stream of bytes to xor with the message.
     * <p>
     * <b>Security note:</b> when this engine is initialised with static keys on both sides (the
     * {@link #init(boolean, CipherParameters, CipherParameters, CipherParameters)} entry point, which
     * supplies no ephemeral component) the key-derivation input is the same for every message, so the
     * stream-mode keystream is identical from message to message - encrypting more than one message
     * under a given key pair is a many-time pad and leaks plaintext relationships. Use the ephemeral
     * sender-key initialisation (the standard ECIES mode) for messages that must remain confidential;
     * the static-static mode is effectively deterministic encryption.
     * </p>
     *
     * @param agree the key agreement used as the basis for the encryption
     * @param kdf   the key derivation function used for byte generation
     * @param mac   the message authentication code generator for the message
     */
    public IESEngine(
        BasicAgreement agree,
        DerivationFunction kdf,
        Mac mac)
    {
        this.agree = agree;
        this.kdf = kdf;
        this.mac = mac;
        this.macBuf = new byte[mac.getMacSize()];
        this.cipher = null;
    }


    /**
     * Set up for use in conjunction with a block cipher to handle the
     * message. It is <b>strongly</b> recommended that the cipher is not in ECB mode.
     *
     * @param agree  the key agreement used as the basis for the encryption
     * @param kdf    the key derivation function used for byte generation
     * @param mac    the message authentication code generator for the message
     * @param cipher the cipher to used for encrypting the message
     */
    public IESEngine(
        BasicAgreement agree,
        DerivationFunction kdf,
        Mac mac,
        BufferedBlockCipher cipher)
    {
        this.agree = agree;
        this.kdf = kdf;
        this.mac = mac;
        this.macBuf = new byte[mac.getMacSize()];
        this.cipher = cipher;
    }

    /**
     * Initialise the encryptor.
     *
     * @param forEncryption whether or not this is encryption/decryption.
     * @param privParam     our private key parameters
     * @param pubParam      the recipient's/sender's public key parameters
     * @param params        encoding and derivation parameters, may be wrapped to include an IV for an underlying block cipher.
     */
    public void init(
        boolean forEncryption,
        CipherParameters privParam,
        CipherParameters pubParam,
        CipherParameters params)
    {
        this.forEncryption = forEncryption;
        this.privParam = privParam;
        this.pubParam = pubParam;
        this.V = new byte[0];

        extractParams(params);
    }

    /**
     * Initialise the decryptor.
     *
     * @param publicKey      the recipient's/sender's public key parameters
     * @param params         encoding and derivation parameters, may be wrapped to include an IV for an underlying block cipher.
     * @param ephemeralKeyPairGenerator             the ephemeral key pair generator to use.
     */
    public void init(AsymmetricKeyParameter publicKey, CipherParameters params, EphemeralKeyPairGenerator ephemeralKeyPairGenerator)
    {
        this.forEncryption = true;
        this.pubParam = publicKey;
        this.keyPairGenerator = ephemeralKeyPairGenerator;

        extractParams(params);
    }

    /**
     * Initialise the encryptor.
     *
     * @param privateKey      the recipient's private key.
     * @param params          encoding and derivation parameters, may be wrapped to include an IV for an underlying block cipher.
     * @param publicKeyParser the parser for reading the ephemeral public key.
     */
    public void init(AsymmetricKeyParameter privateKey, CipherParameters params, KeyParser publicKeyParser)
    {
        this.forEncryption = false;
        this.privParam = privateKey;
        this.keyParser = publicKeyParser;

        extractParams(params);
    }

    private void extractParams(CipherParameters params)
    {
        if (params instanceof ParametersWithIV)
        {
            this.IV = ((ParametersWithIV)params).getIV();
            this.param = (IESParameters)((ParametersWithIV)params).getParameters();
        }
        else
        {
            this.IV = null;
            this.param = (IESParameters)params;
        }
    }

    public BufferedBlockCipher getCipher()
    {
        return cipher;
    }

    public Mac getMac()
    {
        return mac;
    }

    private byte[] encryptBlock(
        byte[] in,
        int inOff,
        int inLen)
        throws InvalidCipherTextException
    {
        byte[] C, K, K1, K2;
        int len;

        if (cipher == null)
        {
            // Streaming mode.
            K1 = new byte[inLen];
            K2 = new byte[param.getMacKeySize() / 8];
            K = new byte[K1.length + K2.length];

            kdf.generateBytes(K, 0, K.length);

            // Derive the MAC key K2 from a fixed prefix of the KDF output and the keystream K1 from
            // the remainder, regardless of whether an ephemeral V is present. Placing K1 first (the
            // legacy static-key, V-absent layout) put K2 at a message-length-dependent offset behind
            // the keystream, so a single known-plaintext leak of K1 also exposed the MAC key of any
            // shorter message - a cross-message forgery in the deterministic static-key mode. A fixed
            // K2 offset is never covered by the keystream, closing that.
            System.arraycopy(K, 0, K2, 0, K2.length);
            System.arraycopy(K, K2.length, K1, 0, K1.length);

            C = new byte[inLen];

            for (int i = 0; i != inLen; i++)
            {
                C[i] = (byte)(in[inOff + i] ^ K1[i]);
            }
            len = inLen;
        }
        else
        {
            // Block cipher mode.
            K1 = new byte[((IESWithCipherParameters)param).getCipherKeySize() / 8];
            K2 = new byte[param.getMacKeySize() / 8];
            K = new byte[K1.length + K2.length];

            kdf.generateBytes(K, 0, K.length);
            System.arraycopy(K, 0, K1, 0, K1.length);
            System.arraycopy(K, K1.length, K2, 0, K2.length);

            CipherParameters cp = new KeyParameter(K1);

            // If IV provide use it to initialize the cipher
            if (IV != null)
            {
                cp = new ParametersWithIV(cp, IV);
            }

            cipher.init(true, cp);

            C = new byte[cipher.getOutputSize(inLen)];
            len = cipher.processBytes(in, inOff, inLen, C, 0);
            len += cipher.doFinal(C, len);
        }


        // Convert the length of the encoding vector into a byte array.
        byte[] P2 = param.getEncodingV();
        byte[] L2 = null;
        if (V.length != 0)
        {
            L2 = getLengthTag(P2);
        }


        // Apply the MAC.
        byte[] T = new byte[mac.getMacSize()];

        mac.init(new KeyParameter(K2));
        mac.update(C, 0, len);
        if (P2 != null)
        {
            mac.update(P2, 0, P2.length);
        }
        if (V.length != 0)
        {
            mac.update(L2, 0, L2.length);
        }
        mac.doFinal(T, 0);


        // Output the triple (V,C,T).
        byte[] Output = new byte[V.length + len + T.length];
        System.arraycopy(V, 0, Output, 0, V.length);
        System.arraycopy(C, 0, Output, V.length, len);
        System.arraycopy(T, 0, Output, V.length + len, T.length);
        return Output;
    }

    private byte[] decryptBlock(
        byte[] in_enc,
        int inOff,
        int inLen)
        throws InvalidCipherTextException
    {
        byte[] M, K, K1, K2;
        int len = 0;

        // Ensure that the length of the input is greater than the MAC in bytes
        if (inLen < V.length + mac.getMacSize())
        {
            throw new InvalidCipherTextException("Length of input must be greater than the MAC and V combined");
        }

        // note order is important: set up keys, do simple encryptions, check mac, do final encryption.
        if (cipher == null)
        {
            // Streaming mode.
            K1 = new byte[inLen - V.length - mac.getMacSize()];
            K2 = new byte[param.getMacKeySize() / 8];
            K = new byte[K1.length + K2.length];

            kdf.generateBytes(K, 0, K.length);

            // K2 (MAC key) from a fixed prefix, K1 (keystream) from the remainder - see encryptBlock.
            System.arraycopy(K, 0, K2, 0, K2.length);
            System.arraycopy(K, K2.length, K1, 0, K1.length);

            // process the message
            M = new byte[K1.length];

            for (int i = 0; i != K1.length; i++)
            {
                M[i] = (byte)(in_enc[inOff + V.length + i] ^ K1[i]);
            }
        }
        else
        {
            // Block cipher mode.
            K1 = new byte[((IESWithCipherParameters)param).getCipherKeySize() / 8];
            K2 = new byte[param.getMacKeySize() / 8];
            K = new byte[K1.length + K2.length];

            kdf.generateBytes(K, 0, K.length);
            System.arraycopy(K, 0, K1, 0, K1.length);
            System.arraycopy(K, K1.length, K2, 0, K2.length);

            CipherParameters cp = new KeyParameter(K1);

            // If IV provided use it to initialize the cipher
            if (IV != null)
            {
                cp = new ParametersWithIV(cp, IV);
            }

            cipher.init(false, cp);

            M = new byte[cipher.getOutputSize(inLen - V.length - mac.getMacSize())];

            // do initial processing
            len = cipher.processBytes(in_enc, inOff + V.length, inLen - V.length - mac.getMacSize(), M, 0);
        }

        // Convert the length of the encoding vector into a byte array.
        byte[] P2 = param.getEncodingV();
        byte[] L2 = null;
        if (V.length != 0)
        {
            L2 = getLengthTag(P2);
        }

        // Verify the MAC.
        int end = inOff + inLen;
        byte[] T1 = Arrays.copyOfRange(in_enc, end - mac.getMacSize(), end);

        byte[] T2 = new byte[T1.length];
        mac.init(new KeyParameter(K2));
        mac.update(in_enc, inOff + V.length, inLen - V.length - T2.length);

        if (P2 != null)
        {
            mac.update(P2, 0, P2.length);
        }
        if (V.length != 0)
        {
            mac.update(L2, 0, L2.length);
        }
        mac.doFinal(T2, 0);

        if (!Arrays.constantTimeAreEqual(T1, T2))
        {
            throw new InvalidCipherTextException("invalid MAC");
        }

        if (cipher == null)
        {
            return M;
        }
        else
        {
            // MAC must be verified above before this doFinal: it removes padding (e.g. PKCS7), and a
            // padding failure here is distinguishable from a MAC failure, which would be a CBC padding oracle.
            // Only authenticated ciphertext reaches this point.
            len += cipher.doFinal(M, len);

            return Arrays.copyOfRange(M, 0, len);
        }
    }


    public byte[] processBlock(
        byte[] in,
        int inOff,
        int inLen)
        throws InvalidCipherTextException
    {
        if (forEncryption)
        {
            if (keyPairGenerator != null)
            {
                EphemeralKeyPair ephKeyPair = keyPairGenerator.generate();

                this.privParam = ephKeyPair.getKeyPair().getPrivate();
                this.V = ephKeyPair.getEncodedPublicKey();
            }
        }
        else
        {
            if (keyParser != null)
            {
                ByteArrayInputStream bIn = new ByteArrayInputStream(in, inOff, inLen);

                try
                {
                    this.pubParam = keyParser.readKey(bIn);
                }
                catch (IOException e)
                {
                    throw new InvalidCipherTextException("unable to recover ephemeral public key: " + e.getMessage(), e);
                }
                catch (IllegalArgumentException e)
                {
                    throw new InvalidCipherTextException("unable to recover ephemeral public key: " + e.getMessage(), e);
                }

                int encLength = (inLen - bIn.available());
                this.V = Arrays.copyOfRange(in, inOff, inOff + encLength);
            }
        }

        // Compute the common value and convert to byte array.
        agree.init(privParam);
        BigInteger z = agree.calculateAgreement(pubParam);
        byte[] Z = BigIntegers.asUnsignedByteArray(agree.getFieldSize(), z);

        // Create input to KDF.
        if (V.length != 0)
        {
            byte[] VZ = Arrays.concatenate(V, Z);
            Arrays.fill(Z, (byte)0);
            Z = VZ;
        }

        try
        {
            // Initialise the KDF.
            KDFParameters kdfParam = new KDFParameters(Z, param.getDerivationV());
            kdf.init(kdfParam);

            return forEncryption
                ? encryptBlock(in, inOff, inLen)
                : decryptBlock(in, inOff, inLen);
        }
        finally
        {
            Arrays.fill(Z, (byte)0);
        }
    }

    // as described in Shroup's paper and P1363a
    protected byte[] getLengthTag(byte[] p2)
    {
        byte[] L2 = new byte[8];
        if (p2 != null)
        {
            Pack.longToBigEndian(p2.length * 8L, L2, 0);
        }
        return L2;
    }
}
