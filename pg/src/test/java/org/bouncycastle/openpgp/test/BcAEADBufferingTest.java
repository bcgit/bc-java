package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.AEADUtils;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.openpgp.operator.bc.BcAEADUtil;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Tests that BcAEADUtil's chunked AEAD encrypt stream holds only to what the AEADBlockCipher
 * contract promises. PGPAeadOutputStream.writeBlock() used to encrypt each chunk in place into a
 * plaintext-sized buffer, which relied on two properties of the pure-Java engines the interface
 * does not guarantee: that output never overtakes input when the two alias, and that doFinal's
 * output fits in the plaintext's length. The two wrapper ciphers below are conforming
 * implementations that break one assumption each; both round-trip against the fixed code.
 */
public class BcAEADBufferingTest
    extends SimpleTest
{
    private static final int ENC_ALG = SymmetricKeyAlgorithmTags.AES_128;
    private static final int AEAD_ALG = AEADAlgorithmTags.GCM;
    private static final int CHUNK_SIZE = 3;    // chunk-size octet: 1 << (3 + 6) = 512-byte chunks

    public String getName()
    {
        return "BcAEADBufferingTest";
    }

    public void performTest()
        throws Exception
    {
        testBaselineRoundTrip();
        testDeferredOutputCipher();
        testEagerWriteCipher();
    }

    private void testBaselineRoundTrip()
        throws Exception
    {
        roundTrip(BcAEADUtil.createAEADCipher(ENC_ALG, AEAD_ALG), "baseline");
    }

    /**
     * A cipher that emits nothing from processBytes and everything from doFinal. Against the old
     * in-place writeBlock() the doFinal output (chunk + tag) overran the plaintext-sized buffer.
     */
    private void testDeferredOutputCipher()
        throws Exception
    {
        roundTrip(new DeferredOutputCipher(BcAEADUtil.createAEADCipher(ENC_ALG, AEAD_ALG)), "deferred output");
    }

    /**
     * A cipher that writes into the output region before it has consumed the corresponding input.
     * Against the old in-place writeBlock() (input aliased output) it destroyed the plaintext it
     * had not yet read, producing ciphertext that cannot be decrypted.
     */
    private void testEagerWriteCipher()
        throws Exception
    {
        roundTrip(new EagerWriteCipher(BcAEADUtil.createAEADCipher(ENC_ALG, AEAD_ALG)), "eager write");
    }

    private void roundTrip(AEADBlockCipher encCipher, String label)
        throws Exception
    {
        // several full chunks plus a partial one
        byte[] message = new byte[2000];
        for (int i = 0; i != message.length; i++)
        {
            message[i] = (byte)(i * 7);
        }

        byte[] key = new byte[16];
        byte[] iv = new byte[AEADUtils.getIVLength(AEAD_ALG)];
        for (int i = 0; i != key.length; i++)
        {
            key[i] = (byte)(i + 1);
        }
        for (int i = 0; i != iv.length; i++)
        {
            iv[i] = (byte)(i + 101);
        }

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream aeadOut = Access.createOutputStream(bOut, encCipher, new KeyParameter(key), iv);

        aeadOut.write(message);
        aeadOut.close();

        InputStream aeadIn = Access.createInputStream(new ByteArrayInputStream(bOut.toByteArray()),
            BcAEADUtil.createAEADCipher(ENC_ALG, AEAD_ALG), new KeyParameter(key), iv);

        byte[] recovered = Streams.readAll(aeadIn);

        isTrue(label + ": recovered data does not match", Arrays.areEqual(message, recovered));
    }

    /**
     * Subclass shim giving the test access to the protected PGPAead stream classes without
     * widening their visibility in the published API.
     */
    private static class Access
        extends BcAEADUtil
    {
        static OutputStream createOutputStream(OutputStream out, AEADBlockCipher c, KeyParameter key, byte[] iv)
        {
            return new PGPAeadOutputStream(false, out, c, key, iv, ENC_ALG, AEAD_ALG, CHUNK_SIZE);
        }

        static InputStream createInputStream(InputStream in, AEADBlockCipher c, KeyParameter key, byte[] iv)
            throws Exception
        {
            return new PGPAeadInputStream(false, in, c, key, iv, ENC_ALG, AEAD_ALG, CHUNK_SIZE,
                SymmetricEncIntegrityPacket.createAAData(SymmetricEncIntegrityPacket.VERSION_2, ENC_ALG, AEAD_ALG, CHUNK_SIZE));
        }
    }

    /**
     * Conforming AEADBlockCipher that buffers all input and produces its entire output - held-back
     * data plus tag - from doFinal, the way an implementation working in larger internal batches
     * may. getOutputSize() correctly accounts for the buffered input.
     */
    private static class DeferredOutputCipher
        implements AEADBlockCipher
    {
        private final AEADBlockCipher delegate;
        private final ByteArrayOutputStream buffered = new ByteArrayOutputStream();

        DeferredOutputCipher(AEADBlockCipher delegate)
        {
            this.delegate = delegate;
        }

        public void init(boolean forEncryption, CipherParameters params)
        {
            buffered.reset();
            delegate.init(forEncryption, params);
        }

        public String getAlgorithmName()
        {
            return delegate.getAlgorithmName();
        }

        public BlockCipher getUnderlyingCipher()
        {
            return delegate.getUnderlyingCipher();
        }

        public void processAADByte(byte in)
        {
            delegate.processAADByte(in);
        }

        public void processAADBytes(byte[] in, int inOff, int len)
        {
            delegate.processAADBytes(in, inOff, len);
        }

        public int processByte(byte in, byte[] out, int outOff)
        {
            buffered.write(in);
            return 0;
        }

        public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff)
        {
            buffered.write(in, inOff, len);
            return 0;
        }

        public int doFinal(byte[] out, int outOff)
            throws InvalidCipherTextException
        {
            byte[] input = buffered.toByteArray();
            buffered.reset();

            int len = delegate.processBytes(input, 0, input.length, out, outOff);
            return len + delegate.doFinal(out, outOff + len);
        }

        public byte[] getMac()
        {
            return delegate.getMac();
        }

        public int getUpdateOutputSize(int len)
        {
            return 0;
        }

        public int getOutputSize(int len)
        {
            return delegate.getOutputSize(len + buffered.size());
        }

        public void reset()
        {
            buffered.reset();
            delegate.reset();
        }
    }

    /**
     * Conforming AEADBlockCipher that scribbles over the whole output region before reading the
     * corresponding input - harmless when input and output are distinct, destructive when a caller
     * aliases them.
     */
    private static class EagerWriteCipher
        implements AEADBlockCipher
    {
        private final AEADBlockCipher delegate;

        EagerWriteCipher(AEADBlockCipher delegate)
        {
            this.delegate = delegate;
        }

        public void init(boolean forEncryption, CipherParameters params)
        {
            delegate.init(forEncryption, params);
        }

        public String getAlgorithmName()
        {
            return delegate.getAlgorithmName();
        }

        public BlockCipher getUnderlyingCipher()
        {
            return delegate.getUnderlyingCipher();
        }

        public void processAADByte(byte in)
        {
            delegate.processAADByte(in);
        }

        public void processAADBytes(byte[] in, int inOff, int len)
        {
            delegate.processAADBytes(in, inOff, len);
        }

        public int processByte(byte in, byte[] out, int outOff)
        {
            return processBytes(new byte[]{ in }, 0, 1, out, outOff);
        }

        public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff)
        {
            byte[] scratch = new byte[delegate.getOutputSize(len)];

            // "write ahead": claim the output region before consuming the input
            for (int i = 0; i != len; i++)
            {
                out[outOff + i] = (byte)0xAA;
            }

            int n = delegate.processBytes(in, inOff, len, scratch, 0);
            System.arraycopy(scratch, 0, out, outOff, n);
            return n;
        }

        public int doFinal(byte[] out, int outOff)
            throws InvalidCipherTextException
        {
            return delegate.doFinal(out, outOff);
        }

        public byte[] getMac()
        {
            return delegate.getMac();
        }

        public int getUpdateOutputSize(int len)
        {
            return delegate.getUpdateOutputSize(len);
        }

        public int getOutputSize(int len)
        {
            return delegate.getOutputSize(len);
        }

        public void reset()
        {
            delegate.reset();
        }
    }

    public static void main(String[] args)
    {
        runTest(new BcAEADBufferingTest());
    }
}
