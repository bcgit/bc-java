package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * ChaCha20Poly1305 Engine.
 */
public class ChaChaPoly1305
    implements StreamCipher {
    /**
     * The MacSize.
     */
    private static final int MACSIZE = 16;

    /**
     * The Zero padding.
     */
    private static final byte[] PADDING = new byte[MACSIZE - 1];

    /**
     * The Underlying cipher.
     */
    private final StreamCipher theCipher;

    /**
     * The Poly1305Mac.
     */
    private final Poly1305 polyMac;

    /**
     * The cachedBytes.
     */
    private final byte[] cachedBytes;

    /**
     * number of bytes in the cache.
     */
    private int cacheBytes;

    /**
     * Are we initialised?
     */
    private boolean initialised;

    /**
     * Are we encrypting?
     */
    private boolean encrypting;

    /**
     * The Initial AEAD Data.
     */
    private byte[] initialAEAD;

    /**
     * Have we completed AEAD?
     */
    private boolean aeadComplete;

    /**
     * The AEAD DataLength.
     */
    private long aeadLength;

    /**
     * The dataLength.
     */
    private long dataLength;

    /**
     * Constructor.
     * @param pChaChaEngine the ChaCha engine.
     */
    public ChaChaPoly1305(final StreamCipher pChaChaEngine) {
        theCipher = pChaChaEngine;
        polyMac = new Poly1305();
        cachedBytes = new byte[MACSIZE];
    }

    /**
     * Obtain algorithm name.
     * @return the algorithm name
     */
    @Override
    public String getAlgorithmName() {
        return theCipher.getAlgorithmName() + "Poly1305";
    }

    /**
     * Initialise the cipher.
     * @param forEncryption true/false
     * @param params the parameters
     */
    public void init(final boolean forEncryption,
                     final CipherParameters params) {
        /* Access parameters */
        CipherParameters parms = params;

        /* Reset details */
        initialised = false;
        initialAEAD = null;

        /* If we have AEAD parameters */
        if (params instanceof AEADParameters) {
            final AEADParameters param = (AEADParameters) params;
            initialAEAD = param.getAssociatedText();
            final byte[] nonce = param.getNonce();
            final KeyParameter key = param.getKey();
            parms = new ParametersWithIV(key, nonce);
        }

        /* Initialise the cipher */
        theCipher.init(forEncryption, parms);

        /* Reset the cipher and init the Mac */
        reset();

        /* Note that we are initialised */
        encrypting = forEncryption;
        initialised = true;
    }

    @Override
    public void reset() {
        /* Reset state */
        dataLength = 0;
        aeadLength = 0;
        aeadComplete = false;
        cacheBytes = 0;
        theCipher.reset();

        /* Run the cipher once to initialise the mac */
        final byte[] firstBlock = new byte[64]; // ChaCha stateLength
        theCipher.processBytes(firstBlock, 0, firstBlock.length, firstBlock, 0);
        polyMac.init(new KeyParameter(firstBlock, 0, 32)); // Poly1305 KeyLength
        Arrays.fill(firstBlock, (byte) 0);

        /* If we have initial AEAD data */
        if (initialAEAD != null) {
            /* Reapply initial AEAD data */
            aeadLength = initialAEAD.length;
            polyMac.update(initialAEAD, 0, (int) aeadLength);
        }
    }

    /**
     * Process AAD byte.
     * @param in the byte to process
     */
    public void processAADByte(final byte in) {
        /* Check AAD is allowed */
        checkAEADStatus();

        /* Process the byte */
        polyMac.update(in);
        aeadLength++;
    }

    /**
     * Process AAD bytes.
     * @param in the bytes to process
     * @param inOff the offset from which to start processing
     * @param len the number of bytes to process
     */
    public void processAADBytes(final byte[] in,
                                final int inOff,
                                final int len) {
        /* Check AAD is allowed */
        checkAEADStatus();

        /* Process the bytes */
        polyMac.update(in, inOff, len);
        aeadLength += len;
    }

    /**
     * check AEAD status.
     */
    private void checkAEADStatus() {
        /* Check we are initialised */
        if (!initialised) {
            throw new IllegalStateException("Cipher is not initialised");
        }

        /* Check AAD is allowed */
        if (aeadComplete) {
            throw new IllegalStateException("AEAD data cannot be processed after ordinary data");
        }
    }

    /**
     * check status.
     */
    private void checkStatus() {
        /* Check we are initialised */
        if (!initialised) {
            throw new IllegalStateException("Cipher is not initialised");
        }

        /* Complete the AEAD section if this is the first data */
        if (!aeadComplete) {
            completeAEADMac();
        }
    }

    /**
     * Process single byte (not supported).
     * @param in the input byte
     * @return the output byte
     */
    public byte returnByte(final byte in) {
        throw new UnsupportedOperationException();
    }

    /**
     * Process bytes.
     * @param in the input buffer
     * @param inOff the starting offset in the input buffer
     * @param len the length of data in the input buffer
     * @param out the output buffer
     * @param outOff the starting offset in the output buffer
     * @return the number of bytes returned in the output buffer
     */
    public int processBytes(final byte[] in,
                            final int inOff,
                            final int len,
                            final byte[] out,
                            final int outOff) {
        /* Check status */
        checkStatus();

        /* process the bytes */
        return encrypting
                  ? processEncryptionBytes(in, inOff, len, out, outOff)
                  : processDecryptionBytes(in, inOff, len, out, outOff);
    }

    /**
     * Obtain the maximum output length for a given input length.
     * @param len the length of data to process
     * @return the maximum output length
     */
    public int getOutputSize(final int len) {
        if (encrypting) {
            return len + MACSIZE;
        }

        /* Allow for cacheSpace */
        final int cacheSpace = MACSIZE - cacheBytes;
        return len < cacheSpace ? 0 : len - cacheSpace;
    }

    /**
     * Obtain the maximum output length for an update.
     * @param len the data length to update
     * @return the maximum output length
     */
    public int getUpdateOutputSize(final int len) {
         return len;
    }

    /**
     * Finish processing.
     * @param out the output buffer
     * @param outOff the offset from which to start writing output
     * @return the length of data written out
     * @throws InvalidCipherTextException on mac misMatch
     */
    public int doFinal(final byte[] out,
                       final int outOff) throws InvalidCipherTextException {
        /* Check status */
        checkStatus();

        /* finish the mac */
        final int outLen = encrypting
                     ? finishEncryptionMac(out, outOff)
                     : finishDecryptionMac();

        /* Reset the cipher */
        reset();

        /* return the number of bytes processed */
        return outLen;
    }

    /**
     * Process encryption bytes.
     * @param in the input buffer
     * @param inOff the offset from which to start processing
     * @param len the length of data to process
     * @param out the output buffer
     * @param outOff the offset from which to start writing output
     * @return the length of data written out
     */
    private int processEncryptionBytes(final byte[] in,
                                       final int inOff,
                                       final int len,
                                       final byte[] out,
                                       final int outOff) {
        /* Check that the buffers are sufficient */
        if (in.length < (len + inOff)) {
            throw new DataLengthException("Input buffer too short.");
        }
        if (out.length < (len + outOff)) {
            throw new OutputLengthException("Output buffer too short.");
        }

        /* Process the bytes */
        theCipher.processBytes(in, inOff, len, out, outOff);

        /* Update the mac */
        polyMac.update(out, outOff, len);
        dataLength += len;

        /* Return the number of bytes processed */
        return len;
    }

    /**
     * finish the encryption Mac.
     * @param out the output buffer
     * @param outOff the offset from which to start writing output
     * @return the length of data written out
     */
    private int finishEncryptionMac(final byte[] out,
                                    final int outOff) {
        /* Check that the output buffer is sufficient */
        if (out.length < (MACSIZE + outOff)) {
            throw new OutputLengthException("Output buffer too short.");
        }

        /* complete the data portion of the Mac */
        completeDataMac();

        /* Update and return the mac in the output buffer */
        return polyMac.doFinal(out, outOff);
    }

    /**
     * Process decryption bytes.
     * @param in the input buffer
     * @param inOff the offset from which to start processing
     * @param len the length of data to process
     * @param out the output buffer
     * @param outOff the offset from which to start writing output
     * @return the length of data written out
     */
    private int processDecryptionBytes(final byte[] in,
                                       final int inOff,
                                       final int len,
                                       final byte[] out,
                                       final int outOff) {
        /* Check that the buffers are sufficient */
        if (in.length < (len + inOff)) {
            throw new DataLengthException("Input buffer too short.");
        }
        if (out.length < (len + outOff + cacheBytes - MACSIZE)) {
            throw new OutputLengthException("Output buffer too short.");
        }

        /* Count how much we have processed */
        int processed = 0;

        /* If we have at least MACSIZE data */
        if (len >= MACSIZE) {
            /* If we have cached mac bytes */
            if (cacheBytes > 0) {
                /* Process any existing cachedBytes */
                polyMac.update(cachedBytes, 0, cacheBytes);
                dataLength += cacheBytes;

                /* Process the cached bytes */
                processed = theCipher.processBytes(cachedBytes, 0, cacheBytes, out, outOff);
            }

            /* Determine how many bytes to process */
            final int numBytes = len - MACSIZE;
            if (numBytes > 0) {
                /* Process the data */
                polyMac.update(in, inOff, numBytes);
                dataLength += numBytes;

                /* Process the input */
                processed += theCipher.processBytes(in, inOff, numBytes, out, outOff + processed);
            }

            /* Store the remaining input into the cache */
            System.arraycopy(in, inOff + numBytes, cachedBytes, 0, MACSIZE);
            cacheBytes = MACSIZE;

            /* else all new data will be placed into the cache */
        } else {
            /* Calculate number of bytes in the cache to process */
            final int numBytes = cacheBytes + len - MACSIZE;
            if (numBytes > 0) {
                /* Process the excess cachedBytes */
                polyMac.update(cachedBytes, 0, numBytes);
                dataLength += numBytes;

                /* Process the cached bytes */
                processed = theCipher.processBytes(cachedBytes, 0, numBytes, out, outOff);

                /* Move remaining cached bytes down */
                cacheBytes -= numBytes;
                System.arraycopy(cachedBytes, numBytes, cachedBytes, 0, cacheBytes);
            }

            /* Store the data into the cache */
            System.arraycopy(in, inOff, cachedBytes, cacheBytes, len);
            cacheBytes += len;
        }

        /* Return the number of bytes processed */
        return processed;
    }

    /**
     * finish the decryption Mac.
     * @return the length of data written out
     * @throws InvalidCipherTextException on mac misMatch
     */
    private int finishDecryptionMac() throws InvalidCipherTextException {
        /* If we do not have sufficient data */
        if (cacheBytes < MACSIZE) {
            throw new InvalidCipherTextException("data too short");
        }

        /* complete the data portion of the Mac */
        completeDataMac();

        /* Update and return the mac in the output buffer */
        final byte[] mac = new byte[MACSIZE];
        polyMac.doFinal(mac, 0);

        /* Check that the buffers compare */
        if (!Arrays.constantTimeAreEqual(mac, cachedBytes)) {
            throw new InvalidCipherTextException("mac check failed");
        }

        /* No bytes returned */
        return 0;
    }

    /**
     * Complete AEAD Mac input.
     */
    private void completeAEADMac() {
        /* Pad to boundary */
        final int xtra = (int) aeadLength % MACSIZE;
        if (xtra != 0) {
            final int numPadding = MACSIZE - xtra;
            polyMac.update(PADDING, 0, numPadding);
        }
        aeadComplete = true;
    }

    /**
     * Complete Mac data input.
     */
    private void completeDataMac() {
        /* Pad to boundary */
        final int xtra = (int) dataLength % MACSIZE;
        if (xtra != 0) {
            final int numPadding = MACSIZE - xtra;
            polyMac.update(PADDING, 0, numPadding);
        }

        /* Write the lengths */
        final byte[] len = new byte[16]; // 2 * Long.BYTES
        Pack.longToLittleEndian(aeadLength, len, 0);
        Pack.longToLittleEndian(dataLength, len, 8); // Long.BYTES
        polyMac.update(len, 0, len.length);
    }
}
