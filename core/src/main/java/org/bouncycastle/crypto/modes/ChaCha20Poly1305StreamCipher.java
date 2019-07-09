package org.bouncycastle.crypto.modes;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * ChaCha20-Poly1305 in AEAD mode as described in <a href="https://tools.ietf.org/html/rfc7539#page-19">RFC 7539</a>.
 */
public class ChaCha20Poly1305StreamCipher implements AEADStreamCipher {

    private static final byte[] ZEROES = new byte[15];

    private final ExposedChaCha7539Engine cipher = new ExposedChaCha7539Engine();
    private final Poly1305 mac = new Poly1305();

    private boolean encrypting = true;
    private byte[] lastMacBlock = new byte[0];
    private byte[] initializedAssociatedText;
    private ExposedByteArrayOutputStream data = new ExposedByteArrayOutputStream();
    private ExposedByteArrayOutputStream associatedText = new ExposedByteArrayOutputStream();

    /**
     * Initialize for encrypting or decrypting.
     * <p>
     * {@code param} must be either {@link AEADParameters} or a {@link ParametersWithIV} that also contains a nested
     * {@link KeyParameter} to initialize the cipher with.
     *
     * @param forEncryption {@code true} to initialize for encrypting, {@code false} to initialize for decrypting.
     * @param param         either {@link AEADParameters} or a {@link ParametersWithIV} that also contains a nested
     *                      {@link KeyParameter}.
     */
    public void init(boolean forEncryption, CipherParameters param) {
        this.encrypting = forEncryption;

        if (param instanceof AEADParameters) {
            byte[] nonce = ((AEADParameters) param).getNonce();

            validateNonce(nonce);

            initializedAssociatedText = ((AEADParameters) param).getAssociatedText();

            KeyParameter keyParameter = ((AEADParameters) param).getKey();

            validateKeyParameter(keyParameter);

            cipher.init(forEncryption, new ParametersWithIV(keyParameter, nonce));

            initMac(mac, cipher);
        } else if (param instanceof ParametersWithIV) {
            byte[] nonce = ((ParametersWithIV) param).getIV();

            validateNonce(nonce);

            CipherParameters innerParameters = ((ParametersWithIV) param).getParameters();

            validateKeyParameter(innerParameters);

            initializedAssociatedText = new byte[0];

            cipher.init(forEncryption, param);

            initMac(mac, cipher);
        } else {
            throw new IllegalArgumentException("param: " + param);
        }

        data.reset();
        associatedText.reset();
    }

    public int doFinal(byte[] output, int outputOffset) throws IllegalStateException, InvalidCipherTextException {
        if (encrypting) {
            int ciphertextLength = cipher.processBytes(data.getBuffer(), 0, data.size(), output, outputOffset);

            if (ciphertextLength != data.size()) {
                throw new IllegalStateException("ciphertext length != input length");
            }

            byte[] associatedData = combineAssociatedTexts();
            updateMac(mac, associatedData, 0, associatedData.length);
            updateMac(mac, output, outputOffset, ciphertextLength);

            byte[] lengths = new byte[16];
            Pack.longToLittleEndian(associatedData.length & 0xFFFFFFFFL, lengths, 0);
            Pack.longToLittleEndian(ciphertextLength & 0xFFFFFFFFL, lengths, 8);
            mac.update(lengths, 0, 16);

            mac.doFinal(output, outputOffset + ciphertextLength);

            lastMacBlock = Arrays.copyOfRange(output, outputOffset + ciphertextLength, output.length);

            return ciphertextLength + 16;
        } else {
            int ciphertextLength = data.size() - 16;

            byte[] associatedData = combineAssociatedTexts();
            updateMac(mac, associatedData, 0, associatedData.length);
            updateMac(mac, data.getBuffer(), 0, ciphertextLength);

            byte[] calculatedMac = new byte[16];
            Pack.longToLittleEndian(associatedData.length & 0xFFFFFFFFL, calculatedMac, 0);
            Pack.longToLittleEndian(ciphertextLength & 0xFFFFFFFFL, calculatedMac, 8);
            mac.update(calculatedMac, 0, 16);
            mac.doFinal(calculatedMac, 0);

            byte[] receivedMac = Arrays.copyOfRange(data.getBuffer(), ciphertextLength, data.size());

            if (!Arrays.constantTimeAreEqual(calculatedMac, receivedMac)) {
                throw new InvalidCipherTextException("mac");
            }

            int bytesProcessed = cipher.processBytes(data.getBuffer(), 0, ciphertextLength, output, outputOffset);

            if (bytesProcessed != ciphertextLength) {
                throw new IllegalStateException();
            }

            lastMacBlock = calculatedMac;

            return ciphertextLength;
        }
    }

    public void reset() {
        cipher.reset();
        mac.reset();
        data.reset();
        associatedText.reset();
    }

    public int processByte(byte in, byte[] out, int outOff) throws DataLengthException {
        data.write(in);

        return 0;
    }

    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff) throws DataLengthException {
        if (in.length < (inOff + len)) {
            throw new DataLengthException("in buffer too short");
        }

        data.write(in, inOff, len);

        return 0;
    }

    public void processAADByte(byte in) {
        associatedText.write(in);
    }

    public void processAADBytes(byte[] in, int inOff, int len) {
        if (in.length < (inOff + len)) {
            throw new DataLengthException("in buffer too short");
        }

        associatedText.write(in, inOff, len);
    }

    public String getAlgorithmName() {
        return "ChaCha20-Poly1305";
    }

    public byte[] getMac() {
        return lastMacBlock;
    }

    public int getOutputSize(int len) {
        assert mac.getMacSize() == 16;

        int totalData = data.size() + len;

        if (encrypting) {
            return totalData + mac.getMacSize();
        } else {
            return totalData < mac.getMacSize() ? 0 : totalData - mac.getMacSize();
        }
    }

    public int getUpdateOutputSize(int len) {
        // processByte() and processBytes()
        // return 0 and do not modify the output buffer.
        return 0;
    }

    public StreamCipher getUnderlyingCipher() {
        return cipher;
    }

    private byte[] combineAssociatedTexts() {
        if (initializedAssociatedText == null || initializedAssociatedText.length == 0) {
            // no associated text provided by a AEADParameter at
            // initialization, just use the accumulated associatedText

            return Arrays.copyOf(associatedText.getBuffer(), associatedText.size());
        } else {
            // associated text was provided at initialization by
            // an AEADParameter, prepend that to the accumulated associatedText

            byte[] associatedData = new byte[initializedAssociatedText.length + associatedText.size()];

            System.arraycopy(
                initializedAssociatedText,
                0, associatedData,
                0, initializedAssociatedText.length
            );

            System.arraycopy(
                associatedText.getBuffer(),
                0, associatedData,
                initializedAssociatedText.length, associatedText.size()
            );

            return associatedData;
        }
    }

    /**
     * Initialize the Mac with a one-time key generated according to RFC 7539:
     *
     * <pre>
     * poly1305_key_gen(key,nonce):
     *      counter = 0
     *      block = chacha20_block(key,counter,nonce)
     *      return block[0..31]
     *      end
     * </pre>
     *
     * @param mac    a {@link Poly1305} Mac instance to initialize.
     * @param cipher a {@link ChaCha7539Engine} cipher pre-initialized with the nonce and key.
     */
    private static void initMac(Poly1305 mac, ExposedChaCha7539Engine cipher) {
        if (cipher.getCounter() != 0L) {
            throw new IllegalStateException("cipher not reset (counter != 0)");
        }

        byte[] firstBlock = new byte[64];
        cipher.processBytes(firstBlock, 0, 64, firstBlock, 0);
        mac.init(new KeyParameter(firstBlock, 0, 32));
        Arrays.fill(firstBlock, (byte) 0);
    }

    /**
     * Update {@code mac} with the {@code len} bytes from {@code buf}, starting at {@code off}.
     * <p>
     * If {@code len} is not an integral multiple of 16 then up to 15 zero bytes will be added as padding.
     *
     * @param mac the {@link Mac} to update.
     * @param buf the data to update from.
     * @param off the offset within {@code bytes} to start updating from.
     * @param len the length of the data to read starting at {@code off}.
     */
    private static void updateMac(Mac mac, byte[] buf, int off, int len) {
        if (buf == null || buf.length == 0) {
            return;
        }

        mac.update(buf, off, len);

        int partial = len % 16;

        if (partial != 0) {
            mac.update(ZEROES, 0, 16 - partial);
        }
    }

    /**
     * Validate that {@code nonce} is exactly 96-bit (12 bytes).
     *
     * @param nonce the nonce bytes to validate.
     */
    private static void validateNonce(byte[] nonce) {
        if (nonce == null || nonce.length != 12) {
            throw new IllegalArgumentException("nonce length must be 12 bytes");
        }
    }

    /**
     * Validate that {@code parameters} is a {@link KeyParameter} with a 256-bit key.
     *
     * @param parameters a {@link CipherParameters} to validate.
     */
    private static void validateKeyParameter(CipherParameters parameters) {
        if (!(parameters instanceof KeyParameter)) {
            throw new IllegalArgumentException("KeyParameter required");
        }

        byte[] key = ((KeyParameter) parameters).getKey();

        if (key == null || key.length != 32) {
            throw new IllegalArgumentException("256-bit key required");
        }
    }

    private static class ExposedByteArrayOutputStream extends ByteArrayOutputStream {

        ExposedByteArrayOutputStream() {
            super();
        }

        public byte[] getBuffer() {
            return this.buf;
        }

    }

    private static class ExposedChaCha7539Engine extends ChaCha7539Engine {

        @Override
        protected long getCounter() {
            return super.getCounter();
        }

    }

}
