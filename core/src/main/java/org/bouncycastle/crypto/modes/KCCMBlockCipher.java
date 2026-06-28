package org.bouncycastle.crypto.modes;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * Implementation of DSTU7624 CCM mode.
 * <p>
 * <b>Partial-block / interop caveat:</b> messages whose length is not a multiple of the
 * underlying block size are handled following the generic CCM construction
 * (NIST SP 800-38C / RFC 3610): the CBC-MAC zero-pads the trailing partial block and the
 * counter (gamma) keystream is truncated for the trailing partial block. DSTU 7624:2014
 * does not publish a partial-block CCM test vector, so this behaviour is verified by
 * round-trip self-consistency only and has <b>not</b> been confirmed against an independent
 * conformant DSTU 7624 implementation. Callers requiring guaranteed interoperability with
 * other DSTU 7624 CCM implementations should restrict input to whole blocks until such a
 * vector is available. See github #287.
 * </p>
 */
public class KCCMBlockCipher
    implements AEADBlockCipher
{

    private static final int BYTES_IN_INT = 4;
    private static final int BITS_IN_BYTE = 8;

    private static final int MAX_MAC_BIT_LENGTH = 512;
    private static final int MIN_MAC_BIT_LENGTH = 64;

    private BlockCipher engine;

    private int macSize;
    private boolean forEncryption;

    private byte[] initialAssociatedText;
    private byte[] mac;
    private byte[] macBlock;

    private byte[] nonce;
    // Previous key seen on init(true, ...) - used with nonce only to reject nonce reuse for encryption.
    private byte[] lastKey;

    private byte[] G1;
    private byte[] buffer;

    private byte[] s;
    private byte[] counter;


    private ExposedByteArrayOutputStream associatedText = new ExposedByteArrayOutputStream();
    private ExposedByteArrayOutputStream data = new ExposedByteArrayOutputStream();


    private int Nb_ = 4;

    private void setNb(int Nb)
    {
        if (Nb == 4 || Nb == 6 || Nb == 8)
        {
            Nb_ = Nb;
        }
        else
        {
            throw new IllegalArgumentException("Nb = 4 is recommended by DSTU7624 but can be changed to only 6 or 8 in this implementation");
        }
    }

    /**
     * Base constructor. Nb value is set to 4.
     *
     * @param engine base cipher to use under CCM.
     */
    public KCCMBlockCipher(BlockCipher engine)
    {
        this(engine, 4);
    }

    /**
     * Constructor allowing Nb configuration.
     * <p>
     * Nb is a parameter specified in CCM mode of DSTU7624 standard.
     * This parameter specifies maximum possible length of input. It should
     * be calculated as follows: Nb = 1/8 * (-3 + log[2]Nmax) + 1,
     * where Nmax - length of input message in bits. For practical reasons
     * Nmax usually less than 4Gb, e.g. for Nmax = 2^32 - 1, Nb = 4.
     * </p>
     * @param engine base cipher to use under CCM.
     * @param nB Nb value to use.
     */
    public KCCMBlockCipher(BlockCipher engine, int nB)
    {
        this.engine = engine;
        this.macSize = engine.getBlockSize();
        this.nonce = new byte[engine.getBlockSize()];
        this.initialAssociatedText = new byte[engine.getBlockSize()];
        this.mac = new byte[engine.getBlockSize()];
        this.macBlock = new byte[engine.getBlockSize()];
        this.G1 = new byte[engine.getBlockSize()];
        this.buffer = new byte[engine.getBlockSize()];
        this.s = new byte[engine.getBlockSize()];
        this.counter = new byte[engine.getBlockSize()];
        setNb(nB);
    }

    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {
        KeyParameter keyParameter = null;
        byte[] newNonce;
        if (params instanceof AEADParameters)
        {
            AEADParameters aeadParameters = (AEADParameters)params;

            int macSizeInBits = aeadParameters.getMacSize();
            if (macSizeInBits > MAX_MAC_BIT_LENGTH || macSizeInBits < MIN_MAC_BIT_LENGTH || macSizeInBits % 8 != 0)
            {
                throw new IllegalArgumentException("Invalid mac size specified");
            }

            newNonce = aeadParameters.getNonce();
            macSize = macSizeInBits / BITS_IN_BYTE;
            initialAssociatedText = aeadParameters.getAssociatedText();
            keyParameter = aeadParameters.getKey();
        }
        else if (params instanceof ParametersWithIV)
        {
            ParametersWithIV withIV = (ParametersWithIV)params;

            newNonce = withIV.getIV();
            macSize = engine.getBlockSize(); // use default blockSize for MAC if it is not specified
            initialAssociatedText = null;

            CipherParameters innerParameters = withIV.getParameters();
            if (innerParameters != null)
            {
                if (!(innerParameters instanceof KeyParameter))
                {
                    throw new IllegalArgumentException("invalid parameters passed to KCCM");
                }

                keyParameter = (KeyParameter)innerParameters;
            }
        }
        else
        {
            throw new IllegalArgumentException("invalid parameters passed to KCCM");
        }

        // RFC 5116 sec. 2.1 requires a distinct nonce per AEAD encryption under a given key; the
        // DSTU 7624 CCM construction inherits this CCM rule (cf. NIST SP 800-38C), and reuse is
        // catastrophic (CTR keystream reuse plus a forgeable CBC-MAC). That obligation is the
        // caller's, so this guard enforces it defensively, mirroring KGCMBlockCipher /
        // GCMBlockCipher. A fresh nonce or key, reset(), or init for decryption are all unaffected.
        if (forEncryption)
        {
            if (nonce != null && Arrays.areEqual(nonce, newNonce))
            {
                if (keyParameter == null)
                {
                    throw new IllegalArgumentException("cannot reuse nonce for KCCM encryption");
                }
                if (lastKey != null && Arrays.constantTimeAreEqual(lastKey, keyParameter.getKey()))
                {
                    throw new IllegalArgumentException("cannot reuse nonce for KCCM encryption");
                }
            }
        }

        nonce = newNonce;
        if (keyParameter != null)
        {
            lastKey = keyParameter.getKey();
        }

        this.mac = new byte[macSize];
        this.forEncryption = forEncryption;

        engine.init(true, keyParameter);

        reset();
    }

    public String getAlgorithmName()
    {
        return engine.getAlgorithmName() + "/KCCM";
    }

    public BlockCipher getUnderlyingCipher()
    {
        return engine;
    }

    public void processAADByte(byte in)
    {
        associatedText.write(in);
    }

    public void processAADBytes(byte[] in, int inOff, int len)
    {
        associatedText.write(in, inOff, len);
    }

    private void processAssociatedText()
    {
        int aadLen = associatedText.size();

        boolean hasAssocText = aadLen > 0;

        if (hasAssocText && aadLen % engine.getBlockSize() != 0)
        {
            throw new IllegalArgumentException("padding not supported");
        }

        // The G1 block binds the nonce, data length and MAC-size flag into the MAC and must be
        // processed unconditionally. DSTU 7624 carries the associated-data-present indicator as a flag
        // bit inside G1, so it is not a gate on computing G1: skipping G1 when no AAD is present leaves
        // the MAC independent of the nonce and enables cross-nonce forgery.
        System.arraycopy(nonce, 0, G1, 0, nonce.length - Nb_ - 1);

        int dataLen = data.size() - (forEncryption ? 0 : macSize);
        Pack.intToLittleEndian(dataLen, buffer, 0); // for G1

        System.arraycopy(buffer, 0, G1, nonce.length - Nb_ - 1, BYTES_IN_INT);

        G1[G1.length - 1] = getFlag(hasAssocText, macSize);

        engine.processBlock(G1, 0, macBlock, 0);

        if (!hasAssocText)
        {
            return;
        }

        Pack.intToLittleEndian(aadLen, buffer, 0); // for G2

        byte[] aad = associatedText.getBuffer();

        if (aadLen <= engine.getBlockSize() - Nb_)
        {
            for (int byteIndex = 0; byteIndex < aadLen; byteIndex++)
            {
                buffer[byteIndex + Nb_] ^= aad[byteIndex];
            }

            for (int byteIndex = 0; byteIndex < engine.getBlockSize(); byteIndex++)
            {
                macBlock[byteIndex] ^= buffer[byteIndex];
            }

            engine.processBlock(macBlock, 0, macBlock, 0);

            return;
        }

        for (int byteIndex = 0; byteIndex < engine.getBlockSize(); byteIndex++)
        {
            macBlock[byteIndex] ^= buffer[byteIndex];
        }

        engine.processBlock(macBlock, 0, macBlock, 0);

        int assocOff = 0;
        int authLen = aadLen;
        while (authLen != 0)
        {
            for (int byteIndex = 0; byteIndex < engine.getBlockSize(); byteIndex++)
            {
                macBlock[byteIndex] ^= aad[byteIndex + assocOff];
            }

            engine.processBlock(macBlock, 0, macBlock, 0);

            assocOff += engine.getBlockSize();
            authLen -= engine.getBlockSize();
        }
    }

    public int processByte(byte in, byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {
        data.write(in);

        return 0;
    }

    public int processBytes(byte[] in, int inOff, int inLen, byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {
        if (in.length < (inOff + inLen))
        {
            throw new DataLengthException("input buffer too short");
        }
        data.write(in, inOff, inLen);

        return 0;
    }

    public int processPacket(byte[] in, int inOff, int len, byte[] out, int outOff)
        throws IllegalStateException, InvalidCipherTextException
    {
        if (in.length - inOff < len)
        {
            throw new DataLengthException("input buffer too short");
        }

        processAssociatedText();

        if (forEncryption)
        {
            if (out.length - outOff < len + macSize)
            {
                throw new OutputLengthException("output buffer too short");
            }

            // Partial trailing block permitted: CalculateMac zero-pads it and the gamma
            // keystream is truncated below. See the interop caveat in the class javadoc (github #287).
            CalculateMac(in, inOff, len);
            engine.processBlock(nonce, 0, s, 0);

            int totalLength = len;
            while (totalLength > 0)
            {
                int blockLen = Math.min(totalLength, engine.getBlockSize());
                ProcessBlock(in, inOff, blockLen, out, outOff);
                totalLength -= blockLen;
                inOff += blockLen;
                outOff += blockLen;
            }

            advanceGamma();

            engine.processBlock(s, 0, buffer, 0);

            for (int byteIndex = 0; byteIndex < macSize; byteIndex++)
            {
                out[outOff + byteIndex] = (byte)(buffer[byteIndex] ^ macBlock[byteIndex]);
            }

            System.arraycopy(macBlock, 0, mac, 0, macSize);
            
            reset();

            return len + macSize;
        }
        else
        {
            if (len < macSize)
            {
                throw new InvalidCipherTextException("data too short");
            }

            int dataLen = len - macSize;

            if (out.length - outOff < dataLen)
            {
                throw new OutputLengthException("output buffer too short");
            }

            engine.processBlock(nonce, 0, s, 0);

            // Recover the plaintext into a private buffer and verify the MAC before writing any of it
            // to the caller's output: on a tag failure the caller's buffer must not be left holding
            // unverified gamma plaintext (matches CCMBlockCipher / GCMSIVBlockCipher). A partial
            // trailing block is permitted: the gamma keystream is truncated for the trailing block
            // and CalculateMac zero-pads it. See the interop caveat in the class javadoc (github #287).
            byte[] plain = new byte[dataLen];
            int plainOff = 0;
            int inPos = inOff;
            int totalLength = dataLen;
            while (totalLength > 0)
            {
                int blockLen = Math.min(totalLength, engine.getBlockSize());
                ProcessBlock(in, inPos, blockLen, plain, plainOff);
                totalLength -= blockLen;
                inPos += blockLen;
                plainOff += blockLen;
            }

            // recover the appended (masked) MAC using the next keystream block
            advanceGamma();

            engine.processBlock(s, 0, buffer, 0);

            byte[] recoveredMac = new byte[macSize];
            for (int byteIndex = 0; byteIndex < macSize; byteIndex++)
            {
                recoveredMac[byteIndex] = (byte)(buffer[byteIndex] ^ in[inPos + byteIndex]);
            }

            // recompute the MAC over the recovered plaintext and compare
            CalculateMac(plain, 0, dataLen);

            System.arraycopy(macBlock, 0, mac, 0, macSize);

            if (!Arrays.constantTimeAreEqual(mac, recoveredMac))
            {
                Arrays.clear(plain);
                throw new InvalidCipherTextException("mac check failed");
            }

            // Only now (MAC verified) expose the recovered plaintext in the caller's output. The MAC
            // is not written to the output - it is consumed for verification and is available via
            // getMac() - matching the standard AEAD contract (CCMBlockCipher / GCMBlockCipher / KGCM).
            System.arraycopy(plain, 0, out, outOff, dataLen);

            reset();

            return dataLen;
        }
    }

    private void ProcessBlock(byte[] input, int inOff, int blockLen, byte[] output, int outOff)
    {
        advanceGamma();

        engine.processBlock(s, 0, buffer, 0);

        // blockLen == engine.getBlockSize() for a full block; a shorter value truncates the
        // gamma keystream for a trailing partial block.
        for (int byteIndex = 0; byteIndex < blockLen; byteIndex++)
        {
            output[outOff + byteIndex] = (byte)(buffer[byteIndex] ^ input[inOff + byteIndex]);
        }
    }

    /**
     * Advance the gamma counter by adding {@code counter} to {@code s} as a little-endian
     * multi-byte integer with carry propagation (counter[0] is the least significant byte).
     * The carry must propagate across the whole block: without it only s[0] ever changes, so
     * the keystream block E(s) repeats every 256 blocks and any message longer than 255 blocks
     * is encrypted with a repeating keystream (a two-time pad). See github #287.
     */
    private void advanceGamma()
    {
        int carry = 0;
        for (int byteIndex = 0; byteIndex < counter.length; byteIndex++)
        {
            carry += (s[byteIndex] & 0xFF) + (counter[byteIndex] & 0xFF);
            s[byteIndex] = (byte)carry;
            carry >>>= 8;
        }
    }

    private void CalculateMac(byte[] authText, int authOff, int len)
    {
        int totalLen = len;
        while (totalLen > 0)
        {
            // A trailing partial block is XORed in over its actual length only; the remaining
            // bytes of macBlock are left unchanged, i.e. the block is zero-padded.
            int blockLen = Math.min(totalLen, engine.getBlockSize());
            for (int byteIndex = 0; byteIndex < blockLen; byteIndex++)
            {
                macBlock[byteIndex] ^= authText[authOff + byteIndex];
            }

            engine.processBlock(macBlock, 0, macBlock, 0);

            totalLen -= blockLen;
            authOff += blockLen;
        }
    }

    public int doFinal(byte[] out, int outOff)
        throws IllegalStateException, InvalidCipherTextException
    {
        int len = processPacket(data.getBuffer(), 0, data.size(), out, outOff);

        reset();

        return len;
    }

    public byte[] getMac()
    {
        return Arrays.clone(mac);
    }

    public int getUpdateOutputSize(int len)
    {
        return len;
    }

    public int getOutputSize(int len)
    {
        int totalData = len + data.size();

        if (forEncryption)
        {
            return totalData + macSize;
        }

        return totalData < macSize ? 0 : totalData - macSize;
    }

    public void reset()
    {
        Arrays.fill(G1, (byte)0);
        Arrays.fill(buffer, (byte)0);
        Arrays.fill(counter, (byte)0);
        Arrays.fill(macBlock, (byte)0);
        counter[0] = 0x01; // defined in standard
        data.reset();
        associatedText.reset();

        if (initialAssociatedText != null)
        {
            processAADBytes(initialAssociatedText, 0, initialAssociatedText.length);
        }
    }

    private byte getFlag(boolean authTextPresents, int macSize)
    {
        StringBuilder flagByte = new StringBuilder();

        if (authTextPresents)
        {
            flagByte.append("1");
        }
        else
        {
            flagByte.append("0");
        }


        switch (macSize)
        {
        case 8:
            flagByte.append("010"); // binary 2
            break;
        case 16:
            flagByte.append("011"); // binary 3
            break;
        case 32:
            flagByte.append("100"); // binary 4
            break;
        case 48:
            flagByte.append("101"); // binary 5
            break;
        case 64:
            flagByte.append("110"); // binary 6
            break;
        }

        String binaryNb = Integer.toBinaryString(Nb_ - 1);
        while (binaryNb.length() < 4)
        {
            binaryNb = new StringBuilder(binaryNb).insert(0, "0").toString();
        }

        flagByte.append(binaryNb);

        return (byte)Integer.parseInt(flagByte.toString(), 2);

    }

    private static class ExposedByteArrayOutputStream
        extends ByteArrayOutputStream
    {
        ExposedByteArrayOutputStream()
        {
        }

        byte[] getBuffer()
        {
            return this.buf;
        }
    }

}
