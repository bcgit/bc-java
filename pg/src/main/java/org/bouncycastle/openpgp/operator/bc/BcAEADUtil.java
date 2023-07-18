package org.bouncycastle.openpgp.operator.bc;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.AEADUtils;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyUtils;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.EAXBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.OCBBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.io.Streams;

public class BcAEADUtil
{
    /**
     * Generate a nonce by xor-ing the given iv with the chunk index.
     *
     * @param iv         initialization vector
     * @param chunkIndex chunk index
     * @return nonce
     */
    protected static byte[] getNonce(byte[] iv, long chunkIndex)
    {
        byte[] nonce = Arrays.clone(iv);

        xorChunkId(nonce, chunkIndex);

        return nonce;
    }

    /**
     * XOR the byte array with the chunk index in-place.
     *
     * @param nonce      byte array
     * @param chunkIndex chunk index
     */
    protected static void xorChunkId(byte[] nonce, long chunkIndex)
    {
        int index = nonce.length - 8;

        nonce[index++] ^= (byte)(chunkIndex >> 56);
        nonce[index++] ^= (byte)(chunkIndex >> 48);
        nonce[index++] ^= (byte)(chunkIndex >> 40);
        nonce[index++] ^= (byte)(chunkIndex >> 32);
        nonce[index++] ^= (byte)(chunkIndex >> 24);
        nonce[index++] ^= (byte)(chunkIndex >> 16);
        nonce[index++] ^= (byte)(chunkIndex >> 8);
        nonce[index] ^= (byte)(chunkIndex);
    }

    /**
     * Calculate an actual chunk length from the encoded chunk size.
     *
     * @param chunkSize encoded chunk size
     * @return decoded length
     */
    protected static long getChunkLength(int chunkSize)
    {
        return 1L << (chunkSize + 6);
    }

    /**
     * Derive a message key and IV from the given session key.
     * The result is two byte arrays containing the key bytes and the IV.
     *
     * @param aeadAlgo   AEAD algorithm
     * @param cipherAlgo symmetric cipher algorithm
     * @param sessionKey session key
     * @param salt       salt
     * @param hkdfInfo   HKDF info
     * @return message key and separate IV
     * @throws PGPException
     */
    static byte[][] deriveMessageKeyAndIv(int aeadAlgo, int cipherAlgo, byte[] sessionKey, byte[] salt, byte[] hkdfInfo)
        throws PGPException
    {
        HKDFParameters hkdfParameters = new HKDFParameters(sessionKey, salt, hkdfInfo);
        HKDFBytesGenerator hkdfGen = new HKDFBytesGenerator(new SHA256Digest());

        hkdfGen.init(hkdfParameters);
        int keyLen = SymmetricKeyUtils.getKeyLengthInOctets(cipherAlgo);
        int ivLen = AEADUtils.getIVLength(aeadAlgo);
        byte[] messageKeyAndIv = new byte[keyLen + ivLen - 8];
        hkdfGen.generateBytes(messageKeyAndIv, 0, messageKeyAndIv.length);

        return new byte[][] { Arrays.copyOfRange(messageKeyAndIv, 0, keyLen), Arrays.copyOfRange(messageKeyAndIv, keyLen, keyLen + ivLen) };
    }

    public static AEADBlockCipher createAEADCipher(int encAlgorithm, int aeadAlgorithm)
        throws PGPException
    {
        if (encAlgorithm != SymmetricKeyAlgorithmTags.AES_128
            && encAlgorithm != SymmetricKeyAlgorithmTags.AES_192
            && encAlgorithm != SymmetricKeyAlgorithmTags.AES_256)
        {
            // Block Cipher must work on 16 byte blocks
            throw new PGPException("AEAD only supported for AES based algorithms");
        }

        switch (aeadAlgorithm)
        {
        case AEADAlgorithmTags.EAX:
            return new EAXBlockCipher(AESEngine.newInstance());
        case AEADAlgorithmTags.OCB:
            return new OCBBlockCipher(AESEngine.newInstance(), AESEngine.newInstance());
        case AEADAlgorithmTags.GCM:
            return GCMBlockCipher.newInstance(AESEngine.newInstance());
        default:
            throw new PGPException("unrecognised AEAD algorithm: " + aeadAlgorithm);
        }
    }

    /**
     * Create a decryptor for OpenPGP v5 AED (AEAD Encrypted Data) packets.
     * This is type of packet is used by GnuPG.
     * For version 2 SEIPD packets used in OpenPGP v6, see
     * {@link #createOpenPgpV6DataDecryptor(SymmetricEncIntegrityPacket, PGPSessionKey)} instead.
     *
     * @param aeadEncDataPacket AEAD encrypted data packet
     * @param sessionKey        session key retrieved from a version 5 symmetric-key encrypted session key packet
     *                          or version 3 public-key encrypted session key packet.
     * @return decryptor for AEAD encrypted data packets
     * @throws PGPException
     */
    static PGPDataDecryptor createOpenPgpV5DataDecryptor(AEADEncDataPacket aeadEncDataPacket, PGPSessionKey sessionKey)
        throws PGPException
    {
        final int aeadAlgorithm = aeadEncDataPacket.getAEADAlgorithm();
        final byte[] iv = aeadEncDataPacket.getIV();
        final int chunkSize = aeadEncDataPacket.getChunkSize();
        final int encAlgorithm = sessionKey.getAlgorithm();
        final byte[] key = sessionKey.getKey();
        final byte[] aaData = aeadEncDataPacket.getAAData();

        final KeyParameter secretKey = new KeyParameter(key);

        final AEADBlockCipher c = createAEADCipher(encAlgorithm, aeadAlgorithm);

        return new PGPDataDecryptor()
        {
            public InputStream getInputStream(InputStream in)
            {
                try
                {
                    return new PGPAeadInputStream(true, in, c, secretKey, iv, encAlgorithm, aeadAlgorithm, chunkSize, aaData);
                }
                catch (IOException e)
                {
                    throw Exceptions.illegalStateException("unable to open stream: " + e.getMessage(), e);
                }
            }

            public int getBlockSize()
            {
                return c.getUnderlyingCipher().getBlockSize();
            }

            public PGPDigestCalculator getIntegrityCalculator()
            {
                return new SHA1PGPDigestCalculator();
            }
        };
    }

    /**
     * Create a data decryptor for SEIPD v2 packets used in OpenPGP v6.
     * Those are symmetrically encrypted integrity protected data packets that make use of AEAD.
     *
     * @param seipd      version 2 symmetrically encrypted integrity-protected data packet
     * @param sessionKey session key as retrieved from a version 6 symmetric- or public-key-encrypted session key packet.
     * @return decryptor
     * @throws PGPException
     */
    static PGPDataDecryptor createOpenPgpV6DataDecryptor(SymmetricEncIntegrityPacket seipd, PGPSessionKey sessionKey)
        throws PGPException
    {
        // We cannot handle v1 SEIPD packets in this method (OpenPGP v4)
        if (seipd.getVersion() == SymmetricEncIntegrityPacket.VERSION_1)
        {
            throw new PGPException("SEIPD packet MUST be of version 2 or greater.");
        }

        final int cipherAlgo = seipd.getCipherAlgorithm();
        final int aeadAlgo = seipd.getAeadAlgorithm();
        final int chunkSize = seipd.getChunkSize();
        final byte[] aaData = seipd.getAAData();

        byte[][] messageKeyAndIv = deriveMessageKeyAndIv(aeadAlgo, cipherAlgo,
            sessionKey.getKey(), seipd.getSalt(), aaData);
        byte[] messageKey = messageKeyAndIv[0];
        final byte[] iv = messageKeyAndIv[1];

        final KeyParameter secretKey = new KeyParameter(messageKey);
        final AEADBlockCipher c = createAEADCipher(cipherAlgo, aeadAlgo);

        return new PGPDataDecryptor()
        {
            public InputStream getInputStream(InputStream in)
            {
                try
                {
                    return new PGPAeadInputStream(false, in, c, secretKey, iv, cipherAlgo, aeadAlgo, chunkSize, aaData);
                }
                catch (IOException e)
                {
                    throw Exceptions.illegalStateException("unable to open stream: " + e.getMessage(), e);
                }
            }

            public int getBlockSize()
            {
                return c.getUnderlyingCipher().getBlockSize();
            }

            public PGPDigestCalculator getIntegrityCalculator()
            {
                return new SHA1PGPDigestCalculator();
            }
        };
    }

    protected static class PGPAeadInputStream
        extends InputStream
    {
        private final InputStream in;
        private final byte[] buf;
        private final AEADBlockCipher c;
        private final KeyParameter secretKey;
        private final byte[] aaData;
        private final byte[] iv;
        private final int chunkLength;
        private final int tagLen;

        private byte[] data;
        private int dataOff;
        private long chunkIndex = 0;
        private long totalBytes = 0;
        private final boolean isV5StyleAEAD;

        /**
         * InputStream for decrypting AEAD encrypted data.
         *
         * @param isV5StyleAEAD       flavour of AEAD (OpenPGP v5 or v6)
         * @param in            underlying InputStream
         * @param c             decryption cipher
         * @param secretKey     decryption key
         * @param iv            initialization vector
         * @param encAlgorithm  symmetric cipher algorithm
         * @param aeadAlgorithm AEAD algorithm
         * @param chunkSize     chunk size of the AEAD encryption
         * @param aaData        associated data
         * @throws IOException
         */
        public PGPAeadInputStream(boolean isV5StyleAEAD, InputStream in,
                                  AEADBlockCipher c,
                                  KeyParameter secretKey,
                                  byte[] iv,
                                  int encAlgorithm,
                                  int aeadAlgorithm,
                                  int chunkSize,
                                  byte[] aaData)
            throws IOException
        {
            this.isV5StyleAEAD = isV5StyleAEAD;
            this.in = in;
            this.iv = iv;
            this.chunkLength = (int)getChunkLength(chunkSize);
            this.tagLen = AEADUtils.getAuthTagLength(aeadAlgorithm);
            this.buf = new byte[chunkLength + tagLen + tagLen]; // allow room for chunk tag and message tag
            this.c = c;
            this.secretKey = secretKey;
            this.aaData = aaData;

            // prime with 2 * tag len bytes.
            Streams.readFully(in, buf, 0, tagLen + tagLen);

            // load the first block
            this.data = readBlock();
            this.dataOff = 0;
        }

        public int read()
            throws IOException
        {
            if (data != null && dataOff == data.length)
            {
                this.data = readBlock();
                this.dataOff = 0;
            }

            if (this.data == null)
            {
                return -1;
            }

            return data[dataOff++] & 0xff;
        }

        public int read(byte[] b, int off, int len)
            throws IOException
        {
            if (data != null && dataOff == data.length)
            {
                this.data = readBlock();
                this.dataOff = 0;
            }

            if (this.data == null)
            {
                return -1;
            }

            int supplyLen = Math.min(len, available());
            System.arraycopy(data, dataOff, b, off, supplyLen);
            dataOff += supplyLen;

            return supplyLen;
        }

        public long skip(long n)
            throws IOException
        {
            if (n <= 0)
            {
                return 0;
            }

            int skip = (int)Math.min(n, available());
            dataOff += skip;
            return skip;
        }

        public int available()
            throws IOException
        {
            if (data != null && dataOff == data.length)
            {
                this.data = readBlock();
                this.dataOff = 0;
            }

            if (this.data == null)
            {
                return -1;
            }

            return data.length - dataOff;
        }

        private byte[] readBlock()
            throws IOException
        {
            // we initialise with the first 16 bytes as there is an additional 16 bytes following
            // the last chunk (which may not be the exact chunklength).
            int dataLen = Streams.readFully(in, buf, tagLen + tagLen, chunkLength);
            if (dataLen == 0)
            {
                return null;
            }

            byte[] adata = new byte[isV5StyleAEAD ? 13 : aaData.length];
            System.arraycopy(aaData, 0, adata, 0, aaData.length);

            if (isV5StyleAEAD)
            {
                xorChunkId(adata, chunkIndex);
            }

            byte[] decData = new byte[dataLen];
            try
            {
                c.init(false, new AEADParameters(secretKey, 128, getNonce(iv, chunkIndex)));  // always full tag.

                c.processAADBytes(adata, 0, adata.length);

                int len = c.processBytes(buf, 0, dataLen + tagLen, decData, 0);

                c.doFinal(decData, len);
            }
            catch (InvalidCipherTextException e)
            {
                throw new IOException("exception processing chunk " + chunkIndex + ": " + e.getMessage());
            }

            totalBytes += decData.length;
            chunkIndex++;

            System.arraycopy(buf, dataLen + tagLen, buf, 0, tagLen); // copy back the "tag"

            if (dataLen != chunkLength)     // it's our last block
            {
                if (isV5StyleAEAD)
                {
                    adata = new byte[13];
                    System.arraycopy(aaData, 0, adata, 0, aaData.length);
                    xorChunkId(adata, chunkIndex);
                }
                else
                {
                    adata = new byte[aaData.length + 8];
                    System.arraycopy(aaData, 0, adata, 0, aaData.length);
                    System.arraycopy(Pack.longToBigEndian(totalBytes), 0, adata, aaData.length, 8);
                }

                try
                {
                    c.init(false, new AEADParameters(secretKey, 128, getNonce(iv, chunkIndex)));  // always full tag.

                    c.processAADBytes(adata, 0, adata.length);
                    if (isV5StyleAEAD)
                    {
                        c.processAADBytes(Pack.longToBigEndian(totalBytes), 0, 8);
                    }

                    c.processBytes(buf, 0, tagLen, buf, 0);

                    c.doFinal(buf, 0); // check final tag
                }
                catch (InvalidCipherTextException e)
                {
                    throw new IOException("exception processing final tag: " + e.getMessage());
                }
            }
            else
            {
                Streams.readFully(in, buf, tagLen, tagLen);   // read the next tag bytes
            }

            return decData;
        }
    }

    protected static class PGPAeadOutputStream
        extends OutputStream
    {
        private final boolean isV5StyleAEAD;
        private final OutputStream out;
        private final byte[] data;
        private final AEADBlockCipher c;
        private final KeyParameter secretKey;
        private final byte[] aaData;
        private final byte[] iv;
        private final int chunkLength;
        private final int tagLen;

        private int dataOff;
        private long chunkIndex = 0;
        private long totalBytes = 0;

        /**
         * OutputStream for AEAD encryption.
         *
         * @param isV5StyleAEAD flavour of AEAD (OpenPGP v5 or v6)
         * @param out           underlying OutputStream
         * @param c             AEAD cipher
         * @param secretKey     secret key
         * @param iv            initialization vector
         * @param encAlgorithm  encryption algorithm
         * @param aeadAlgorithm aead algorithm
         * @param chunkSize     chunk size of the AEAD encryption
         */
        public PGPAeadOutputStream(boolean isV5StyleAEAD,
                                   OutputStream out,
                                   AEADBlockCipher c,
                                   KeyParameter secretKey,
                                   byte[] iv, int encAlgorithm,
                                   int aeadAlgorithm,
                                   int chunkSize)
        {
            this.isV5StyleAEAD = isV5StyleAEAD;
            this.out = out;
            this.iv = iv;
            this.chunkLength = (int)getChunkLength(chunkSize);
            this.tagLen = AEADUtils.getAuthTagLength(aeadAlgorithm);
            this.data = new byte[chunkLength];
            this.c = c;
            this.secretKey = secretKey;

            aaData = createAAD(isV5StyleAEAD, encAlgorithm, aeadAlgorithm, chunkSize);
        }

        private byte[] createAAD(boolean isV5StyleAEAD, int encAlgorithm, int aeadAlgorithm, int chunkSize)
        {
            if (isV5StyleAEAD)
            {
                return AEADEncDataPacket.createAAData(AEADEncDataPacket.VERSION_1, encAlgorithm, aeadAlgorithm, chunkSize);
            }
            else
            {
                return SymmetricEncIntegrityPacket.createAAData(SymmetricEncIntegrityPacket.VERSION_2, encAlgorithm, aeadAlgorithm, chunkSize);
            }
        }

        public void write(int b)
            throws IOException
        {
            if (dataOff == data.length)
            {
                writeBlock();
            }
            data[dataOff++] = (byte)b;
        }

        public void write(byte[] b, int off, int len)
            throws IOException
        {
            if (dataOff == data.length)
            {
                writeBlock();
            }

            if (len < data.length - dataOff)
            {
                System.arraycopy(b, off, data, dataOff, len);
                dataOff += len;
            }
            else
            {
                int gap = data.length - dataOff;
                System.arraycopy(b, off, data, dataOff, gap);
                dataOff += gap;
                writeBlock();

                len -= gap;
                off += gap;

                while (len >= data.length)
                {
                    System.arraycopy(b, off, data, 0, data.length);
                    dataOff = data.length;
                    writeBlock();
                    len -= data.length;
                    off += data.length;
                }

                if (len > 0)
                {
                    System.arraycopy(b, off, data, 0, len);
                    dataOff = len;
                }
            }
        }

        public void close()
            throws IOException
        {
            finish();
        }

        private void writeBlock()
            throws IOException
        {
            boolean v5StyleAEAD = isV5StyleAEAD;

            byte[] adata = v5StyleAEAD ? new byte[13] : new byte[aaData.length];
            System.arraycopy(aaData, 0, adata, 0, aaData.length);

            if (v5StyleAEAD)
            {
                xorChunkId(adata, chunkIndex);
            }

            try
            {
                c.init(true, new AEADParameters(secretKey, 128, getNonce(iv, chunkIndex)));  // always full tag.
                c.processAADBytes(adata, 0, adata.length);

                int len = c.processBytes(data, 0, dataOff, data, 0);
                out.write(data, 0, len);

                len = c.doFinal(data, 0);
                out.write(data, 0, len);
            }
            catch (InvalidCipherTextException e)
            {
                throw new IOException("exception processing chunk " + chunkIndex + ": " + e.getMessage());
            }

            totalBytes += dataOff;
            chunkIndex++;
            dataOff = 0;
        }

        private void finish()
            throws IOException
        {
            if (dataOff > 0)
            {
                writeBlock();
            }


            byte[] adata;
            boolean v5StyleAEAD = isV5StyleAEAD;
            if (v5StyleAEAD)
            {
                adata = new byte[13];
                System.arraycopy(aaData, 0, adata, 0, aaData.length);
                xorChunkId(adata, chunkIndex);
            }
            else
            {
                adata = new byte[aaData.length + 8];
                System.arraycopy(aaData, 0, adata, 0, aaData.length);
                System.arraycopy(Pack.longToBigEndian(totalBytes), 0, adata, aaData.length, 8);
            }
            try
            {
                c.init(true, new AEADParameters(secretKey, 128, getNonce(iv, chunkIndex)));  // always full tag.
                c.processAADBytes(adata, 0, adata.length);
                if (v5StyleAEAD)
                {
                    c.processAADBytes(Pack.longToBigEndian(totalBytes), 0, 8);
                }

                c.doFinal(data, 0);
                out.write(data, 0, tagLen); // output final tag
            }
            catch (InvalidCipherTextException e)
            {
                throw new IOException("exception processing final tag: " + e.getMessage());
            }
            out.close();
        }
    }
}
