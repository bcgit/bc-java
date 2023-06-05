package org.bouncycastle.openpgp.operator.jcajce;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.AEADUtils;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyUtils;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.io.Streams;

class JceAEADUtil
{
    private final OperatorHelper helper;

    public JceAEADUtil(OperatorHelper helper)
    {
        this.helper = helper;
    }

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
        // TODO: needs to be JCA based. KeyGenerator?
        HKDFParameters hkdfParameters = new HKDFParameters(sessionKey, salt, hkdfInfo);
        HKDFBytesGenerator hkdfGen = new HKDFBytesGenerator(new SHA256Digest());

        hkdfGen.init(hkdfParameters);
        int keyLen = SymmetricKeyUtils.getKeyLengthInOctets(cipherAlgo);
        int ivLen = AEADUtils.getIVLength(aeadAlgo);
        byte[] messageKeyAndIv = new byte[keyLen + ivLen - 8];
        hkdfGen.generateBytes(messageKeyAndIv, 0, messageKeyAndIv.length);

        return new byte[][] { Arrays.copyOfRange(messageKeyAndIv, 0, keyLen), Arrays.copyOfRange(messageKeyAndIv, keyLen, keyLen + ivLen) };
    }
    
    /**
     * Create a {@link PGPDataDecryptor} for decrypting AEAD encrypted OpenPGP v5 data packets.
     *
     * @param aeadEncDataPacket AEAD encrypted data packet
     * @param sessionKey        session key to decrypt the data
     * @return decryptor
     * @throws PGPException
     */
    PGPDataDecryptor createOpenPgpV5DataDecryptor(AEADEncDataPacket aeadEncDataPacket,
                                                  PGPSessionKey sessionKey)
        throws PGPException
    {
        final int aeadAlgorithm = aeadEncDataPacket.getAEADAlgorithm();
        final byte[] iv = aeadEncDataPacket.getIV();
        final int chunkSize = aeadEncDataPacket.getChunkSize();
        final int encAlgorithm = sessionKey.getAlgorithm();
        final byte[] key = sessionKey.getKey();
        final byte[] aaData = aeadEncDataPacket.getAAData();
        try
        {
            final SecretKey secretKey = new SecretKeySpec(key, PGPUtil.getSymmetricCipherName(encAlgorithm));

            final Cipher c = createAEADCipher(encAlgorithm, aeadAlgorithm);

            return new PGPDataDecryptor()
            {
                public InputStream getInputStream(InputStream in)
                {
                    try
                    {
                        return new JceAEADUtil.PGPAeadInputStream(true, in, c, secretKey, iv, encAlgorithm, aeadAlgorithm, chunkSize, aaData);
                    }
                    catch (IOException e)
                    {
                        throw Exceptions.illegalStateException("unable to open stream: " + e.getMessage(), e);
                    }
                }

                public int getBlockSize()
                {
                    return c.getBlockSize();
                }

                public PGPDigestCalculator getIntegrityCalculator()
                {
                    return new SHA1PGPDigestCalculator();
                }
            };
        }
        catch (PGPException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new PGPException("Exception creating cipher", e);
        }
    }

    /**
     * Create a {@link PGPDataDecryptor} for decrypting AEAD encrypted OpenPGP v6 data.
     *
     * @param seipd      version 2 SEIPD packet
     * @param sessionKey session key to decrypt the data
     * @return decryptor
     * @throws PGPException
     */
    PGPDataDecryptor createOpenPgpV6DataDecryptor(SymmetricEncIntegrityPacket seipd,
                                                  PGPSessionKey sessionKey)
        throws PGPException
    {
        final int cipherAlgo = seipd.getCipherAlgorithm();
        final int aeadAlgo = seipd.getAeadAlgorithm();
        final int chunkSize = seipd.getChunkSize();
        final byte[] salt = seipd.getSalt();
        final byte[] aaData = seipd.getAAData();


        final byte[][] messageKeyAndIv = deriveMessageKeyAndIv(aeadAlgo, cipherAlgo, sessionKey.getKey(), salt, aaData);
        final byte[] messageKey = messageKeyAndIv[0];
        final byte[] iv = messageKeyAndIv[1];

        try
        {
            final SecretKey secretKey = new SecretKeySpec(messageKey, PGPUtil.getSymmetricCipherName(cipherAlgo));
            final Cipher c = createAEADCipher(cipherAlgo, aeadAlgo);

            return new PGPDataDecryptor()
            {
                public InputStream getInputStream(InputStream in)
                {
                    try
                    {
                        return new JceAEADUtil.PGPAeadInputStream(false, in, c, secretKey, iv, cipherAlgo, aeadAlgo, chunkSize, aaData);
                    }
                    catch (IOException e)
                    {
                        throw Exceptions.illegalStateException("unable to open stream: " + e.getMessage(), e);
                    }
                }

                public int getBlockSize()
                {
                    return c.getBlockSize();
                }

                public PGPDigestCalculator getIntegrityCalculator()
                {
                    return new SHA1PGPDigestCalculator();
                }
            };
        }
        catch (PGPException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new PGPException("Exception creating cipher", e);
        }
    }

    Cipher createAEADCipher(int encAlgorithm, int aeadAlgorithm)
        throws PGPException
    {
        if (encAlgorithm != SymmetricKeyAlgorithmTags.AES_128
            && encAlgorithm != SymmetricKeyAlgorithmTags.AES_192
            && encAlgorithm != SymmetricKeyAlgorithmTags.AES_256)
        {
            // Block Cipher must work on 16 byte blocks
            throw new PGPException("AEAD only supported for AES based algorithms");
        }

        String mode;
        switch (aeadAlgorithm)
        {
        case AEADAlgorithmTags.EAX:
            mode = "EAX";
            break;
        case AEADAlgorithmTags.OCB:
            mode = "OCB";
            break;
        case AEADAlgorithmTags.GCM:
            mode = "GCM";
            break;
        default:
            throw new PGPException("encountered unknown AEAD algorithm: " + aeadAlgorithm);
        }

        String cName = PGPUtil.getSymmetricCipherName(encAlgorithm)
            + "/" + mode + "/NoPadding";

        return helper.createCipher(cName);
    }


    static class PGPAeadInputStream
        extends InputStream
    {
        private final InputStream in;
        private final byte[] buf;
        private final Cipher c;
        private final SecretKey secretKey;
        private final byte[] aaData;
        private final byte[] iv;
        private final int chunkLength;
        private final int aeadTagLength;

        private byte[] data;
        private int dataOff;
        private long chunkIndex = 0;
        private long totalBytes = 0;
        private boolean v5StyleAEAD;

        /**
         * InputStream for decrypting AEAD encrypted data.
         *
         * @param isV5AEAD      AEAD flavour (OpenPGP v5 or v6)
         * @param in            underlying input stream
         * @param c             AEAD cipher
         * @param secretKey     secret key
         * @param iv            initialization vector
         * @param encAlgorithm  encryption algorithm
         * @param aeadAlgorithm AEAD algorithm
         * @param chunkSize     chunk size of the AEAD encryption
         * @param aaData        associated data
         * @throws IOException
         */
        public PGPAeadInputStream(boolean isV5AEAD, InputStream in,
                                  Cipher c,
                                  SecretKey secretKey,
                                  byte[] iv,
                                  int encAlgorithm,
                                  int aeadAlgorithm,
                                  int chunkSize,
                                  byte[] aaData)
            throws IOException
        {
            this.v5StyleAEAD = isV5AEAD;
            this.in = in;
            this.iv = iv;
            this.chunkLength = (int)getChunkLength(chunkSize);
            this.aeadTagLength = AEADUtils.getAuthTagLength(aeadAlgorithm);
            this.buf = new byte[chunkLength + aeadTagLength + aeadTagLength]; // allow room for chunk tag and message tag
            this.c = c;
            this.secretKey = secretKey;
            this.aaData = aaData;

            // prime with 2 * tag len bytes.
            Streams.readFully(in, buf, 0, aeadTagLength + aeadTagLength);

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
            int dataLen = Streams.readFully(in, buf, aeadTagLength + aeadTagLength, chunkLength);
            if (dataLen == 0)
            {
                return null;
            }

            byte[] adata = new byte[v5StyleAEAD ? 13 : aaData.length];
            System.arraycopy(aaData, 0, adata, 0, aaData.length);
            if (v5StyleAEAD)
            {
                xorChunkId(adata, chunkIndex);
            }

            byte[] decData;
            try
            {
                JceAEADCipherUtil.setUpAeadCipher(c, secretKey, Cipher.DECRYPT_MODE,  getNonce(iv, chunkIndex), 128, adata);

                decData = c.doFinal(buf, 0, dataLen + aeadTagLength);
            }
            catch (GeneralSecurityException e)
            {
                throw new IOException("exception processing chunk " + chunkIndex + ": " + e.getMessage());
            }

            totalBytes += decData.length;
            chunkIndex++;

            System.arraycopy(buf, dataLen + aeadTagLength, buf, 0, aeadTagLength); // copy back the "tag"

            if (dataLen != chunkLength)     // it's our last block
            {
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
                    if (v5StyleAEAD)
                    {
                        JceAEADCipherUtil.setUpAeadCipher(c, secretKey, Cipher.DECRYPT_MODE, getNonce(iv, chunkIndex), 128, Arrays.concatenate(adata, Pack.longToBigEndian(totalBytes)));
                    }
                    else
                    {
                        JceAEADCipherUtil.setUpAeadCipher(c, secretKey, Cipher.DECRYPT_MODE, getNonce(iv, chunkIndex), 128, adata);
                    }

                    c.doFinal(buf, 0, aeadTagLength); // check final tag
                }
                catch (GeneralSecurityException e)
                {
                    throw new IOException("exception processing final tag: " + e.getMessage());
                }
            }
            else
            {
                Streams.readFully(in, buf, aeadTagLength, aeadTagLength);   // read the next tag bytes
            }

            return decData;
        }
    }

    static class PGPAeadOutputStream
        extends OutputStream
    {
        private final boolean isV5AEAD;
        private final OutputStream out;
        private final byte[] data;
        private final Cipher c;
        private final SecretKey secretKey;
        private final byte[] aaData;
        private final byte[] iv;
        private final int chunkLength;

        private int dataOff;
        private long chunkIndex = 0;
        private long totalBytes = 0;

        /**
         * OutputStream for AEAD encryption.
         *
         * @param isV5AEAD       isV5AEAD of AEAD (OpenPGP v5 or v6)
         * @param out           underlying OutputStream
         * @param c             AEAD cipher
         * @param secretKey     secret key
         * @param iv            initialization vector
         * @param encAlgorithm  encryption algorithm
         * @param aeadAlgorithm AEAD algorithm
         * @param chunkSize     chunk size of the AEAD algorithm
         */
        public PGPAeadOutputStream(boolean isV5AEAD,
                                   OutputStream out,
                                   Cipher c,
                                   SecretKey secretKey,
                                   byte[] iv,
                                   int encAlgorithm,
                                   int aeadAlgorithm,
                                   int chunkSize)
        {
            this.isV5AEAD = isV5AEAD;
            this.out = out;
            this.iv = iv;
            this.chunkLength = (int)getChunkLength(chunkSize);
            this.data = new byte[chunkLength];
            this.c = c;
            this.secretKey = secretKey;

            this.aaData = createAAD(isV5AEAD, encAlgorithm, aeadAlgorithm, chunkSize);
        }

        /**
         * Create the associated data for the AEAD encryption.
         * Since the associated data array differs between OpenPGP v5 and v6, we need to know the flavour.
         *
         * @param isV5AEAD      true if flavour of AEAD OpenPGP v5
         * @param encAlgorithm  symmetric encryption algorithm
         * @param aeadAlgorithm AEAD algorithm
         * @param chunkSize     chunk size
         * @return associated data
         */
        private byte[] createAAD(boolean isV5AEAD, int encAlgorithm, int aeadAlgorithm, int chunkSize)
        {
            if (isV5AEAD)
            {
                return AEADEncDataPacket.createAAData(AEADEncDataPacket.VERSION_1,
                    encAlgorithm, aeadAlgorithm, chunkSize);
            }
            else
            {
                return SymmetricEncIntegrityPacket.createAAData(SymmetricEncIntegrityPacket.VERSION_2,
                    encAlgorithm, aeadAlgorithm, chunkSize);
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
            byte[] adata = isV5AEAD ? new byte[13] : new byte[aaData.length];
            System.arraycopy(aaData, 0, adata, 0, aaData.length);
            if (isV5AEAD)
            {
                xorChunkId(adata, chunkIndex);
            }

            try
            {
                JceAEADCipherUtil.setUpAeadCipher(c, secretKey, Cipher.ENCRYPT_MODE,  getNonce(iv, chunkIndex), 128, adata);

                out.write(c.doFinal(data, 0, dataOff));
            }
            catch (GeneralSecurityException e)
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
            if (isV5AEAD)
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
                if (isV5AEAD)
                {
                    JceAEADCipherUtil.setUpAeadCipher(c, secretKey, Cipher.ENCRYPT_MODE, getNonce(iv, chunkIndex), 128, Arrays.concatenate(adata, Pack.longToBigEndian(totalBytes)));
                }
                else
                {
                    JceAEADCipherUtil.setUpAeadCipher(c, secretKey, Cipher.ENCRYPT_MODE, getNonce(iv, chunkIndex), 128, adata);
                }

                out.write(c.doFinal(aaData, 0, 0)); // output final tag
            }
            catch (GeneralSecurityException e)
            {
                throw new IOException("exception processing final tag: " + e.getMessage());
            }
            out.close();
        }
    }
}
