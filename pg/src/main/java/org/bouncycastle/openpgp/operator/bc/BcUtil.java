package org.bouncycastle.openpgp.operator.bc;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.PacketTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.io.CipherInputStream;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.EAXBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.OCBBlockCipher;
import org.bouncycastle.crypto.modes.OpenPGPCFBBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.io.Streams;

class BcUtil
{
    static BufferedBlockCipher createStreamCipher(boolean forEncryption, BlockCipher engine, boolean withIntegrityPacket, byte[] key)
    {
        BufferedBlockCipher c;

        if (withIntegrityPacket)
        {
            c = new BufferedBlockCipher(new CFBBlockCipher(engine, engine.getBlockSize() * 8));
        }
        else
        {
            c = new BufferedBlockCipher(new OpenPGPCFBBlockCipher(engine));
        }

        KeyParameter keyParameter = new KeyParameter(key);

        if (withIntegrityPacket)
        {
            c.init(forEncryption, new ParametersWithIV(keyParameter, new byte[engine.getBlockSize()]));
        }
        else
        {
            c.init(forEncryption, keyParameter);
        }

        return c;
    }

    public static PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, BlockCipher engine, byte[] key)
    {
        final BufferedBlockCipher c = createStreamCipher(false, engine, withIntegrityPacket, key);

        return new PGPDataDecryptor()
        {
            public InputStream getInputStream(InputStream in)
            {
                return new CipherInputStream(in, c);
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

    public static BufferedBlockCipher createSymmetricKeyWrapper(boolean forEncryption, BlockCipher engine, byte[] key, byte[] iv)
    {
        BufferedBlockCipher c = new BufferedBlockCipher(new CFBBlockCipher(engine, engine.getBlockSize() * 8));

        c.init(forEncryption, new ParametersWithIV(new KeyParameter(key), iv));

        return c;
    }

    static X9ECParameters getX9Parameters(ASN1ObjectIdentifier curveOID)
    {
        X9ECParameters x9 = CustomNamedCurves.getByOID(curveOID);
        if (x9 == null)
        {
            x9 = ECNamedCurveTable.getByOID(curveOID);
        }

        return x9;
    }

    static ECPoint decodePoint(
        BigInteger encodedPoint,
        ECCurve curve)
    {
        return curve.decodePoint(BigIntegers.asUnsignedByteArray(encodedPoint));
    }

    private static long getChunkLength(int chunkSize)
    {
        return 1L << (chunkSize + 6);
    }

    static PGPDataDecryptor createDataDecryptor(final int aeadAlgorithm, final byte[] iv, final int chunkSize, final int encAlgorithm, final byte[] key)
        throws PGPException
    {
        final KeyParameter secretKey = new KeyParameter(key);

        final AEADBlockCipher c = createAEADCipher(encAlgorithm, aeadAlgorithm);

        return new PGPDataDecryptor()
        {
            public InputStream getInputStream(InputStream in)
            {
                try
                {
                    return new PGPAeadInputStream(in, c, secretKey, iv, encAlgorithm, aeadAlgorithm, chunkSize);
                }
                catch (IOException e)
                {
                    throw new IllegalStateException("unable to open stream: " + e.getMessage(), e);
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

    static AEADBlockCipher createAEADCipher(int encAlgorithm, int aeadAlgorithm)
        throws PGPException
    {
        if (encAlgorithm != SymmetricKeyAlgorithmTags.AES_128
            && encAlgorithm != SymmetricKeyAlgorithmTags.AES_192
            && encAlgorithm != SymmetricKeyAlgorithmTags.AES_256)
        {
            throw new PGPException("AEAD only supported for AES based algorithms");
        }

        switch (aeadAlgorithm)
        {
        case AEADAlgorithmTags.EAX:
            return new EAXBlockCipher(new AESEngine());
        case AEADAlgorithmTags.OCB:
            return new OCBBlockCipher(new AESEngine(), new AESEngine());
        case AEADAlgorithmTags.GCM:
            return new GCMBlockCipher(new AESEngine());
        default:
            throw new PGPException("unrecognised AEAD algorithm: " + aeadAlgorithm);
        }
    }

    static byte[] getNonce(byte[] iv, long chunkIndex)
    {
        byte[] nonce = Arrays.clone(iv);

        xorChunkId(nonce, chunkIndex);

        return nonce;
    }

    static void xorChunkId(byte[] nonce, long chunkIndex)
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

    private static class PGPAeadInputStream
        extends InputStream
    {
        private final InputStream in;
        private final byte[] buf;
        private final AEADBlockCipher c;
        private final KeyParameter secretKey;
        private final byte[] aaData;
        private final byte[] iv;
        private final int chunkLength;

        private byte[] data;
        private int dataOff;
        private long chunkIndex = 0;
        private long totalBytes = 0;

        public PGPAeadInputStream(InputStream in, AEADBlockCipher c, KeyParameter secretKey, byte[] iv, int encAlgorithm, int aeadAlgorithm, int chunkSize)
            throws IOException
        {
            this.in = in;
            this.iv = iv;
            this.chunkLength = (int)getChunkLength(chunkSize);
            this.buf = new byte[chunkLength + 32]; // allow room for chunk tag and message tag
            this.c = c;
            this.secretKey = secretKey;

            aaData = new byte[5];

            aaData[0] = (byte)(0xC0 | PacketTags.AEAD_ENC_DATA);
            aaData[1] = 0x01;   // packet version
            aaData[2] = (byte)encAlgorithm;
            aaData[3] = (byte)aeadAlgorithm;
            aaData[4] = (byte)chunkSize;

            // prime with 2 * tag len bytes.
            Streams.readFully(in, buf, 0, 32);

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
            int dataLen = Streams.readFully(in, buf, 32, chunkLength);
            if (dataLen == 0)
            {
                return null;
            }

            byte[] adata = new byte[13];
            System.arraycopy(aaData, 0, adata, 0, aaData.length);

            xorChunkId(adata, chunkIndex);

            byte[] decData = new byte[dataLen];
            try
            {
                c.init(false, new AEADParameters(secretKey, 128, getNonce(iv, chunkIndex)));  // always full tag.

                c.processAADBytes(adata, 0, adata.length);

                int len = c.processBytes(buf, 0, dataLen + 16, decData, 0);

                c.doFinal(decData, len);
            }
            catch (InvalidCipherTextException e)
            {
                throw new IOException("exception processing chunk " + chunkIndex + ": " + e.getMessage());
            }

            totalBytes += decData.length;
            chunkIndex++;

            System.arraycopy(buf, dataLen + 16, buf, 0, 16); // copy back the "tag"

            if (dataLen != chunkLength)     // it's our last block
            {
                adata = new byte[13];

                System.arraycopy(aaData, 0, adata, 0, aaData.length);

                xorChunkId(adata, chunkIndex);
                try
                {
                    c.init(false, new AEADParameters(secretKey, 128, getNonce(iv, chunkIndex)));  // always full tag.

                    c.processAADBytes(adata, 0, adata.length);
                    c.processAADBytes(Pack.longToBigEndian(totalBytes), 0, 8);

                    c.processBytes(buf, 0, 16, buf, 0);

                    c.doFinal(buf, 0); // check final tag
                }
                catch (InvalidCipherTextException e)
                {
                    throw new IOException("exception processing final tag: " + e.getMessage());
                }
            }
            else
            {
                Streams.readFully(in, buf, 16, 16);   // read the next tag bytes
            }

            return decData;
        }
    }

    static class PGPAeadOutputStream
        extends OutputStream
    {
        private final OutputStream out;
        private final byte[] data;
        private final AEADBlockCipher c;
        private final KeyParameter secretKey;
        private final byte[] aaData;
        private final byte[] iv;
        private final int chunkLength;

        private int dataOff;
        private long chunkIndex = 0;
        private long totalBytes = 0;

        public PGPAeadOutputStream(OutputStream out, AEADBlockCipher c, KeyParameter secretKey, int encAlgorithm, int aeadAlgorithm, int chunkSize, byte[] iv)
        {
            this.out = out;
            this.iv = iv;
            this.chunkLength = (int)getChunkLength(chunkSize);
            this.data = new byte[chunkLength];
            this.c = c;
            this.secretKey = secretKey;

            aaData = new byte[5];

            aaData[0] = (byte)(0xC0 | PacketTags.AEAD_ENC_DATA);
            aaData[1] = 0x01;   // packet version
            aaData[2] = (byte)encAlgorithm;
            aaData[3] = (byte)aeadAlgorithm;
            aaData[4] = (byte)chunkSize;
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
            byte[] adata = new byte[13];
            System.arraycopy(aaData, 0, adata, 0, aaData.length);

            xorChunkId(adata, chunkIndex);

            try
            {
                c.init(true, new AEADParameters(secretKey, 128, getNonce(iv, chunkIndex)));  // always full tag.

                c.processAADBytes(adata, 0,adata.length);

                int len = c.processBytes(data, 0, dataOff, data, 0);

                out.write(data, 0, len);

                len = c.doFinal(data, 0);

                out.write(data, 0, len);
            }
            catch (InvalidCipherTextException e)
            {                      e.printStackTrace();
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

            byte[] adata = new byte[13];
            System.arraycopy(aaData, 0, adata, 0, aaData.length);

            xorChunkId(adata, chunkIndex);
            try
            {
                c.init(true, new AEADParameters(secretKey, 128, getNonce(iv, chunkIndex)));  // always full tag.

                c.processAADBytes(adata, 0, adata.length);
                c.processAADBytes(Pack.longToBigEndian(totalBytes), 0, 8);

                c.doFinal(data, 0);

                out.write(data, 0, 16); // output final tag
            }
            catch (InvalidCipherTextException e)
            {
                throw new IOException("exception processing final tag: " + e.getMessage());
            }
        }
    }
}
