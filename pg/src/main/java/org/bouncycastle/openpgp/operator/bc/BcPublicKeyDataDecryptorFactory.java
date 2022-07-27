package org.bouncycastle.openpgp.operator.bc;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

import org.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers;
import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.bcpg.PacketTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedAsymmetricBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.EAXBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.OCBBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ElGamalPrivateKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.PGPPad;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.RFC6637Utils;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.io.Streams;

/**
 * A decryptor factory for handling public key decryption operations.
 */
public class BcPublicKeyDataDecryptorFactory
    implements PublicKeyDataDecryptorFactory
{
    private static final BcPGPKeyConverter KEY_CONVERTER = new BcPGPKeyConverter();

    private final PGPPrivateKey pgpPrivKey;

    public BcPublicKeyDataDecryptorFactory(PGPPrivateKey pgpPrivKey)
    {
        this.pgpPrivKey = pgpPrivKey;
    }

    public byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData)
        throws PGPException
    {
        try
        {
            AsymmetricKeyParameter privKey = KEY_CONVERTER.getPrivateKey(pgpPrivKey);

            if (keyAlgorithm != PublicKeyAlgorithmTags.ECDH)
            {
                AsymmetricBlockCipher c = BcImplProvider.createPublicKeyCipher(keyAlgorithm);

                BufferedAsymmetricBlockCipher c1 = new BufferedAsymmetricBlockCipher(c);

                c1.init(false, privKey);

                if (keyAlgorithm == PublicKeyAlgorithmTags.RSA_ENCRYPT
                    || keyAlgorithm == PublicKeyAlgorithmTags.RSA_GENERAL)
                {
                    byte[] bi = secKeyData[0];

                    c1.processBytes(bi, 2, bi.length - 2);
                }
                else
                {
                    ElGamalPrivateKeyParameters parms = (ElGamalPrivateKeyParameters)privKey;
                    int size = (parms.getParameters().getP().bitLength() + 7) / 8;
                    byte[] tmp = new byte[size];

                    byte[] bi = secKeyData[0]; // encoded MPI
                    if (bi.length - 2 > size)  // leading Zero? Shouldn't happen but...
                    {
                        c1.processBytes(bi, 3, bi.length - 3);
                    }
                    else
                    {
                        System.arraycopy(bi, 2, tmp, tmp.length - (bi.length - 2), bi.length - 2);
                        c1.processBytes(tmp, 0, tmp.length);
                    }

                    bi = secKeyData[1];  // encoded MPI
                    for (int i = 0; i != tmp.length; i++)
                    {
                        tmp[i] = 0;
                    }

                    if (bi.length - 2 > size) // leading Zero? Shouldn't happen but...
                    {
                        c1.processBytes(bi, 3, bi.length - 3);
                    }
                    else
                    {
                        System.arraycopy(bi, 2, tmp, tmp.length - (bi.length - 2), bi.length - 2);
                        c1.processBytes(tmp, 0, tmp.length);
                    }
                }

                return c1.doFinal();
            }
            else
            {
                ECDHPublicBCPGKey ecPubKey = (ECDHPublicBCPGKey)pgpPrivKey.getPublicKeyPacket().getKey();
                byte[] enc = secKeyData[0];

                int pLen = ((((enc[0] & 0xff) << 8) + (enc[1] & 0xff)) + 7) / 8;
                if ((2 + pLen + 1) > enc.length)
                {
                    throw new PGPException("encoded length out of range");
                }

                byte[] pEnc = new byte[pLen];
                System.arraycopy(enc, 2, pEnc, 0, pLen);

                int keyLen = enc[pLen + 2] & 0xff;
                if ((2 + pLen + 1 + keyLen) > enc.length)
                {
                    throw new PGPException("encoded length out of range");
                }

                byte[] keyEnc = new byte[keyLen];
                System.arraycopy(enc, 2 + pLen + 1, keyEnc, 0, keyLen);

                byte[] secret;
                // XDH
                if (ecPubKey.getCurveOID().equals(CryptlibObjectIdentifiers.curvey25519))
                {
                    // skip the 0x40 header byte.
                    if (pEnc.length != (1 + X25519PublicKeyParameters.KEY_SIZE) || 0x40 != pEnc[0])
                    {
                        throw new IllegalArgumentException("Invalid Curve25519 public key");
                    }

                    X25519PublicKeyParameters ephPub = new X25519PublicKeyParameters(pEnc, 1);

                    X25519Agreement agreement = new X25519Agreement();
                    agreement.init(privKey);

                    secret = new byte[agreement.getAgreementSize()];
                    agreement.calculateAgreement(ephPub, secret, 0);
                }
                else
                {
                    ECDomainParameters ecParameters = ((ECPrivateKeyParameters)privKey).getParameters();

                    ECPublicKeyParameters ephPub = new ECPublicKeyParameters(ecParameters.getCurve().decodePoint(pEnc),
                        ecParameters);

                    ECDHBasicAgreement agreement = new ECDHBasicAgreement();
                    agreement.init(privKey);
                    BigInteger S = agreement.calculateAgreement(ephPub);
                    secret = BigIntegers.asUnsignedByteArray(agreement.getFieldSize(), S);
                }

                RFC6637KDFCalculator rfc6637KDFCalculator = new RFC6637KDFCalculator(
                    new BcPGPDigestCalculatorProvider().get(ecPubKey.getHashAlgorithm()),
                    ecPubKey.getSymmetricKeyAlgorithm());
                byte[] userKeyingMaterial = RFC6637Utils.createUserKeyingMaterial(pgpPrivKey.getPublicKeyPacket(),
                    new BcKeyFingerprintCalculator());

                KeyParameter key = new KeyParameter(rfc6637KDFCalculator.createKey(secret, userKeyingMaterial));

                Wrapper c = BcImplProvider.createWrapper(ecPubKey.getSymmetricKeyAlgorithm());
                c.init(false, key);
                return PGPPad.unpadSessionData(c.unwrap(keyEnc, 0, keyEnc.length));
            }
        }
        catch (IOException e)
        {
            throw new PGPException("exception creating user keying material: " + e.getMessage(), e);
        }
        catch (InvalidCipherTextException e)
        {
            throw new PGPException("exception decrypting session info: " + e.getMessage(), e);
        }

    }

    public PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key)
        throws PGPException
    {
        BlockCipher engine = BcImplProvider.createBlockCipher(encAlgorithm);

        return BcUtil.createDataDecryptor(withIntegrityPacket, engine, key);
    }

    private static long getChunkLength(int chunkSize)
    {
        return 1L << (chunkSize + 6);
    }

    public PGPDataDecryptor createDataDecryptor(final int aeadAlgorithm, final byte[] iv, final int chunkSize, final int encAlgorithm, byte[] key)
        throws PGPException
    {
        try
        {
            final KeyParameter secretKey = new KeyParameter(key);

            final AEADBlockCipher c = createAEADCipher(encAlgorithm, aeadAlgorithm);

            // TODO: get this working for more than one chunk!
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
        catch (Exception e)
        {
            throw new PGPException("Exception creating cipher", e);
        }
    }

    public AEADBlockCipher createAEADCipher(int encAlgorithm, int aeadAlgorithm)
    {
        if (encAlgorithm != SymmetricKeyAlgorithmTags.AES_128
           && encAlgorithm != SymmetricKeyAlgorithmTags.AES_192
           && encAlgorithm != SymmetricKeyAlgorithmTags.AES_256)
        {
            throw new IllegalArgumentException("AEAD only supported for AES based algorithms");
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
            throw new IllegalArgumentException("unrecognised AEAD algorithm: " + aeadAlgorithm);
        }
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

        private byte[] getNonce(byte[] iv, long chunkIndex)
        {
            byte[] nonce = Arrays.clone(iv);

            xorChunkId(nonce, chunkIndex);

            return nonce;
        }

        private void xorChunkId(byte[] nonce, long chunkIndex)
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
    }
}
