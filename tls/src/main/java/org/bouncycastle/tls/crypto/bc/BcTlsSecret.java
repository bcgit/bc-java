package org.bouncycastle.tls.crypto.bc;

import java.io.IOException;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.PRFAlgorithm;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;

public class BcTlsSecret implements TlsSecret
{
    protected static final int MD5_SIZE = 16;

    // SSL3 magic mix constants ("A", "BB", "CCC", ...)
    private static final byte[][] SSL3_CONST = generateSSL3Constants();

    protected static byte[][] generateSSL3Constants()
    {
        int n = 10;
        byte[][] arr = new byte[n][];
        for (int i = 0; i < n; i++)
        {
            byte[] b = new byte[i + 1];
            Arrays.fill(b, (byte)('A' + i));
            arr[i] = b;
        }
        return arr;
    }

    protected BcTlsCrypto crypto;
    protected byte[] data;

    public BcTlsSecret(BcTlsCrypto crypto, byte[] data)
    {
        this.crypto = crypto;
        this.data = data;
    }

    public synchronized TlsSecret deriveSSLKeyBlock(byte[] seed, int length)
    {
        checkAlive();

        int md5Count = (length + MD5_SIZE - 1) / MD5_SIZE;
        byte[] md5Buf = prf_SSL(seed, md5Count);

        TlsSecret result = crypto.adoptSecret(Arrays.copyOfRange(md5Buf, 0, length));
        Arrays.fill(md5Buf, (byte)0);
        return result;
    }

    public synchronized TlsSecret deriveSSLMasterSecret(byte[] seed)
    {
        checkAlive();

        return crypto.adoptSecret(prf_SSL(seed, 3));
    }

    public synchronized void destroy()
    {
        if (data != null)
        {
            // TODO Is there a way to ensure the data is really overwritten?
            Arrays.fill(data, (byte)0);
            this.data = null;
        }
    }

    public synchronized byte[] encryptRSA(TlsCertificate certificate) throws IOException
    {
        RSAKeyParameters pubKeyRSA = BcTlsCertificate.convert(certificate).getPubKeyRSA();

        PKCS1Encoding encoding = new PKCS1Encoding(new RSABlindedEngine());
        encoding.init(true, new ParametersWithRandom(pubKeyRSA, crypto.getContext().getSecureRandom()));

        try
        {
            return encoding.processBlock(data, 0, data.length);
        }
        catch (InvalidCipherTextException e)
        {
            /*
             * This should never happen, only during decryption.
             */
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }

    public synchronized byte[] extract()
    {
        checkAlive();

        byte[] result = data;
        this.data = null;
        return result;
    }

    public synchronized TlsSecret prf(int prfAlgorithm, byte[] labelSeed, int length)
    {
        checkAlive();

        byte[] result = (prfAlgorithm == PRFAlgorithm.tls_prf_legacy)
            ?   prf_1_0(data, labelSeed, length)
            :   prf_1_2(crypto.createPRFHash(prfAlgorithm), data, labelSeed, length);

        return crypto.adoptSecret(result);
    }

    public synchronized void replace(int pos, byte[] buf, int bufPos, int bufLen)
    {
        checkAlive();

        for (int i = 0; i < bufLen; ++i)
        {
            data[pos + i] = buf[bufPos + i];
        }
    }

    protected void checkAlive()
    {
        if (data == null)
        {
            throw new IllegalStateException("Secret has already been extracted or destroyed");
        }
    }

    protected void hmacHash(Digest digest, byte[] secret, byte[] seed, byte[] output)
    {
        HMac mac = new HMac(digest);
        mac.init(new KeyParameter(secret));
        byte[] a = seed;
        int size = digest.getDigestSize();
        int iterations = (output.length + size - 1) / size;
        byte[] b1 = new byte[mac.getMacSize()];
        byte[] b2 = new byte[mac.getMacSize()];
        for (int i = 0; i < iterations; i++)
        {
            mac.update(a, 0, a.length);
            mac.doFinal(b1, 0);
            a = b1;
            mac.update(a, 0, a.length);
            mac.update(seed, 0, seed.length);
            mac.doFinal(b2, 0);
            System.arraycopy(b2, 0, output, (size * i), Math.min(size, output.length - (size * i)));
        }
    }

    protected byte[] prf_SSL(byte[] seed, int md5Count)
    {
        Digest md5 = crypto.createHash(HashAlgorithm.md5);
        Digest sha1 = crypto.createHash(HashAlgorithm.sha1);

        int md5Size = md5.getDigestSize();
        byte[] md5Buf = new byte[md5Size * md5Count];
        int md5Pos = 0;

        byte[] sha1Buf = new byte[sha1.getDigestSize()];

        for (int i = 0; i < md5Count; ++i)
        {
            byte[] ssl3Const = SSL3_CONST[i];

            sha1.update(ssl3Const, 0, ssl3Const.length);
            sha1.update(data, 0, data.length);
            sha1.update(seed, 0, seed.length);
            sha1.doFinal(sha1Buf, 0);

            md5.update(data, 0, data.length);
            md5.update(sha1Buf, 0, sha1Buf.length);
            md5.doFinal(md5Buf, md5Pos);

            md5Pos += md5Size;
        }

        return md5Buf;
    }

    protected byte[] prf_1_0(byte[] secret, byte[] labelSeed, int length)
    {
        int s_half = (secret.length + 1) / 2;
        byte[] s1 = new byte[s_half];
        byte[] s2 = new byte[s_half];
        System.arraycopy(secret, 0, s1, 0, s_half);
        System.arraycopy(secret, secret.length - s_half, s2, 0, s_half);

        byte[] b1 = new byte[length];
        byte[] b2 = new byte[length];
        hmacHash(crypto.createHash(HashAlgorithm.md5), s1, labelSeed, b1);
        hmacHash(crypto.createHash(HashAlgorithm.sha1), s2, labelSeed, b2);
        for (int i = 0; i < length; i++)
        {
            b1[i] ^= b2[i];
        }
        return b1;
    }

    protected byte[] prf_1_2(Digest prfDigest, byte[] secret, byte[] labelSeed, int length)
    {
        byte[] result = new byte[length];
        hmacHash(prfDigest, secret, labelSeed, result);
        return result;
    }
}
