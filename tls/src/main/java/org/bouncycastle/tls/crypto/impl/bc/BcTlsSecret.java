package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.PRFAlgorithm;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCryptoUtils;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.impl.AbstractTlsCrypto;
import org.bouncycastle.tls.crypto.impl.AbstractTlsSecret;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * BC light-weight support class for handling TLS secrets and deriving key material and other secrets from them.
 */
public class BcTlsSecret
    extends AbstractTlsSecret
{
    // SSL3 magic mix constants ("A", "BB", "CCC", ...)
    private static final byte[] SSL3_CONST = generateSSL3Constants();

    private static byte[] generateSSL3Constants()
    {
        int n = 15;
        byte[] result = new byte[n * (n + 1) / 2];
        int pos = 0;
        for (int i = 0; i < n; ++i)
        {
            byte b = (byte)('A' + i);
            for (int j = 0; j <= i; ++j)
            {
                result[pos++] = b;
            }
        }
        return result;
    }

    protected final BcTlsCrypto crypto;

    public BcTlsSecret(BcTlsCrypto crypto, byte[] data)
    {
        super(data);

        this.crypto = crypto;
    }

    public synchronized TlsSecret deriveUsingPRF(int prfAlgorithm, String label, byte[] seed, int length)
    {
        checkAlive();

        try
        {
            switch (prfAlgorithm)
            {
            case PRFAlgorithm.tls13_hkdf_sha256:
                return TlsCryptoUtils.hkdfExpandLabel(this, HashAlgorithm.sha256, label, seed, length);
            case PRFAlgorithm.tls13_hkdf_sha384:
                return TlsCryptoUtils.hkdfExpandLabel(this, HashAlgorithm.sha384, label, seed, length);
            default:
                return crypto.adoptLocalSecret(prf(prfAlgorithm, label, seed, length));
            }
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
    }

    public synchronized TlsSecret hkdfExpand(short hashAlgorithm, byte[] info, int length)
    {
        if (length < 1)
        {
            return crypto.adoptLocalSecret(TlsUtils.EMPTY_BYTES);
        }

        int hashLen = HashAlgorithm.getOutputSize(hashAlgorithm);
        if (length > (255 * hashLen))
        {
            throw new IllegalArgumentException("'length' must be <= 255 * (output size of 'hashAlgorithm')");
        }

        checkAlive();

        byte[] prk = data;

        HMac hmac = new HMac(crypto.createDigest(hashAlgorithm));
        hmac.init(new KeyParameter(prk));

        byte[] okm = new byte[length];

        byte[] t = new byte[hashLen];
        byte counter = 0x00;

        int pos = 0;
        for (;;)
        {
            hmac.update(info, 0, info.length);
            hmac.update((byte)++counter);
            hmac.doFinal(t, 0);

            int remaining = length - pos;
            if (remaining <= hashLen)
            {
                System.arraycopy(t, 0, okm, pos, remaining);
                break;
            }

            System.arraycopy(t, 0, okm, pos, hashLen);
            pos += hashLen;
            hmac.update(t, 0, t.length);
        }

        return crypto.adoptLocalSecret(okm);
    }

    public synchronized TlsSecret hkdfExtract(short hashAlgorithm, byte[] ikm)
    {
        checkAlive();

        byte[] salt = data;
        this.data = null;

        HMac hmac = new HMac(crypto.createDigest(hashAlgorithm));
        hmac.init(new KeyParameter(salt));

        hmac.update(ikm, 0, ikm.length);

        byte[] prk = new byte[hmac.getMacSize()];
        hmac.doFinal(prk, 0);

        return crypto.adoptLocalSecret(prk);
    }

    protected AbstractTlsCrypto getCrypto()
    {
        return crypto;
    }

    protected void hmacHash(Digest digest, byte[] secret, int secretOff, int secretLen, byte[] seed, byte[] output)
    {
        HMac mac = new HMac(digest);
        mac.init(new KeyParameter(secret, secretOff, secretLen));

        byte[] a = seed;

        int macSize = mac.getMacSize();

        byte[] b1 = new byte[macSize];
        byte[] b2 = new byte[macSize];

        int pos = 0;
        while (pos < output.length)
        {
            mac.update(a, 0, a.length);
            mac.doFinal(b1, 0);
            a = b1;
            mac.update(a, 0, a.length);
            mac.update(seed, 0, seed.length);
            mac.doFinal(b2, 0);
            System.arraycopy(b2, 0, output, pos, Math.min(macSize, output.length - pos));
            pos += macSize;
        }
    }

    protected byte[] prf(int prfAlgorithm, String label, byte[] seed, int length)
    {
        if (PRFAlgorithm.ssl_prf_legacy == prfAlgorithm)
        {
            return prf_SSL(seed, length);
        }

        byte[] labelSeed = Arrays.concatenate(Strings.toByteArray(label), seed);

        if (PRFAlgorithm.tls_prf_legacy == prfAlgorithm)
        {
            return prf_1_0(labelSeed, length);
        }

        return prf_1_2(prfAlgorithm, labelSeed, length);
    }

    protected byte[] prf_SSL(byte[] seed, int length)
    {
        Digest md5 = crypto.createDigest(HashAlgorithm.md5);
        Digest sha1 = crypto.createDigest(HashAlgorithm.sha1);

        int md5Size = md5.getDigestSize();
        int sha1Size = sha1.getDigestSize();

        byte[] tmp = new byte[Math.max(md5Size, sha1Size)];
        byte[] result = new byte[length];

        int constLen = 1, constPos = 0, resultPos = 0;
        while (resultPos < length)
        {
            sha1.update(SSL3_CONST, constPos, constLen);
            constPos += constLen++;

            sha1.update(data, 0, data.length);
            sha1.update(seed, 0, seed.length);
            sha1.doFinal(tmp, 0);

            md5.update(data, 0, data.length);
            md5.update(tmp, 0, sha1Size);

            int remaining = length - resultPos;
            if (remaining < md5Size)
            {
                md5.doFinal(tmp, 0);
                System.arraycopy(tmp, 0, result, resultPos, remaining);
                resultPos += remaining;
            }
            else
            {
                md5.doFinal(result, resultPos);
                resultPos += md5Size;
            }
        }

        return result;
    }

    protected byte[] prf_1_0(byte[] labelSeed, int length)
    {
        int s_half = (data.length + 1) / 2;

        byte[] b1 = new byte[length];
        hmacHash(crypto.createDigest(HashAlgorithm.md5), data, 0, s_half, labelSeed, b1);

        byte[] b2 = new byte[length];
        hmacHash(crypto.createDigest(HashAlgorithm.sha1), data, data.length - s_half, s_half, labelSeed, b2);

        for (int i = 0; i < length; i++)
        {
            b1[i] ^= b2[i];
        }
        return b1;
    }

    protected byte[] prf_1_2(int prfAlgorithm, byte[] labelSeed, int length)
    {
        Digest digest = crypto.createDigest(TlsUtils.getHashAlgorithmForPRFAlgorithm(prfAlgorithm));
        byte[] result = new byte[length];
        hmacHash(digest, data, 0, data.length, labelSeed, result);
        return result;
    }
}
