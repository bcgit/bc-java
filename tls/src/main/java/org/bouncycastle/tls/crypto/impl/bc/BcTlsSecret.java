package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.PRFAlgorithm;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.impl.AbstractTlsCrypto;
import org.bouncycastle.tls.crypto.impl.AbstractTlsSecret;
import org.bouncycastle.util.Arrays;

/**
 * BC light-weight support class for handling TLS secrets and deriving key material and other secrets from them.
 */
public class BcTlsSecret
    extends AbstractTlsSecret
{
    protected final BcTlsCrypto crypto;

    public BcTlsSecret(BcTlsCrypto crypto, byte[] data)
    {
        super(data);

        this.crypto = crypto;
    }

    protected AbstractTlsCrypto getCrypto()
    {
        return crypto;
    }

    public synchronized TlsSecret deriveSSLKeyBlock(byte[] seed, int length)
    {
        checkAlive();

        int md5Count = (length + MD5_SIZE - 1) / MD5_SIZE;
        byte[] md5Buf = prf_SSL(seed, md5Count);

        TlsSecret result = crypto.adoptLocalSecret(Arrays.copyOfRange(md5Buf, 0, length));
        Arrays.fill(md5Buf, (byte)0);
        return result;
    }

    public synchronized TlsSecret deriveSSLMasterSecret(byte[] seed)
    {
        checkAlive();
        return crypto.adoptLocalSecret(prf_SSL(seed, 3));
    }

    public synchronized TlsSecret deriveUsingPRF(int prfAlgorithm, byte[] labelSeed, int length)
    {
        checkAlive();

        byte[] result = (prfAlgorithm == PRFAlgorithm.tls_prf_legacy)
            ?   prf_1_0(data, labelSeed, length)
            :   prf_1_2(crypto.createPRFHash(prfAlgorithm), data, labelSeed, length);

        return crypto.adoptLocalSecret(result);
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
        Digest md5 = crypto.createDigest(HashAlgorithm.md5);
        Digest sha1 = crypto.createDigest(HashAlgorithm.sha1);

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
        hmacHash(crypto.createDigest(HashAlgorithm.md5), s1, labelSeed, b1);
        hmacHash(crypto.createDigest(HashAlgorithm.sha1), s2, labelSeed, b2);
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
