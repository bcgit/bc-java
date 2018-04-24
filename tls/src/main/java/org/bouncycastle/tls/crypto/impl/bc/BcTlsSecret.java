package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.PRFAlgorithm;
import org.bouncycastle.tls.TlsUtils;
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
    protected final BcTlsCrypto crypto;

    public BcTlsSecret(BcTlsCrypto crypto, byte[] data)
    {
        super(data);

        this.crypto = crypto;
    }

    public synchronized TlsSecret deriveUsingPRF(int prfAlgorithm, String label, byte[] seed, int length)
    {
        checkAlive();

        byte[] labelSeed = Arrays.concatenate(Strings.toByteArray(label), seed);

        byte[] result = (prfAlgorithm == PRFAlgorithm.tls_prf_legacy)
            ?   prf_1_0(data, labelSeed, length)
            :   prf_1_2(prfAlgorithm, data, labelSeed, length);

        return crypto.adoptLocalSecret(result);
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

    protected byte[] prf_1_0(byte[] secret, byte[] labelSeed, int length)
    {
        int s_half = (secret.length + 1) / 2;

        byte[] b1 = new byte[length];
        hmacHash(crypto.createDigest(HashAlgorithm.md5), secret, 0, s_half, labelSeed, b1);

        byte[] b2 = new byte[length];
        hmacHash(crypto.createDigest(HashAlgorithm.sha1), secret, secret.length - s_half, s_half, labelSeed, b2);

        for (int i = 0; i < length; i++)
        {
            b1[i] ^= b2[i];
        }
        return b1;
    }

    protected byte[] prf_1_2(int prfAlgorithm, byte[] secret, byte[] labelSeed, int length)
    {
        Digest digest = crypto.createDigest(TlsUtils.getHashAlgorithmForPRFAlgorithm(prfAlgorithm));
        byte[] result = new byte[length];
        hmacHash(digest, secret, 0, secret.length, labelSeed, result);
        return result;
    }
}
