package org.bouncycastle.tls.crypto.impl;

import org.bouncycastle.tls.ExporterLabel;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;

/**
 * Useful utility methods.
 */
public class TlsImplUtils
{
    public static boolean isTLSv11(ProtocolVersion version)
    {
        return ProtocolVersion.TLSv11.isEqualOrEarlierVersionOf(version.getEquivalentTLSVersion());
    }

    public static boolean isTLSv11(TlsCryptoParameters cryptoParams)
    {
        return isTLSv11(cryptoParams.getServerVersion());
    }

    public static boolean isTLSv12(ProtocolVersion version)
    {
        return ProtocolVersion.TLSv12.isEqualOrEarlierVersionOf(version.getEquivalentTLSVersion());
    }

    public static boolean isTLSv12(TlsCryptoParameters cryptoParams)
    {
        return isTLSv12(cryptoParams.getServerVersion());
    }

    public static byte[] calculateKeyBlock(TlsCryptoParameters cryptoParams, int length)
    {
        SecurityParameters securityParameters = cryptoParams.getSecurityParameters();
        TlsSecret master_secret = securityParameters.getMasterSecret();
        byte[] seed = Arrays.concatenate(securityParameters.getServerRandom(), securityParameters.getClientRandom());
        return PRF(cryptoParams, master_secret, ExporterLabel.key_expansion, seed, length).extract();
    }

    public static TlsSecret PRF(TlsCryptoParameters cryptoParams, TlsSecret secret, String asciiLabel, byte[] seed, int length)
    {
        int prfAlgorithm = cryptoParams.getSecurityParameters().getPrfAlgorithm();

        return secret.deriveUsingPRF(prfAlgorithm, asciiLabel, seed, length);
    }

    public static TlsSecret unpadPreMasterSecret(TlsCrypto crypto, TlsCryptoParameters cryptoParams, int rsaBytes,
        byte[] buf, int off, int len)
    {
        byte[] result = cryptoParams.getNonceGenerator().generateNonce(48);
        byte[] block = new byte[rsaBytes];

        int implicitZeroes = rsaBytes - len;
        System.arraycopy(buf, off, block, implicitZeroes, len);

        int pos = 0, diff = 0;
        int zeroPos = block.length - 49;

        diff |= ((zeroPos - 10) >>> 31);
        diff |= ((block[pos++] & 0xFF) ^ 0x00);
        diff |= ((block[pos++] & 0xFF) ^ 0x02);

        while (pos < zeroPos)
        {
            diff |= (((block[pos++] & 0xFF) - 1) >>> 31);
        }

        diff |= ((block[pos++] & 0xFF) ^ 0x00);

        ProtocolVersion clientVersion = cryptoParams.getClientVersion();
        diff |= (clientVersion.getMajorVersion() ^ (block[pos + 0] & 0xFF));
        diff |= (clientVersion.getMinorVersion() ^ (block[pos + 1] & 0xFF));

        int mask = (diff - 1) >> 31;
        for (int i = 0; i < 48; ++i)
        {
            int ri = result[i] & 0xFF, di = ri ^ (block[pos++] & 0xFF);
            result[i] = (byte)(ri ^ (di & mask));
        }

        assert pos == block.length;

        Arrays.fill(block, (byte)0);

        return crypto.createSecret(result);
    }
}
