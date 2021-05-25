package org.bouncycastle.tls.crypto;

import java.io.IOException;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.MACAlgorithm;
import org.bouncycastle.tls.PRFAlgorithm;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;

public abstract class TlsCryptoUtils
{
    // "tls13 "
    private static final byte[] TLS13_PREFIX = new byte[]{ 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20 };

    public static int getHash(short hashAlgorithm)
    {
        switch (hashAlgorithm)
        {
        case HashAlgorithm.md5:
            return CryptoHashAlgorithm.md5;
        case HashAlgorithm.sha1:
            return CryptoHashAlgorithm.sha1;
        case HashAlgorithm.sha224:
            return CryptoHashAlgorithm.sha224;
        case HashAlgorithm.sha256:
            return CryptoHashAlgorithm.sha256;
        case HashAlgorithm.sha384:
            return CryptoHashAlgorithm.sha384;
        case HashAlgorithm.sha512:
            return CryptoHashAlgorithm.sha512;
        default:
            throw new IllegalArgumentException("specified HashAlgorithm invalid: " + HashAlgorithm.getText(hashAlgorithm));
        }
    }

    public static int getHashForHMAC(int macAlgorithm)
    {
        switch (macAlgorithm)
        {
        case MACAlgorithm.hmac_md5:
            return CryptoHashAlgorithm.md5;
        case MACAlgorithm.hmac_sha1:
            return CryptoHashAlgorithm.sha1;
        case MACAlgorithm.hmac_sha256:
            return CryptoHashAlgorithm.sha256;
        case MACAlgorithm.hmac_sha384:
            return CryptoHashAlgorithm.sha384;
        case MACAlgorithm.hmac_sha512:
            return CryptoHashAlgorithm.sha512;
        default:
            throw new IllegalArgumentException("specified MACAlgorithm not an HMAC: " + MACAlgorithm.getText(macAlgorithm));
        }
    }

    public static int getHashForPRF(int prfAlgorithm)
    {
        switch (prfAlgorithm)
        {
        case PRFAlgorithm.ssl_prf_legacy:
        case PRFAlgorithm.tls_prf_legacy:
            throw new IllegalArgumentException("legacy PRF not a valid algorithm");
        case PRFAlgorithm.tls_prf_sha256:
        case PRFAlgorithm.tls13_hkdf_sha256:
            return CryptoHashAlgorithm.sha256;
        case PRFAlgorithm.tls_prf_sha384:
        case PRFAlgorithm.tls13_hkdf_sha384:
            return CryptoHashAlgorithm.sha384;
        case PRFAlgorithm.tls13_hkdf_sm3:
            return CryptoHashAlgorithm.sm3;
        default:
            throw new IllegalArgumentException("unknown PRFAlgorithm: " + PRFAlgorithm.getText(prfAlgorithm));
        }
    }

    public static int getHashOutputSize(int cryptoHashAlgorithm)
    {
        switch (cryptoHashAlgorithm)
        {
        case CryptoHashAlgorithm.md5:
            return 16;
        case CryptoHashAlgorithm.sha1:
            return 20;
        case CryptoHashAlgorithm.sha224:
            return 28;
        case CryptoHashAlgorithm.sha256:
        case CryptoHashAlgorithm.sm3:
            return 32;
        case CryptoHashAlgorithm.sha384:
            return 48;
        case CryptoHashAlgorithm.sha512:
            return 64;
        default:
            throw new IllegalArgumentException();
        }
    }

    public static int getSignature(short signatureAlgorithm)
    {
        switch (signatureAlgorithm)
        {
        case SignatureAlgorithm.rsa:
            return CryptoSignatureAlgorithm.rsa;
        case SignatureAlgorithm.dsa:
            return CryptoSignatureAlgorithm.dsa;
        case SignatureAlgorithm.ecdsa:
            return CryptoSignatureAlgorithm.ecdsa;
        case SignatureAlgorithm.rsa_pss_rsae_sha256:
            return CryptoSignatureAlgorithm.rsa_pss_rsae_sha256;
        case SignatureAlgorithm.rsa_pss_rsae_sha384:
            return CryptoSignatureAlgorithm.rsa_pss_rsae_sha384;
        case SignatureAlgorithm.rsa_pss_rsae_sha512:
            return CryptoSignatureAlgorithm.rsa_pss_rsae_sha512;
        case SignatureAlgorithm.ed25519:
            return CryptoSignatureAlgorithm.ed25519;
        case SignatureAlgorithm.ed448:
            return CryptoSignatureAlgorithm.ed448;
        case SignatureAlgorithm.rsa_pss_pss_sha256:
            return CryptoSignatureAlgorithm.rsa_pss_pss_sha256;
        case SignatureAlgorithm.rsa_pss_pss_sha384:
            return CryptoSignatureAlgorithm.rsa_pss_pss_sha384;
        case SignatureAlgorithm.rsa_pss_pss_sha512:
            return CryptoSignatureAlgorithm.rsa_pss_pss_sha512;
        case SignatureAlgorithm.gostr34102012_256:
            return CryptoSignatureAlgorithm.gostr34102012_256;
        case SignatureAlgorithm.gostr34102012_512:
            return CryptoSignatureAlgorithm.gostr34102012_512;
        default:
            throw new IllegalArgumentException(
                "specified SignatureAlgorithm invalid: " + SignatureAlgorithm.getText(signatureAlgorithm));
        }
    }

    public static TlsSecret hkdfExpandLabel(TlsSecret secret, short hashAlgorithm, String label, byte[] context,
        int length) throws IOException
    {
        int cryptoHashAlgorithm = getHash(hashAlgorithm);

        return hkdfExpandLabel(secret, cryptoHashAlgorithm, label, context, length);
    }

    public static TlsSecret hkdfExpandLabel(TlsSecret secret, int cryptoHashAlgorithm, String label, byte[] context,
        int length) throws IOException
    {
        int labelLength = label.length();
        if (labelLength < 1)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        int contextLength = context.length;
        int expandedLabelLength = TLS13_PREFIX.length + labelLength;

        byte[] hkdfLabel = new byte[2 + (1 + expandedLabelLength) + (1 + contextLength)];

        // uint16 length
        {
            TlsUtils.checkUint16(length);
            TlsUtils.writeUint16(length, hkdfLabel, 0);
        }

        // opaque label<7..255>
        {
            TlsUtils.checkUint8(expandedLabelLength);
            TlsUtils.writeUint8(expandedLabelLength, hkdfLabel, 2);

            System.arraycopy(TLS13_PREFIX, 0, hkdfLabel, 2 + 1, TLS13_PREFIX.length);

            int labelPos = 2 + (1 + TLS13_PREFIX.length);
            for (int i = 0; i < labelLength; ++i)
            {
                char c = label.charAt(i);
                hkdfLabel[labelPos + i] = (byte)c;
            }
        }

        // context
        {
            TlsUtils.writeOpaque8(context, hkdfLabel, 2 + (1 + expandedLabelLength));
        }

        return secret.hkdfExpand(cryptoHashAlgorithm, hkdfLabel, length);
    }
}
