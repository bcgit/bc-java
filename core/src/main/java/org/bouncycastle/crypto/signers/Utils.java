package org.bouncycastle.crypto.signers;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServiceProperties;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.constraints.ConstraintUtils;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.params.DSAKeyParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.GOST3410KeyParameters;
import org.bouncycastle.pqc.crypto.DigestUtils;
import org.bouncycastle.util.Exceptions;

class Utils
{
    /**
     * Return the DER encoding of the OID of a HashML-DSA / HashSLH-DSA pre-hash function (FIPS 204
     * Algorithm 4, FIPS 205 Algorithm 23).
     *
     * @throws IllegalArgumentException if the digest is SHA-1 or has no known OID.
     */
    static byte[] getPreHashOIDEncoding(Digest digest)
    {
        String name = digest.getAlgorithmName();
        if ("SHA-1".equals(name))
        {
            throw new IllegalArgumentException("unsupported pre-hash digest: " + name);
        }

        try
        {
            return DigestUtils.getDigestOid(name).getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            throw Exceptions.illegalStateException("oid encoding failed", e);
        }
    }

    static CryptoServiceProperties getDefaultProperties(String algorithm, DSAKeyParameters k, boolean forSigning)
    {
        return new DefaultServiceProperties(algorithm, ConstraintUtils.bitsOfSecurityFor(k.getParameters().getP()), k, getPurpose(forSigning));
    }

    static CryptoServiceProperties getDefaultProperties(String algorithm, GOST3410KeyParameters k, boolean forSigning)
    {
        return new DefaultServiceProperties(algorithm, ConstraintUtils.bitsOfSecurityFor(k.getParameters().getP()), k, getPurpose(forSigning));
    }

    static CryptoServiceProperties getDefaultProperties(String algorithm, ECKeyParameters k, boolean forSigning)
    {
        return new DefaultServiceProperties(algorithm, ConstraintUtils.bitsOfSecurityFor(k.getParameters().getCurve()), k, getPurpose(forSigning));
    }

    static CryptoServiceProperties getDefaultProperties(String algorithm, int bitsOfSecurity, CipherParameters k, boolean forSigning)
    {
        return new DefaultServiceProperties(algorithm, bitsOfSecurity, k, getPurpose(forSigning));
    }

    static CryptoServicePurpose getPurpose(boolean forSigning)
    {
        return forSigning ? CryptoServicePurpose.SIGNING : CryptoServicePurpose.VERIFYING;
    }
}
