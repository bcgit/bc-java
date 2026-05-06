package org.bouncycastle.jcajce.provider.keystore.pkcs12;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1ParsingException;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.EncryptedData;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Properties;

/**
 * Internal helper used by the PKCS#12 keystore SPIs in this package.
 * Mirrors the validation and content-extraction helpers from the deprecated
 * {@link org.bouncycastle.jce.PKCS12Util}, without the JCE
 * {@code convertToDefiniteLength} re-encoding API.
 */
class PKCS12Util
{
    private static final BigInteger DEFAULT_MAX_IT_COUNT = BigInteger.valueOf(5000000);

    static ASN1Encodable getContent(ContentInfo contentInfo) throws IOException
    {
        ASN1Encodable content = contentInfo.getContent();
        if (content == null)
        {
            throw new ASN1ParsingException("ContentInfo content missing");
        }

        return content;
    }

    static byte[] getContentOctets(ContentInfo contentInfo) throws IOException
    {
        return ASN1OctetString.getInstance(getContent(contentInfo)).getOctets();
    }

    static ASN1OctetString getEncryptedContent(EncryptedData encryptedData) throws IOException
    {
        ASN1OctetString content = encryptedData.getContent();
        if (content == null)
        {
            throw new ASN1ParsingException("EncryptedContentInfo content missing");
        }

        return content;
    }

    static int validateIterationCount(BigInteger ic)
    {
        if (ic.signum() < 0)
        {
            throw new IllegalStateException("negative iteration count found");
        }
        if (ic.bitLength() > 31)
        {
            throw new IllegalStateException("iteration counts >= 2^31 are not suppported");
        }

        BigInteger max = Properties.asBigInteger(Properties.PKCS12_MAX_IT_COUNT);
        if (max == null)
        {
            max = DEFAULT_MAX_IT_COUNT;
        }

        if (ic.compareTo(max) > 0)
        {
            throw new IllegalStateException("iteration count " + ic + " greater than " + max);
        }

        return BigIntegers.intValueExact(ic);
    }
}
