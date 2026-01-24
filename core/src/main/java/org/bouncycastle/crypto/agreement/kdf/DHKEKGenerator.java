package org.bouncycastle.crypto.agreement.kdf;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x9.KeySpecificInfo;
import org.bouncycastle.asn1.x9.OtherInfo;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.util.Pack;

/**
 * RFC 2631 Diffie-hellman KEK derivation function.
 */
public class DHKEKGenerator
    implements DerivationFunction
{
    private final Digest digest;

    private ASN1ObjectIdentifier algorithm;
    private int                 keySize;
    private byte[]              z;
    private byte[]              extraInfo;

    public DHKEKGenerator(Digest digest)
    {
        this.digest = digest;
    }

    public void init(DerivationParameters param)
    {
        DHKDFParameters params = (DHKDFParameters)param;

        this.algorithm = params.getAlgorithm();
        this.keySize = params.getKeySize();
        this.z = params.getZ();
        this.extraInfo = params.getExtraInfo();
    }

    public Digest getDigest()
    {
        return digest;
    }

    public int generateBytes(byte[] out, int outOff, int len)
        throws DataLengthException, IllegalArgumentException
    {
        if ((out.length - len) < outOff)
        {
            throw new OutputLengthException("output buffer too small");
        }

        digest.reset();

        long oBytes = len;
        int outLen = digest.getDigestSize();

        // NOTE: This limit isn't reachable for current array lengths
        if (oBytes > ((1L << 32) - 1) * outLen)
        {
            throw new IllegalArgumentException("Output length too large");
        }

        int cThreshold = (int)((oBytes + outLen - 1) / outLen);

        byte[] dig = new byte[digest.getDigestSize()];

        int counter32 = 1;

        for (int i = 0; i < cThreshold; i++)
        {
            digest.update(z, 0, z.length);

            // KeySpecificInfo
            ASN1OctetString counter = DEROctetString.withContents(Pack.intToBigEndian(counter32));
            KeySpecificInfo keyInfo = new KeySpecificInfo(algorithm, counter);

            // OtherInfo
            ASN1OctetString partyAInfo = DEROctetString.withContentsOptional(extraInfo);
            ASN1OctetString suppPubInfo = DEROctetString.withContents(Pack.intToBigEndian(keySize));
            OtherInfo otherInfo = new OtherInfo(keyInfo, partyAInfo, suppPubInfo);

            try
            {
                byte[] other = otherInfo.getEncoded(ASN1Encoding.DER);

                digest.update(other, 0, other.length);
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("unable to encode parameter info: " + e.getMessage());
            }

            digest.doFinal(dig, 0);

            if (len > outLen)
            {
                System.arraycopy(dig, 0, out, outOff, outLen);
                outOff += outLen;
                len -= outLen;
            }
            else
            {
                System.arraycopy(dig, 0, out, outOff, len);
            }

            counter32++;
        }

        return (int)oBytes;
    }
}
