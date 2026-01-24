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
import org.bouncycastle.crypto.io.DigestOutputStream;
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

        int outputLength = len;
        int digestSize = digest.getDigestSize();

        // NOTE: This limit isn't reachable for current array lengths
        if (outputLength > ((1L << 32) - 1) * digestSize)
        {
            throw new IllegalArgumentException("Output length too large");
        }

        int counter32 = 0;
        byte[] counterOctets = new byte[4];

        ASN1OctetString counter = DEROctetString.withContents(counterOctets);
        KeySpecificInfo keyInfo = new KeySpecificInfo(algorithm, counter);
        ASN1OctetString partyAInfo = DEROctetString.withContentsOptional(extraInfo);
        ASN1OctetString suppPubInfo = DEROctetString.withContents(Pack.intToBigEndian(keySize));
        OtherInfo otherInfo = new OtherInfo(keyInfo, partyAInfo, suppPubInfo);

        DigestOutputStream digestSink = new DigestOutputStream(digest);

        while (len > 0)
        {
            digest.update(z, 0, z.length);

            try
            {
                // NOTE: Modify counterOctets in-situ since counter is private to this method
                Pack.intToBigEndian(++counter32, counterOctets);
                otherInfo.encodeTo(digestSink, ASN1Encoding.DER);
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("unable to encode parameter info: " + e.getMessage());
            }

            if (len < digestSize)
            {
                byte[] tmp = new byte[digestSize];
                digest.doFinal(tmp, 0);
                System.arraycopy(tmp, 0, out, outOff, len);
                break;
            }

            digest.doFinal(out, outOff);
            outOff += digestSize;
            len -= digestSize;
        }

        return outputLength;
    }
}
