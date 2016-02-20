package org.bouncycastle.pkcs;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.MacData;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.pkcs.Pfx;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.Arrays;

/**
 * A holding class for the PKCS12 Pfx structure.
 */
public class PKCS12PfxPdu
{
    private Pfx pfx;

    private static Pfx parseBytes(byte[] pfxEncoding)
        throws IOException
    {
        try
        {
            return Pfx.getInstance(ASN1Primitive.fromByteArray(pfxEncoding));
        }
        catch (ClassCastException e)
        {
            throw new PKCSIOException("malformed data: " + e.getMessage(), e);
        }
        catch (IllegalArgumentException e)
        {
            throw new PKCSIOException("malformed data: " + e.getMessage(), e);
        }
    }

    public PKCS12PfxPdu(Pfx pfx)
    {
        this.pfx = pfx;
    }

    public PKCS12PfxPdu(byte[] pfx)
        throws IOException
    {
        this(parseBytes(pfx));
    }

    /**
     * Return the content infos in the AuthenticatedSafe contained in this Pfx.
     *
     * @return an array of ContentInfo.
     */
    public ContentInfo[] getContentInfos()
    {
        ASN1Sequence seq = ASN1Sequence.getInstance(ASN1OctetString.getInstance(this.pfx.getAuthSafe().getContent()).getOctets());
        ContentInfo[] content = new ContentInfo[seq.size()];

        for (int i = 0; i != seq.size(); i++)
        {
            content[i] = ContentInfo.getInstance(seq.getObjectAt(i));
        }

        return content;
    }

    /**
     * Return whether or not there is MAC attached to this file.
     *
     * @return true if there is, false otherwise.
     */
    public boolean hasMac()
    {
        return pfx.getMacData() != null;
    }

    /**
     * Return the algorithm identifier describing the MAC algorithm
     *
     * @return the AlgorithmIdentifier representing the MAC algorithm, null if none present.
     */
    public AlgorithmIdentifier getMacAlgorithmID()
    {
        MacData md = pfx.getMacData();

        if (md != null)
        {
            return md.getMac().getAlgorithmId();
        }

        return null;
    }

    /**
     * Verify the MacData attached to the PFX is consistent with what is expected.
     *
     * @param macCalcProviderBuilder provider builder for the calculator for the MAC
     * @param password password to use
     * @return true if mac data is valid, false otherwise.
     * @throws PKCSException if there is a problem evaluating the MAC.
     * @throws IllegalStateException if no MAC is actually present
     */
    public boolean isMacValid(PKCS12MacCalculatorBuilderProvider macCalcProviderBuilder, char[] password)
        throws PKCSException
    {
        if (hasMac())
        {
            MacData pfxmData = pfx.getMacData();
            MacDataGenerator mdGen = new MacDataGenerator(macCalcProviderBuilder.get(new AlgorithmIdentifier(pfxmData.getMac().getAlgorithmId().getAlgorithm(), new PKCS12PBEParams(pfxmData.getSalt(), pfxmData.getIterationCount().intValue()))));

            try
            {
                MacData mData = mdGen.build(
                    password,
                    ASN1OctetString.getInstance(pfx.getAuthSafe().getContent()).getOctets());

                return Arrays.constantTimeAreEqual(mData.getEncoded(), pfx.getMacData().getEncoded());
            }
            catch (IOException e)
            {
                throw new PKCSException("unable to process AuthSafe: " + e.getMessage());
            }
        }

        throw new IllegalStateException("no MAC present on PFX");
    }

    /**
     * Return the underlying ASN.1 object.
     *
     * @return a Pfx object.
     */
    public Pfx toASN1Structure()
    {
        return pfx;
    }

    public byte[] getEncoded()
        throws IOException
    {
        return toASN1Structure().getEncoded();
    }

    /**
     * Return a Pfx with the outer wrapper encoded as asked for. For example, Pfx is a usually
     * a BER encoded object, to get one with DefiniteLength encoding use:
     * <pre>
     * getEncoded(ASN1Encoding.DL)
     * </pre>
     * @param encoding encoding style (ASN1Encoding.DER, ASN1Encoding.DL, ASN1Encoding.BER)
     * @return a byte array containing the encoded object.
     * @throws IOException
     */
    public byte[] getEncoded(String encoding)
        throws IOException
    {
        return toASN1Structure().getEncoded(encoding);
    }
}
