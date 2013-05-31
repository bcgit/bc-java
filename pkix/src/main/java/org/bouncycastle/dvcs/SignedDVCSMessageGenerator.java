package org.bouncycastle.dvcs;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;

public class SignedDVCSMessageGenerator
{
    private final CMSSignedDataGenerator signedDataGen;

    public SignedDVCSMessageGenerator(CMSSignedDataGenerator signedDataGen)
    {
        this.signedDataGen = signedDataGen;
    }

    /**
     * Creates a CMSSignedData object containing the passed in DVCSMessage
     *
     * @param message the request to be signed.
     * @return an encapsulating SignedData object.
     * @throws DVCSException in the event of failure to encode the request or sign it.
     */
    public CMSSignedData build(DVCSMessage message)
        throws DVCSException
    {
        try
        {
            byte[] encapsulatedData = message.getContent().toASN1Primitive().getEncoded(ASN1Encoding.DER);

            return signedDataGen.generate(new CMSProcessableByteArray(message.getContentType(), encapsulatedData), true);
        }
        catch (CMSException e)
        {
            throw new DVCSException("Could not sign DVCS request", e);
        }
        catch (IOException e)
        {
            throw new DVCSException("Could not encode DVCS request", e);
        }
    }
}
