package org.bouncycastle.dvcs;

import java.io.IOException;
import java.util.Date;

import org.bouncycastle.asn1.dvcs.DVCSRequestInformationBuilder;
import org.bouncycastle.asn1.dvcs.DVCSTime;
import org.bouncycastle.asn1.dvcs.Data;
import org.bouncycastle.asn1.dvcs.ServiceType;
import org.bouncycastle.cms.CMSSignedData;

/**
 * Builder of DVCS requests to VSD service (Verify Signed Document).
 */
public class VSDRequestBuilder
    extends DVCSRequestBuilder
{
    public VSDRequestBuilder()
    {
        super(new DVCSRequestInformationBuilder(ServiceType.VSD));
    }

    public void setRequestTime(Date requestTime)
    {
        requestInformationBuilder.setRequestTime(new DVCSTime(requestTime));
    }

    /**
     * Build VSD request from CMS SignedData object.
     *
     * @param document the CMS SignedData to include in the request.
     * @return a new DVCSRequest based on the state of this builder.
     * @throws DVCSException if an issue occurs during construction.
     */
    public DVCSRequest build(CMSSignedData document)
        throws DVCSException
    {
        try
        {
            Data data = new Data(document.getEncoded());

            return createDVCRequest(data);
        }
        catch (IOException e)
        {
            throw new DVCSException("Failed to encode CMS signed data", e);
        }
    }
}
