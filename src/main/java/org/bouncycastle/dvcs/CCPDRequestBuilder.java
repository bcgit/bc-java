package org.bouncycastle.dvcs;

import java.io.IOException;

import org.bouncycastle.asn1.dvcs.DVCSRequestInformationBuilder;
import org.bouncycastle.asn1.dvcs.Data;
import org.bouncycastle.asn1.dvcs.ServiceType;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;

/**
 * Builder of CCPD requests (Certify Claim of Possession of Data).
 */
public class CCPDRequestBuilder
    extends DVCSRequestBuilder
{
    public CCPDRequestBuilder()
    {
        super(new DVCSRequestInformationBuilder(ServiceType.CCPD));
    }

    /**
     * Builds CCPD request.
     *
     * @param messageImprint - the message imprint to include.
     * @return
     * @throws DVCSException
     */
    public DVCSRequest build(MessageImprint messageImprint)
        throws DVCSException
    {
        Data data = new Data(messageImprint.toASN1Structure());

        return createDVCRequest(data);
    }
}
