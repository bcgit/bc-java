package org.bouncycastle.dvcs;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.dvcs.CertEtcToken;
import org.bouncycastle.asn1.dvcs.DVCSRequestInformationBuilder;
import org.bouncycastle.asn1.dvcs.DVCSTime;
import org.bouncycastle.asn1.dvcs.Data;
import org.bouncycastle.asn1.dvcs.ServiceType;
import org.bouncycastle.asn1.dvcs.TargetEtcChain;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Builder of DVC requests to VPKC service (Verify Public Key Certificates).
 */
public class VPKCRequestBuilder
    extends DVCSRequestBuilder
{
    private List chains = new ArrayList();

    public VPKCRequestBuilder()
    {
        super(new DVCSRequestInformationBuilder(ServiceType.VPKC));
    }

    /**
     * Adds a TargetChain representing a X.509 certificate to the request.
     *
     * @param cert the certificate to be added
     */
    public void addTargetChain(X509CertificateHolder cert)
    {
        chains.add(new TargetEtcChain(new CertEtcToken(CertEtcToken.TAG_CERTIFICATE, cert.toASN1Structure())));
    }

    /**
     * Adds a TargetChain representing a single X.509 Extension to the request
     *
     * @param extension the extension to be added.
     */
    public void addTargetChain(Extension extension)
    {
        chains.add(new TargetEtcChain(new CertEtcToken(extension)));
    }

    /**
     * Adds a X.509 certificate to the request.
     *
     * @param targetChain the CertChain object to be added.
     */
    public void addTargetChain(TargetChain targetChain)
    {
        chains.add(targetChain.toASN1Structure());
    }

    public void setRequestTime(Date requestTime)
    {
        requestInformationBuilder.setRequestTime(new DVCSTime(requestTime));
    }

    /**
     * Build DVCS request to VPKC service.
     *
     * @return a new DVCSRequest based on the state of this builder.
     * @throws DVCSException if an issue occurs during construction.
     */
    public DVCSRequest build()
        throws DVCSException
    {
        Data data = new Data((TargetEtcChain[])chains.toArray(new TargetEtcChain[chains.size()]));

        return createDVCRequest(data);
    }
}
