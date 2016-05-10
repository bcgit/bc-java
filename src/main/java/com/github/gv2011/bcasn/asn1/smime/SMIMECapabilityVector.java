package com.github.gv2011.bcasn.asn1.smime;

import com.github.gv2011.bcasn.asn1.ASN1Encodable;
import com.github.gv2011.bcasn.asn1.ASN1EncodableVector;
import com.github.gv2011.bcasn.asn1.ASN1Integer;
import com.github.gv2011.bcasn.asn1.ASN1ObjectIdentifier;
import com.github.gv2011.bcasn.asn1.DERSequence;

/**
 * Handler for creating a vector S/MIME Capabilities
 */
public class SMIMECapabilityVector
{
    private ASN1EncodableVector    capabilities = new ASN1EncodableVector();

    public void addCapability(
        ASN1ObjectIdentifier capability)
    {
        capabilities.add(new DERSequence(capability));
    }

    public void addCapability(
        ASN1ObjectIdentifier capability,
        int                 value)
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add(capability);
        v.add(new ASN1Integer(value));

        capabilities.add(new DERSequence(v));
    }

    public void addCapability(
        ASN1ObjectIdentifier capability,
        ASN1Encodable params)
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add(capability);
        v.add(params);

        capabilities.add(new DERSequence(v));
    }

    public ASN1EncodableVector toASN1EncodableVector()
    {
        return capabilities;
    }
}
