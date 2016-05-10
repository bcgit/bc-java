package com.github.gv2011.bcasn.asn1.smime;

import com.github.gv2011.bcasn.asn1.DERSequence;
import com.github.gv2011.bcasn.asn1.DERSet;
import com.github.gv2011.bcasn.asn1.cms.Attribute;

public class SMIMECapabilitiesAttribute
    extends Attribute
{
    public SMIMECapabilitiesAttribute(
        SMIMECapabilityVector capabilities)
    {
        super(SMIMEAttributes.smimeCapabilities,
                new DERSet(new DERSequence(capabilities.toASN1EncodableVector())));
    }
}
