/**
 * EtsiTs103097ExtensionModule
 * {itu-t(0) identified-organization(4) etsi(0) itsDomain(5) wg5(5) secHeaders(103097) extension(2) version1(1)}
 */
package org.bouncycastle.oer.its.etsi103097.extension;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;

/**
 * Ieee1609Dot2HeaderInfoContributedExtensions
 * IEEE1609DOT2-HEADERINFO-CONTRIBUTED-EXTENSION ::= {
 * {EtsiOriginatingHeaderInfoExtension IDENTIFIED BY etsiHeaderInfoContributorId},
 * ...
 * }
 */
public class EtsiOriginatingHeaderInfoExtension
    extends Extension
{
    public EtsiOriginatingHeaderInfoExtension(ExtId id, ASN1Encodable content)
    {
        super(id, content);
    }

    private EtsiOriginatingHeaderInfoExtension(ASN1Sequence sequence)
    {
        super(sequence);
    }

    public static EtsiOriginatingHeaderInfoExtension getInstance(Object o)
    {
        if (o instanceof EtsiOriginatingHeaderInfoExtension)
        {
            return (EtsiOriginatingHeaderInfoExtension)o;
        }

        if (o != null)
        {
            return new EtsiOriginatingHeaderInfoExtension(ASN1Sequence.getInstance(o));
        }

        return null;

    }



}
