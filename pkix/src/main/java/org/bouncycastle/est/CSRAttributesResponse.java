package org.bouncycastle.est;

import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.est.AttrOrOID;
import org.bouncycastle.asn1.est.CsrAttrs;
import org.bouncycastle.util.Encodable;

/**
 * Wrapper class around a CsrAttrs structure.
 */
public class CSRAttributesResponse
    implements Encodable
{
    private final CsrAttrs csrAttrs;
    private final HashMap<ASN1ObjectIdentifier, AttrOrOID> index;

    /**
     * Create a CSRAttributesResponse from the passed in bytes.
     *
     * @param responseEncoding BER/DER encoding of the certificate.
     * @throws ESTException in the event of corrupted data, or an incorrect structure.
     */
    public CSRAttributesResponse(byte[] responseEncoding)
        throws ESTException
    {
        this(parseBytes(responseEncoding));
    }

    /**
     * Create a CSRAttributesResponse from the passed in ASN.1 structure.
     *
     * @param csrAttrs an RFC 7030 CsrAttrs structure.
     */
    public CSRAttributesResponse(CsrAttrs csrAttrs)
        throws ESTException
    {
        this.csrAttrs = csrAttrs;
        this.index = new HashMap<ASN1ObjectIdentifier, AttrOrOID>(csrAttrs.size());

        AttrOrOID[] attrOrOIDs = csrAttrs.getAttrOrOIDs();
        for (int i = 0; i != attrOrOIDs.length; i++)
        {
            AttrOrOID attrOrOID = attrOrOIDs[i];

            if (attrOrOID.isOid())
            {
                index.put(attrOrOID.getOid(), attrOrOID);
            }
            else
            {
                index.put(attrOrOID.getAttribute().getAttrType(), attrOrOID);
            }
        }
    }

    private static CsrAttrs parseBytes(byte[] responseEncoding)
        throws ESTException
    {
        try
        {
            return CsrAttrs.getInstance(ASN1Primitive.fromByteArray(responseEncoding));
        }
        catch (Exception e)
        {
            throw new ESTException("malformed data: " + e.getMessage(), e);
        }
    }

    public boolean hasRequirement(ASN1ObjectIdentifier requirementOid)
    {
        return index.containsKey(requirementOid);
    }

    public boolean isAttribute(ASN1ObjectIdentifier requirementOid)
    {
        if (index.containsKey(requirementOid))
        {
            return !(((AttrOrOID)index.get(requirementOid)).isOid());
        }

        return false;
    }

    public boolean isEmpty()
    {
        return csrAttrs.size() == 0;
    }

    public Collection<ASN1ObjectIdentifier> getRequirements()
    {
        return index.keySet();
    }

    public byte[] getEncoded()
        throws IOException
    {
        return csrAttrs.getEncoded();
    }
}
