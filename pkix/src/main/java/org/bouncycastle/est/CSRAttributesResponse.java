package org.bouncycastle.est;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

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
    // keyed on the OID's string form: an ordered map keeps a response whose OIDs share a hash code linear to index
    private final Map<String, AttrOrOID> index;

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
        this.index = new TreeMap<String, AttrOrOID>();

        AttrOrOID[] attrOrOIDs = csrAttrs.getAttrOrOIDs();
        for (int i = 0; i != attrOrOIDs.length; i++)
        {
            AttrOrOID attrOrOID = attrOrOIDs[i];

            if (attrOrOID.isOid())
            {
                index.put(attrOrOID.getOid().getId(), attrOrOID);
            }
            else
            {
                index.put(attrOrOID.getAttribute().getAttrType().getId(), attrOrOID);
            }
        }
    }

    private static CsrAttrs parseBytes(byte[] responseEncoding)
        throws ESTException
    {
        try
        {
            ASN1Primitive obj = ASN1Primitive.fromByteArray(responseEncoding);
            if (obj == null)
            {
                throw new IOException("no content found");
            }
            return CsrAttrs.getInstance(obj);
        }
        catch (Exception e)
        {
            throw new ESTException("malformed data: " + e.getMessage(), e);
        }
    }

    public boolean hasRequirement(ASN1ObjectIdentifier requirementOid)
    {
        return index.containsKey(requirementOid.getId());
    }

    public boolean isAttribute(ASN1ObjectIdentifier requirementOid)
    {
        if (index.containsKey(requirementOid.getId()))
        {
            return !(((AttrOrOID)index.get(requirementOid.getId())).isOid());
        }

        return false;
    }

    public boolean isEmpty()
    {
        return csrAttrs.size() == 0;
    }

    public Collection<ASN1ObjectIdentifier> getRequirements()
    {
        List<ASN1ObjectIdentifier> oids = new ArrayList<ASN1ObjectIdentifier>(index.size());

        for (Iterator<AttrOrOID> it = index.values().iterator(); it.hasNext();)
        {
            AttrOrOID attrOrOID = it.next();

            oids.add(attrOrOID.isOid() ? attrOrOID.getOid() : attrOrOID.getAttribute().getAttrType());
        }

        return oids;
    }

    public byte[] getEncoded()
        throws IOException
    {
        return csrAttrs.getEncoded();
    }
}
