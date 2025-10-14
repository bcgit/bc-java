package org.bouncycastle.cert.cmp;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.POPODecKeyRespContent;

public class POPODecryptionKeyResponseContent
{
    private final POPODecKeyRespContent respContent;

    POPODecryptionKeyResponseContent(POPODecKeyRespContent respContent)
    {
        this.respContent = respContent;
    }

    public byte[][] getResponses()
    {
        ASN1Integer[] resps = respContent.toASN1IntegerArray();
        byte[][] rv = new byte[resps.length][];

        for (int i = 0; i != resps.length; i++)
        {
            rv[i] = resps[i].getValue().toByteArray();
        }

        return rv;
    }

    public static POPODecryptionKeyResponseContent fromPKIBody(PKIBody pkiBody)
    {
        if (pkiBody.getType() != PKIBody.TYPE_POPO_REP)
        {
            throw new IllegalArgumentException("content of PKIBody wrong type: " + pkiBody.getType());
        }

        return new POPODecryptionKeyResponseContent(POPODecKeyRespContent.getInstance(pkiBody.getContent()));
    }

    public POPODecKeyRespContent toASN1Structure()
    {
        return respContent;
    }
}
