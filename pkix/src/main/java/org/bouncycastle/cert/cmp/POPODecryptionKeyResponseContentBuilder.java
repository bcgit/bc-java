package org.bouncycastle.cert.cmp;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.POPODecKeyRespContent;

public class POPODecryptionKeyResponseContentBuilder
{
    private ASN1EncodableVector v = new ASN1EncodableVector();

    public POPODecryptionKeyResponseContentBuilder addChallengeResponse(byte[] response)
    {
          v.add(new ASN1Integer(new BigInteger(response)));

          return this;
    }

    public POPODecryptionKeyResponseContent build()
    {
        return new POPODecryptionKeyResponseContent(POPODecKeyRespContent.getInstance(new DERSequence(v)));
    }
}
