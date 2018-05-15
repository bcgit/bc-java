package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

/**
 * Implementation of the CryptoInfos element defined in RFC 4998:
 *
 * CryptoInfos ::= SEQUENCE SIZE (1..MAX OF Attribute
 *
 */
public class CryptoInfos extends ASN1Object
{

  private ASN1Sequence attributes;

  @Override
  public ASN1Primitive toASN1Primitive() {
    return null;
  }

  public static CryptoInfos getInstance (final Object obj)
  {

    if (obj == null || obj instanceof CryptoInfos)
    {
      return (CryptoInfos) obj;
    }
    else if (obj instanceof ASN1Sequence || obj instanceof byte[])
    {
      return new CryptoInfos(ASN1Sequence.getInstance(obj));
    }

    throw new IllegalArgumentException("unknown object in getInstance: " + obj.getClass().getName
        ());
  }

  private CryptoInfos(final ASN1Sequence attributes)
  {
    this.attributes = attributes;
  }
}
