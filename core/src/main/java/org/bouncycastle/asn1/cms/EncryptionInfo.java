package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.*;

/**
 * Implementation of the EncryptionInfo element defined in RFC 4998:
 *
 * 1988 ASN.1 EncryptionInfo
 *
 * EncryptionInfo       ::=     SEQUENCE {
 *   encryptionInfoType     OBJECT IDENTIFIER,
 *   encryptionInfoValue    ANY DEFINED BY encryptionInfoType
 * }
 *
 * 1997-ASN.1 EncryptionInfo
 *
 * EncryptionInfo       ::=     SEQUENCE {
 *   encryptionInfoType   ENCINFO-TYPE.&id
 *   ({SupportedEncryptionAlgorithms}),
 *   encryptionInfoValue  ENCINFO-TYPE.&Type
 *   ({SupportedEncryptionAlgorithms}{@encryptionInfoType})
 * }
 *
 * ENCINFO-TYPE ::= TYPE-IDENTIFIER
 *
 * SupportedEncryptionAlgorithms ENCINFO-TYPE ::= {...}
 *
 */
public class EncryptionInfo extends ASN1Object
{

  /**
   * The OID for EncryptionInfo type.
   */
  private ASN1ObjectIdentifier encryptionInfoType;

  /**
   * The value of EncryptionInfo
   */
  private ASN1Object encryptionInfoValue;

  public static EncryptionInfo getInstance(final ASN1Object object) {

    return new EncryptionInfo();
  }

  public static EncryptionInfo getInstance(final ASN1ObjectIdentifier identifier,
                                           final ASN1Object encryptionValue) {

    return new EncryptionInfo(identifier, encryptionValue);
  }

  public EncryptionInfo(final ASN1ObjectIdentifier encryptionInfoType,
                        final ASN1Object encryptionInfoValue) {

    this.encryptionInfoType = encryptionInfoType;
    this.encryptionInfoValue = encryptionInfoValue;
  }

  private EncryptionInfo() {

  }

  @Override
  public ASN1Primitive toASN1Primitive() {

    final ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(encryptionInfoType);
    v.add(encryptionInfoValue);

    return ASN1Sequence.getInstance(v);
  }

}
