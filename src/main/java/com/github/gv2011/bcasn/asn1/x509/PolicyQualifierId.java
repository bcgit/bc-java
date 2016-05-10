
package com.github.gv2011.bcasn.asn1.x509;

import com.github.gv2011.bcasn.asn1.ASN1ObjectIdentifier;

/**
 * PolicyQualifierId, used in the CertificatePolicies
 * X509V3 extension.
 * 
 * <pre>
 *    id-qt          OBJECT IDENTIFIER ::=  { id-pkix 2 }
 *    id-qt-cps      OBJECT IDENTIFIER ::=  { id-qt 1 }
 *    id-qt-unotice  OBJECT IDENTIFIER ::=  { id-qt 2 }
 *  PolicyQualifierId ::=
 *       OBJECT IDENTIFIER (id-qt-cps | id-qt-unotice)
 * </pre>
 */
public class PolicyQualifierId extends ASN1ObjectIdentifier 
{
   private static final String id_qt = "1.3.6.1.5.5.7.2";

   private PolicyQualifierId(String id) 
      {
         super(id);
      }
   
   public static final PolicyQualifierId id_qt_cps =
       new PolicyQualifierId(id_qt + ".1");
   public static final PolicyQualifierId id_qt_unotice =
       new PolicyQualifierId(id_qt + ".2");
}
