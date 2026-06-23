package org.bouncycastle.asn1.isara;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public interface IsaraObjectIdentifiers
{
    /*
    id-alg-xmss  OBJECT IDENTIFIER ::= { 
       so(1) identified-organization(3) dod(6) internet(1)
       security(5) mechanisms(5) pkix(7) algorithms(6) 34 }
     */
    static ASN1ObjectIdentifier id_alg_xmss = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.6.34");

    /*
      id-alg-xmssmt  OBJECT IDENTIFIER ::= { 
         so(1) identified-organization(3) dod(6) internet(1)
         security(5) mechanisms(5) pkix(7) algorithms(6) 35 }
     */
    static ASN1ObjectIdentifier id_alg_xmssmt = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.6.35");
}
