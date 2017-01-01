package org.bouncycastle.asn1.cmc;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * Object Identifiers from RFC 5272
 */
public interface CMCObjectIdentifiers
{
    //   id_pkix OBJECT IDENTIFIER  ::= { iso(1) identified_organization(3)
    //       dod(6) internet(1) security(5) mechanisms(5) pkix(7) }
   ASN1ObjectIdentifier id_pkix = new ASN1ObjectIdentifier("1.3.6.1.5.5.7");
        
   ASN1ObjectIdentifier id_cmc =  id_pkix.branch("7");   // CMC controls
   ASN1ObjectIdentifier id_cct =  id_pkix.branch("12");  // CMC content types
  
   // The following controls have the type OCTET STRING
  
   ASN1ObjectIdentifier id_cmc_identityProof =  id_cmc.branch("3");
   ASN1ObjectIdentifier id_cmc_dataReturn =  id_cmc.branch("4");
   ASN1ObjectIdentifier id_cmc_regInfo =  id_cmc.branch("18");
   ASN1ObjectIdentifier id_cmc_responseInfo =  id_cmc.branch("19");
   ASN1ObjectIdentifier id_cmc_queryPending =  id_cmc.branch("21");
   ASN1ObjectIdentifier id_cmc_popLinkRandom =  id_cmc.branch("22");
   ASN1ObjectIdentifier id_cmc_popLinkWitness =  id_cmc.branch("23");
  
   // The following controls have the type UTF8String
  
   ASN1ObjectIdentifier id_cmc_identification =  id_cmc.branch("2");
  
   // The following controls have the type INTEGER
  
   ASN1ObjectIdentifier id_cmc_transactionId =  id_cmc.branch("5");
  
   // The following controls have the type OCTET STRING
  
   ASN1ObjectIdentifier id_cmc_senderNonce =  id_cmc.branch("6");
   ASN1ObjectIdentifier id_cmc_recipientNonce =  id_cmc.branch("7");
  
    // This is the content type used for a request message in the protocol
  
   ASN1ObjectIdentifier id_cct_PKIData =  id_cct.branch("2");

    //  This defines the response message in the protocol
    ASN1ObjectIdentifier id_cct_PKIResponse = id_cct.branch("3");

    // Used to return status state in a response

    ASN1ObjectIdentifier id_cmc_statusInfo = id_cmc.branch("1");


    // Used for RAs to add extensions to certification requests
    ASN1ObjectIdentifier id_cmc_addExtensions = id_cmc.branch("8");

    ASN1ObjectIdentifier id_cmc_encryptedPOP = id_cmc.branch("9");
    ASN1ObjectIdentifier id_cmc_decryptedPOP = id_cmc.branch("10");


    ASN1ObjectIdentifier id_cmc_lraPOPWitness = id_cmc.branch("11");

    ASN1ObjectIdentifier id_cmc_getCert = id_cmc.branch("15");

    ASN1ObjectIdentifier id_cmc_getCRL = id_cmc.branch("16");

    ASN1ObjectIdentifier id_cmc_revokeRequest = id_cmc.branch("17");


    ASN1ObjectIdentifier id_cmc_confirmCertAcceptance = id_cmc.branch("24");

    //  Replaces CMC Status Info
    //

    ASN1ObjectIdentifier id_cmc_statusInfoV2 = id_cmc.branch("25");


    //  Allow for distribution of trust anchors
    //

    ASN1ObjectIdentifier id_cmc_trustedAnchors = id_cmc.branch("26");

    ASN1ObjectIdentifier id_cmc_authData = id_cmc.branch("27");

    //   These two items use BodyPartList
    ASN1ObjectIdentifier id_cmc_batchRequests = id_cmc.branch("28");
    ASN1ObjectIdentifier id_cmc_batchResponses = id_cmc.branch("29");

    ASN1ObjectIdentifier id_cmc_publishCert = id_cmc.branch("30");

    ASN1ObjectIdentifier id_cmc_modCertTemplate = id_cmc.branch("31");

    // Inform follow on servers that one or more controls have already been
    // processed

    ASN1ObjectIdentifier id_cmc_controlProcessed = id_cmc.branch("32");

    //  Identity Proof control w/ algorithm agility

    ASN1ObjectIdentifier id_cmc_identityProofV2 = id_cmc.branch("34");
    
    ASN1ObjectIdentifier id_cmc_popLinkWitnessV2 = id_cmc.branch("33");
}
