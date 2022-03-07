package org.bouncycastle.oer.its.template.etsi103097;

import org.bouncycastle.oer.OERDefinition;
import org.bouncycastle.oer.its.template.ieee1609dot2.IEEE1609dot2;

/**
 * EtsiTs103097Module
 * {itu-t(0) identified-organization(4) etsi(0) itsDomain(5) wg5(5) secHeaders(103097) core(1) version2(2)}
 * <p>
 * https://forge.etsi.org/rep/ITS/asn1/sec_ts103097/blob/v1.4.1/EtsiTs103097Module.asn
 */
public class EtsiTs103097Module
{

    public static final OERDefinition.Builder EtsiTs103097Certificate = IEEE1609dot2.ExplicitCertificate.typeName("EtsiTs103097Certificate");


    /**
     * EtsiTs103097Data::=Ieee1609Dot2Data (WITH COMPONENTS {...,
     * content (WITH COMPONENTS {...,
     * signedData (WITH COMPONENTS {..., -- constraints on signed data headers
     * tbsData (WITH COMPONENTS {
     * headerInfo (WITH COMPONENTS {...,
     * generationTime PRESENT,
     * p2pcdLearningRequest ABSENT,
     * missingCrlIdentifier ABSENT
     * })
     * }),
     * signer (WITH COMPONENTS {...,  --constraints on the certificate
     * certificate ((WITH COMPONENT (EtsiTs103097Certificate))^(SIZE(1)))
     * })
     * }),
     * encryptedData (WITH COMPONENTS {..., -- constraints on encrypted data headers
     * recipients  (WITH COMPONENT (
     * (WITH COMPONENTS {...,
     * pskRecipInfo ABSENT,
     * symmRecipInfo ABSENT,
     * rekRecipInfo ABSENT
     * })
     * ))
     * }),
     * signedCertificateRequest ABSENT
     * })
     * })
     */
    public static final OERDefinition.Builder EtsiTs103097Data = IEEE1609dot2.Ieee1609Dot2Data.typeName("EtsiTs103097Data");

    /**
     * EtsiTs103097Data-Unsecured {ToBeSentDataContent} ::= EtsiTs103097Data (WITH COMPONENTS {...,
     * content (WITH COMPONENTS {
     * unsecuredData (CONTAINING ToBeSentDataContent)
     * })
     * })
     */
    public static final OERDefinition.Builder EtsiTs103097Data_Unsecured = EtsiTs103097Data.typeName("EtsiTs103097DataUnsecured");


    /**
     * EtsiTs103097Data-Signed {ToBeSignedDataContent} ::= EtsiTs103097Data (WITH COMPONENTS {...,
     * content (WITH COMPONENTS {
     * signedData (WITH COMPONENTS {...,
     * tbsData (WITH COMPONENTS {
     * payload (WITH COMPONENTS {
     * data (WITH COMPONENTS {...,
     * content (WITH COMPONENTS {
     * unsecuredData (CONTAINING ToBeSignedDataContent)
     * })
     * }) PRESENT
     * })
     * })
     * })
     * })
     * })
     */
    public static final OERDefinition.Builder EtsiTs103097Data_Signed = EtsiTs103097Data.typeName("EtsiTs103097DataSigned");


    /**
     * EtsiTs103097Data-SignedExternalPayload ::= EtsiTs103097Data (WITH COMPONENTS {...,
     * content (WITH COMPONENTS {
     * signedData (WITH COMPONENTS {...,
     * tbsData (WITH COMPONENTS {
     * payload (WITH COMPONENTS {
     * extDataHash (WITH COMPONENTS {
     * sha256HashedData PRESENT
     * }) PRESENT
     * })
     * })
     * })
     * })
     * })
     */
    public static final OERDefinition.Builder EtsiTs103097Data_SignedExternalPayload = EtsiTs103097Data.typeName("EtsiTs103097DataSignedExternalPayload");


    /**
     * EtsiTs103097Data-Encrypted {ToBeEncryptedDataContent} ::= EtsiTs103097Data (WITH COMPONENTS {...,
     * content (WITH COMPONENTS {
     * encryptedData (WITH COMPONENTS {...,
     * ciphertext (WITH COMPONENTS {...,
     * aes128ccm (WITH COMPONENTS {...,
     * ccmCiphertext (CONSTRAINED BY {-- ccm encryption of -- ToBeEncryptedDataContent})
     * })
     * })
     * })
     * })
     * })
     */
    public static final OERDefinition.Builder EtsiTs103097Data_Encrypted = EtsiTs103097Data.typeName("EtsiTs103097DataEncrypted");


    /**
     * EtsiTs103097Data-SignedAndEncrypted {ToBesignedAndEncryptedDataContent} ::= EtsiTs103097Data-Encrypted
     * {EtsiTs103097Data-Signed {ToBesignedAndEncryptedDataContent}}
     */
    public static final OERDefinition.Builder EtsiTs103097Data_SignedAndEncrypted = EtsiTs103097Data.typeName("EtsiTs103097DataSignedAndEncrypted");


    /**
     * EtsiTs103097Data-Encrypted-Unicast {ToBeEncryptedDataContent} ::= EtsiTs103097Data-Encrypted { EtsiTs103097Data-Unsecured{ToBeEncryptedDataContent}} (WITH COMPONENTS {...,
     *   content (WITH COMPONENTS {
     *     encryptedData (WITH COMPONENTS {...,
     *       recipients (SIZE(1))
     *     })
     *   })
     * })
     */
    public static final OERDefinition.Builder EtsiTs103097Data_Encrypted_Unicast = EtsiTs103097Data.typeName("EtsiTs103097DataEncryptedUnicast");


    /**
     * EtsiTs103097Data-SignedAndEncrypted-Unicast {ToBesignedAndEncryptedDataContent} ::= EtsiTs103097Data-Encrypted
     * {EtsiTs103097Data-Signed {ToBesignedAndEncryptedDataContent}} (WITH COMPONENTS {...,
     * content (WITH COMPONENTS {
     * encryptedData (WITH COMPONENTS {...,
     * recipients (SIZE(1))
     * })
     * })
     * })
     */
    public static final OERDefinition.Builder EtsiTs103097Data_SignedAndEncrypted_Unicast = EtsiTs103097Data.typeName("EtsiTs103097DataSignedAndEncryptedUnicast");


}
