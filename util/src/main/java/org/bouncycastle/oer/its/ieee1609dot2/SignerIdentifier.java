package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId8;

/**
 * SignerIdentifier
 * This structure allows the recipient of data to determine which
 * keying material to use to authenticate the data. It also indicates the
 * verification type to be used to generate the hash for verification, as
 * specified in 5.3.1.
 * <ul>
 * <li> If the choice indicated is digest:</li>
 * <ul>
 * <li> The structure contains the HashedId8 of the relevant certificate. The
 * HashedId8 is calculated with the whole-certificate hash algorithm,
 * determined as described in 6.4.3.</li>
 *
 * <li> The verification type is <i>certificate</i> and the certificate data
 * passed to the hash function as specified in 5.3.1 is the authorization
 * certificate.</li>
 * </ul>
 *
 * <li> If the choice indicated is certificate:</li>
 * <ul>
 * <li> The structure contains one or more Certificate structures, in order
 * such that the first certificate is the authorization certificate and each
 * subsequent certificate is the issuer of the one before it.</li>
 *
 * <li> The verification type is <i>certificate</i> and the certificate data
 * passed to the hash function as specified in 5.3.1 is the authorization
 * certificate.</li>
 * </ul>
 *
 * <li> If the choice indicated is self:</li>
 * <ul>
 * <li> The structure does not contain any data beyond the indication that
 * the choice value is self.</li>
 *
 * <li> The verification type is <i>self-signed</i>.</li>
 * </ul>
 * </ul>
 *
 * <b>Critical information fields</b>:
 * <ol>
 * <li> If present, this is a critical information field as defined in 5.2.6.
 * An implementation that does not recognize the CHOICE value for this type
 * when verifying a signed SPDU shall indicate that the signed SPDU is invalid.
 * </li>
 *
 * <li> If present, certificate is a critical information field as defined in
 * 5.2.6. An implementation that does not support the number of certificates
 * in certificate when verifying a signed SPDU shall indicate that the signed
 * SPDU is invalid. A compliant implementation shall support certificate
 * fields containing at least one certificate.</li>
 * </ol>
 * <p>
 * SignerIdentifier ::= CHOICE {
 *     digest       HashedId8,
 *     certificate  SequenceOfCertificate,
 *     self         NULL,
 *     ...
 *     }
 */
public class SignerIdentifier
    extends ASN1Object
    implements ASN1Choice
{

    public static final int digest = 0;
    public static final int certificate = 1;
    public static final int self = 2;


    private final int choice;
    private final ASN1Encodable signerIdentifier;


    public SignerIdentifier(int choice, ASN1Encodable value)
    {
        this.choice = choice;
        this.signerIdentifier = value;
    }


    private SignerIdentifier(ASN1TaggedObject ato)
    {
        choice = ato.getTagNo();
        switch (choice)
        {
        case digest:
            signerIdentifier = HashedId8.getInstance(ato.getExplicitBaseObject());
            break;
        case certificate:
            signerIdentifier = SequenceOfCertificate.getInstance(ato.getExplicitBaseObject());
            break;
        case self:
            signerIdentifier = DERNull.getInstance(ato.getExplicitBaseObject());
            break;

        default:
            throw new IllegalArgumentException("invalid choice value " + choice);
        }

    }

    public static SignerIdentifier getInstance(Object src)
    {

        if (src instanceof SignerIdentifier)
        {
            return (SignerIdentifier)src;
        }

        if (src != null)
        {
            return new SignerIdentifier(ASN1TaggedObject.getInstance(src, BERTags.CONTEXT_SPECIFIC));
        }

        return null;
    }


    public int getChoice()
    {
        return choice;
    }

    public static SignerIdentifier digest(HashedId8 id)
    {
        return new SignerIdentifier(digest, id);
    }

    public static SignerIdentifier certificate(SequenceOfCertificate sequenceOfCertificate)
    {
        return new SignerIdentifier(certificate, sequenceOfCertificate);
    }

    public static SignerIdentifier self()
    {
        return new SignerIdentifier(self, DERNull.INSTANCE);
    }


    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, signerIdentifier);
    }


    public ASN1Encodable getSignerIdentifier()
    {
        return signerIdentifier;
    }



}
