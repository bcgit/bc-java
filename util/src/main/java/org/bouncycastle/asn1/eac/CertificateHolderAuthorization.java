package org.bouncycastle.asn1.eac;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Integers;

/**
 * an Iso7816CertificateHolderAuthorization structure.
 * <pre>
 *  Certificate Holder Authorization ::= SEQUENCE {
 *      // specifies the format and the rules for the evaluation of the authorization
 *      // level
 *      ASN1ObjectIdentifier        oid,
 *      // access rights
 *      ASN1TaggedObject            accessRights,
 *  }
 * </pre>
 */
public class CertificateHolderAuthorization
    extends ASN1Object
{
    public static final ASN1ObjectIdentifier id_role_EAC = EACObjectIdentifiers.bsi_de.branch("3.1.2.1");

    public static final int CVCA = 0xC0;
    public static final int DV_DOMESTIC = 0x80;
    public static final int DV_FOREIGN = 0x40;
    public static final int IS = 0;
    public static final int RADG4 = 0x02;//Read Access to DG4 (Iris)
    public static final int RADG3 = 0x01;//Read Access to DG3 (fingerprint)

    static Map RightsDecodeMap = new HashMap();
    static BidirectionalMap AuthorizationRole = new BidirectionalMap();

    static
    {
        RightsDecodeMap.put(Integers.valueOf(RADG4), "RADG4");
        RightsDecodeMap.put(Integers.valueOf(RADG3), "RADG3");

        AuthorizationRole.put(Integers.valueOf(CVCA), "CVCA");
        AuthorizationRole.put(Integers.valueOf(DV_DOMESTIC), "DV_DOMESTIC");
        AuthorizationRole.put(Integers.valueOf(DV_FOREIGN), "DV_FOREIGN");
        AuthorizationRole.put(Integers.valueOf(IS), "IS");
    }

    private ASN1ObjectIdentifier oid;
    private byte accessRights;

    public static String getRoleDescription(int i)
    {
        return (String)AuthorizationRole.get(Integers.valueOf(i));
    }

    public static int getFlag(String description)
    {
        Integer i = (Integer)AuthorizationRole.getReverse(description);
        if (i == null)
        {
            throw new IllegalArgumentException("Unknown value " + description);
        }

        return i.intValue();
    }

    private void setPrivateData(ASN1Sequence seq)
    {
        ASN1Primitive obj;
        obj = (ASN1Primitive)seq.getObjectAt(0);
        if (obj instanceof ASN1ObjectIdentifier)
        {
            this.oid = (ASN1ObjectIdentifier)obj;
        }
        else
        {
            throw new IllegalArgumentException("no Oid in CerticateHolderAuthorization");
        }
        obj = (ASN1Primitive)seq.getObjectAt(1);
        if (obj instanceof ASN1TaggedObject)
        {
            ASN1TaggedObject tObj = ASN1TaggedObject.getInstance(obj, BERTags.APPLICATION, EACTags.DISCRETIONARY_DATA);
            this.accessRights = ASN1OctetString.getInstance(tObj.getBaseUniversal(false, BERTags.OCTET_STRING)).getOctets()[0];
        }
        else
        {
            throw new IllegalArgumentException("No access rights in CerticateHolderAuthorization");
        }
    }


    /**
     * create an Iso7816CertificateHolderAuthorization according to the parameters
     *
     * @param oid    Object Identifier : specifies the format and the rules for the
     *               evaluatioin of the authorization level.
     * @param rights specifies the access rights
     * @throws IOException
     */
    public CertificateHolderAuthorization(ASN1ObjectIdentifier oid, int rights)
        throws IOException
    {
        setOid(oid);
        setAccessRights((byte)rights);
    }

    /**
     * create an Iso7816CertificateHolderAuthorization according to the {@link ASN1TaggedObject}
     *
     * @param aSpe the ASN1TaggedObject containing the data
     * @throws IOException
     */
    public CertificateHolderAuthorization(ASN1TaggedObject aSpe)
        throws IOException
    {
        if (aSpe.hasTag(BERTags.APPLICATION, EACTags.CERTIFICATE_HOLDER_AUTHORIZATION_TEMPLATE))
        {
            setPrivateData(ASN1Sequence.getInstance(aSpe.getBaseUniversal(false, BERTags.SEQUENCE)));
        }
        else
        {
            throw new IllegalArgumentException("Unrecognized object in CerticateHolderAuthorization");
        }
    }

    /**
     * @return containing the access rights
     */
    public int getAccessRights()
    {
        return accessRights & 0xff;
    }

    /**
     * create an ASN1TaggedObject and set the access rights to "rights"
     *
     * @param rights byte containing the rights.
     */
    private void setAccessRights(byte rights)
    {
        this.accessRights = rights;
    }

    /**
     * @return the Object identifier
     */
    public ASN1ObjectIdentifier getOid()
    {
        return oid;
    }

    /**
     * set the Object Identifier
     *
     * @param oid {@link ASN1ObjectIdentifier} containing the Object Identifier
     */
    private void setOid(ASN1ObjectIdentifier oid)
    {
        this.oid = oid;
    }

    /**
     * return the Certificate Holder Authorization as an ASN1TaggedObject
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(oid);
        v.add(EACTagged.create(EACTags.DISCRETIONARY_DATA, new byte[] { accessRights }));

        return EACTagged.create(EACTags.CERTIFICATE_HOLDER_AUTHORIZATION_TEMPLATE, new DERSequence(v));
    }
}
