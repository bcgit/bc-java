package org.bouncycastle.asn1.x509.qualified;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.GeneralName;

/**
 * The SemanticsInformation object.
 * <pre>
 *       SemanticsInformation ::= SEQUENCE {
 *         semanticsIdentifier        OBJECT IDENTIFIER   OPTIONAL,
 *         nameRegistrationAuthorities NameRegistrationAuthorities
 *                                                         OPTIONAL }
 *         (WITH COMPONENTS {..., semanticsIdentifier PRESENT}|
 *          WITH COMPONENTS {..., nameRegistrationAuthorities PRESENT})
 *
 *     NameRegistrationAuthorities ::=  SEQUENCE SIZE (1..MAX) OF
 *         GeneralName
 * </pre>
 */
public class SemanticsInformation
    extends ASN1Object
{
    private ASN1ObjectIdentifier semanticsIdentifier;
    private GeneralName[] nameRegistrationAuthorities;
    
    public static SemanticsInformation getInstance(Object obj)
    {
        if (obj instanceof SemanticsInformation)
        {
            return (SemanticsInformation)obj;
        }

        if (obj != null)
        {
            return new SemanticsInformation(ASN1Sequence.getInstance(obj));            
        }
        
        return null;
    }
        
    private SemanticsInformation(ASN1Sequence seq)
    {
        Enumeration e = seq.getObjects();
        if (seq.size() < 1)
        {
             throw new IllegalArgumentException("no objects in SemanticsInformation");
        }
        
        Object object = e.nextElement();
        if (object instanceof ASN1ObjectIdentifier)
        {
            semanticsIdentifier = ASN1ObjectIdentifier.getInstance(object);
            if (e.hasMoreElements())
            {
                object = e.nextElement();
            }
            else
            {
                object = null;
            }
        }
        
        if (object != null)
        {
            ASN1Sequence generalNameSeq = ASN1Sequence.getInstance(object);
            nameRegistrationAuthorities = new GeneralName[generalNameSeq.size()];
            for (int i= 0; i < generalNameSeq.size(); i++)
            {
                nameRegistrationAuthorities[i] = GeneralName.getInstance(generalNameSeq.getObjectAt(i));
            } 
        }
    }
        
    public SemanticsInformation(
        ASN1ObjectIdentifier semanticsIdentifier,
        GeneralName[] generalNames)
    {
        this.semanticsIdentifier = semanticsIdentifier;
        this.nameRegistrationAuthorities = cloneNames(generalNames);
    }

    public SemanticsInformation(ASN1ObjectIdentifier semanticsIdentifier)
    {
        this.semanticsIdentifier = semanticsIdentifier;
        this.nameRegistrationAuthorities = null;
    }

    public SemanticsInformation(GeneralName[] generalNames)
    {
        this.semanticsIdentifier = null;
        this.nameRegistrationAuthorities = cloneNames(generalNames);
    }        
    
    public ASN1ObjectIdentifier getSemanticsIdentifier()
    {
        return semanticsIdentifier;
    }
        
    public GeneralName[] getNameRegistrationAuthorities()
    {
        return cloneNames(nameRegistrationAuthorities);
    } 
    
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector seq = new ASN1EncodableVector(2);
        
        if (this.semanticsIdentifier != null)
        {
            seq.add(semanticsIdentifier);
        }
        if (this.nameRegistrationAuthorities != null)
        {
            seq.add(new DERSequence(nameRegistrationAuthorities));
        }            

        return new DERSequence(seq);
    }

    private static GeneralName[] cloneNames(GeneralName[] names)
    {
        if (names != null)
        {
            GeneralName[] tmp = new GeneralName[names.length];

            System.arraycopy(names, 0, tmp, 0, names.length);

            return tmp;
        }
        return null;
    }
}
