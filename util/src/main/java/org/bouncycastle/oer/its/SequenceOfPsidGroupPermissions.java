package org.bouncycastle.oer.its;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * <pre>
 *     SEQUENCE OF PsidGroupPermissions
 * </pre>
 */
public class SequenceOfPsidGroupPermissions
    extends ASN1Object
{
    private final List<PsidGroupPermissions> groupPermissions;

    public SequenceOfPsidGroupPermissions(List<PsidGroupPermissions> groupPermissions)
    {
        this.groupPermissions = Collections.unmodifiableList(groupPermissions);
    }

    public static SequenceOfPsidGroupPermissions getInstance(Object obj)
    {
        if (obj instanceof SequenceOfPsidGroupPermissions)
        {
            return (SequenceOfPsidGroupPermissions)obj;
        }

        ASN1Sequence sequence = ASN1Sequence.getInstance(obj);
        ArrayList<PsidGroupPermissions> psidGroupPermissions = new ArrayList<PsidGroupPermissions>();
        Enumeration e = sequence.getObjects();
        while (e.hasMoreElements())
        {
            psidGroupPermissions.add(PsidGroupPermissions.getInstance(e.nextElement()));
        }

        return new Builder().setGroupPermissions(psidGroupPermissions).createSequenceOfPsidGroupPermissions();

    }

    public static Builder builder()
    {
        return new Builder();
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(groupPermissions.toArray(new PsidGroupPermissions[0]));
    }

    public static class Builder
    {

        private final List<PsidGroupPermissions> groupPermissions = new ArrayList<PsidGroupPermissions>();

        public Builder setGroupPermissions(List<PsidGroupPermissions> groupPermissions)
        {
            this.groupPermissions.addAll(groupPermissions);
            return this;
        }

        public Builder addGroupPermission(PsidGroupPermissions... permissions)
        {
            this.groupPermissions.addAll(Arrays.asList(permissions));
            return this;
        }

        public SequenceOfPsidGroupPermissions createSequenceOfPsidGroupPermissions()
        {
            return new SequenceOfPsidGroupPermissions(groupPermissions);
        }
    }

}