package org.bouncycastle.oer.its.ieee1609dot2;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
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
    private final List<PsidGroupPermissions> psidGroupPermissions;

    public SequenceOfPsidGroupPermissions(List<PsidGroupPermissions> groupPermissions)
    {
        this.psidGroupPermissions = Collections.unmodifiableList(groupPermissions);
    }

    private SequenceOfPsidGroupPermissions(ASN1Sequence seq)
    {
        ArrayList<PsidGroupPermissions> l = new ArrayList<PsidGroupPermissions>();
        for (Iterator<ASN1Encodable> it = seq.iterator(); it.hasNext(); )
        {
            l.add(PsidGroupPermissions.getInstance(it.next()));
        }
        this.psidGroupPermissions = Collections.unmodifiableList(l);
    }

    public static SequenceOfPsidGroupPermissions getInstance(Object obj)
    {
        if (obj instanceof SequenceOfPsidGroupPermissions)
        {
            return (SequenceOfPsidGroupPermissions)obj;
        }

        if (obj != null)
        {
            return new SequenceOfPsidGroupPermissions(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public List<PsidGroupPermissions> getPsidGroupPermissions()
    {
        return psidGroupPermissions;
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(psidGroupPermissions.toArray(new PsidGroupPermissions[0]));
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