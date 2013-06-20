package org.bouncycastle.asn1;

public class ASN1ObjectIdentifier
    extends DERObjectIdentifier
{
    public ASN1ObjectIdentifier(String identifier)
    {
        super(identifier);
    }

    ASN1ObjectIdentifier(byte[] bytes)
    {
        super(bytes);
    }

    /**
     * Return an OID that creates a branch under the current one.
     *
     * @param branchID node numbers for the new branch.
     * @return the OID for the new created branch.
     */
    ASN1ObjectIdentifier(ASN1ObjectIdentifier oid, String branch)
    {
        super(oid, branch);
    }

    /**
     * Return an OID that creates a branch under the current one.
     *
     * @param branchID node numbers for the new branch.
     * @return the OID for the new created branch.
     */
    ASN1ObjectIdentifier(ASN1ObjectIdentifier oid, long branch)
    {
        super(oid, branch);
    }

    /**
     * Return an OID that creates a branch under the current one.
     *
     * @param branchID node numbers for the new branch.
     * @return the OID for the new created branch.
     */
    ASN1ObjectIdentifier(ASN1ObjectIdentifier oid, long branch1, long branch2)
    {
        super(oid, branch1, branch2);
    }

    /**
     * Return an OID that creates a branch under the current one.
     *
     * @param branchID node numbers for the new branch.
     * @return the OID for the new created branch.
     */
    public ASN1ObjectIdentifier branch(String branchID)
    {
        return new ASN1ObjectIdentifier(this, branchID);
    }

    /**
     * Return an OID that creates a branch under the current one.
     * <p>
     * The extending value must be positive (0..INT_MAX)
     *
     * @param branchID node numbers for the new branch.
     * @return the OID for the new created branch.
     */
    public ASN1ObjectIdentifier branch(int branchID)
    {
        return new ASN1ObjectIdentifier(this, branchID);
    }

    /**
     * Return an OID that creates a branch under the current one.
     * <p>
     * The extending value must be positive (0..LONG_MAX)
     *
     * @param branchID node numbers for the new branch.
     * @return the OID for the new created branch.
     */
    public ASN1ObjectIdentifier branch(long branchID)
    {
        return new ASN1ObjectIdentifier(this, branchID);
    }

    /**
     * Return an OID that creates a branch under the current one.
     * <p>
     * The extending values must be positive (0..INT_MAX)
     *
     * @param branchID1 node numbers for the new branch.
     * @param branchID2 node numbers for the new branch, 2nd level
     * @return the OID for the new created branch.
     */
    public ASN1ObjectIdentifier branch(int branchID1, int branchID2)
    {
        return new ASN1ObjectIdentifier(this, branchID1, branchID2);
    }

    /**
     * Return an OID that creates a branch under the current one.
     * <p>
     * The extending values must be positive (0..LONG_MAX)
     *
     * @param branchID1 node numbers for the new branch.
     * @param branchID2 node numbers for the new branch, 2nd level
     * @return the OID for the new created branch.
     */
    public ASN1ObjectIdentifier branch(long branchID1, long branchID2)
    {
        return new ASN1ObjectIdentifier(this, branchID1, branchID2);
    }


    /**
     * Return  true if this oid is an extension of the passed in branch, stem.
     * @param stem the arc or branch that is a possible parent.
     * @return true if the branch is on the passed in stem, false otherwise.
     */
    public boolean on(ASN1ObjectIdentifier stem)
    {
        byte[] body     = super.getBody();
        byte[] stembody = stem.getBody();

        // Body under study is equal in length or longer than the stem -> can't be under the stem
        if (stembody.length >= body.length) return false;

        // Search for variable length encoding value end bytes, should be TRUE at the end of the stem.
        boolean numberEndSeen = false;
        for (int i = 0; i < stembody.length; ++i) {
            numberEndSeen = (stembody[i] >= 0);
            // If bytes don't match during the stem, the result is false.
            if (stembody[i] != body[i]) return false;
        }
        if (!numberEndSeen) {
            // Actually this should NOT happen with well formatted OID.
            return false;
        }
        // Data at the tail does not interest us.
        return true;
    }
}
