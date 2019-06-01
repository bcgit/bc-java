package org.bouncycastle.jce.provider;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.NameConstraintValidatorException;

public class PKIXNameConstraintValidator
{
    org.bouncycastle.asn1.x509.PKIXNameConstraintValidator validator = new org.bouncycastle.asn1.x509.PKIXNameConstraintValidator();

    public PKIXNameConstraintValidator()
    {
    }

    public int hashCode()
    {
        return validator.hashCode();
    }

    public boolean equals(Object o)
    {
        if (!(o instanceof PKIXNameConstraintValidator))
        {
            return false;
        }
        PKIXNameConstraintValidator constraintValidator = (PKIXNameConstraintValidator)o;
        return this.validator.equals(constraintValidator.validator);
    }

    public void checkPermittedDN(ASN1Sequence dns)
        throws PKIXNameConstraintValidatorException
    {
        try
        {
            this.validator.checkPermittedDN(X500Name.getInstance(dns));
        }
        catch (NameConstraintValidatorException e)
        {
            throw new PKIXNameConstraintValidatorException(e.getMessage(), e);
        }
    }

    public void checkExcludedDN(ASN1Sequence dns)
        throws PKIXNameConstraintValidatorException
    {
        try
        {
            this.validator.checkExcludedDN(X500Name.getInstance(dns));
        }
        catch (NameConstraintValidatorException e)
        {
            throw new PKIXNameConstraintValidatorException(e.getMessage(), e);
        }
    }

    /**
     * Checks if the given GeneralName is in the permitted set.
     *
     * @param name The GeneralName
     * @throws PKIXNameConstraintValidatorException
     *          If the <code>name</code>
     */
    public void checkPermitted(GeneralName name)
        throws PKIXNameConstraintValidatorException
    {
        try
        {
            validator.checkPermitted(name);
        }
        catch (NameConstraintValidatorException e)
        {
            throw new PKIXNameConstraintValidatorException(e.getMessage(), e);
        }
    }

    /**
     * Check if the given GeneralName is contained in the excluded set.
     *
     * @param name The GeneralName.
     * @throws PKIXNameConstraintValidatorException
     *          If the <code>name</code> is
     *          excluded.
     */
    public void checkExcluded(GeneralName name)
        throws PKIXNameConstraintValidatorException
    {
        try
        {
            validator.checkExcluded(name);
        }
        catch (NameConstraintValidatorException e)
        {
            throw new PKIXNameConstraintValidatorException(e.getMessage(), e);
        }
    }

    public void intersectPermittedSubtree(GeneralSubtree permitted)
    {
        validator.intersectPermittedSubtree(permitted);
    }

    /**
     * Updates the permitted set of these name constraints with the intersection
     * with the given subtree.
     *
     * @param permitted The permitted subtrees
     */

    public void intersectPermittedSubtree(GeneralSubtree[] permitted)
    {
        validator.intersectPermittedSubtree(permitted);
    }

    public void intersectEmptyPermittedSubtree(int nameType)
    {
        validator.intersectEmptyPermittedSubtree(nameType);
    }
    
    /**                                                           
     * Adds a subtree to the excluded set of these name constraints.
     *
     * @param subtree A subtree with an excluded GeneralName.
     */
    public void addExcludedSubtree(GeneralSubtree subtree)
    {
        validator.addExcludedSubtree(subtree);
    }

    public String toString()
    {
        return validator.toString();
    }
}
