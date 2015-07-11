package org.bouncycastle.asn1.x509;

public interface NameConstraintValidator
{
    void checkPermitted(GeneralName name)
        throws NameConstraintValidatorException;

    void checkExcluded(GeneralName name)
            throws NameConstraintValidatorException;

    void intersectPermittedSubtree(GeneralSubtree permitted);

    void intersectPermittedSubtree(GeneralSubtree[] permitted);

    void intersectEmptyPermittedSubtree(int nameType);

    void addExcludedSubtree(GeneralSubtree subtree);
}
