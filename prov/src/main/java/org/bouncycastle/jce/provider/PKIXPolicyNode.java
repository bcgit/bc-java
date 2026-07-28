package org.bouncycastle.jce.provider;

import java.security.cert.PolicyNode;
import java.util.List;
import java.util.Set;

/**
 * Retained for binary/source compatibility. The valid-policy-tree node type is now
 * {@link org.bouncycastle.jcajce.PKIXPolicyNode}, which the cert-path code uses directly;
 * this subclass preserves the historical {@code org.bouncycastle.jce.provider} name.
 */
public class PKIXPolicyNode
    extends org.bouncycastle.jcajce.PKIXPolicyNode
{
    public PKIXPolicyNode(
        List       _children,
        int        _depth,
        Set        _expectedPolicies,
        PolicyNode _parent,
        Set        _policyQualifiers,
        String     _validPolicy,
        boolean    _critical)
    {
        super(_children, _depth, _expectedPolicies, _parent, _policyQualifiers, _validPolicy, _critical);
    }
}
