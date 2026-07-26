package org.bouncycastle.jce.provider;

// NOTE: jdk1.3 overlay. java.security.cert.PolicyNode is part of the CertPath API added in Java
// 1.4 and is absent on JDK 1.3; the jdk1.3 preprocessor does not auto-rewrite this class name (see
// docs/jdk13-certpath-overlay-sync-plan.md), so this overlay uses the org.bouncycastle.jce.cert
// backport instead, matching the jdk1.3 overlay of the org.bouncycastle.jcajce.PKIXPolicyNode
// superclass it retains binary/source compatibility for.
import org.bouncycastle.jce.cert.PolicyNode;
import java.util.List;
import java.util.Set;

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
