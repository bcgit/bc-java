package org.bouncycastle.jce.provider;

import java.security.cert.PolicyNode;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

public class PKIXPolicyNode
    implements PolicyNode
{
    protected List       children;
    protected int        depth;
    protected Set        expectedPolicies;
    protected PolicyNode parent;
    protected Set        policyQualifiers;
    protected String     validPolicy;
    protected boolean    critical;
    
    /*  
     *  
     *  CONSTRUCTORS
     *  
     */ 
    
    public PKIXPolicyNode(
        List       _children,
        int        _depth,
        Set        _expectedPolicies,
        PolicyNode _parent,
        Set        _policyQualifiers,
        String     _validPolicy,
        boolean    _critical)
    {
        children         = _children;
        depth            = _depth;
        expectedPolicies = _expectedPolicies;
        parent           = _parent;
        policyQualifiers = _policyQualifiers;
        validPolicy      = _validPolicy;
        critical         = _critical;
    }
    
    public void addChild(
        PKIXPolicyNode _child)
    {
        children.add(_child);
        _child.setParent(this);
    }
    
    public Iterator getChildren()
    {
        return children.iterator();
    }

    public int getDepth()
    {
        return depth;
    }

    public Set getExpectedPolicies()
    {
        return expectedPolicies;
    }

    public PolicyNode getParent()
    {
        return parent;
    }

    public Set getPolicyQualifiers()
    {
        return policyQualifiers;
    }

    public String getValidPolicy()
    {
        return validPolicy;
    }

    public boolean hasChildren()
    {
        return !children.isEmpty();
    }

    public boolean isCritical()
    {
        return critical;
    }
    
    public void removeChild(PKIXPolicyNode _child)
    {
        children.remove(_child);
    }
    
    public void setCritical(boolean _critical)
    {
        critical = _critical;
    }

    public void setExpectedPolicies(Set expectedPolicies)
    {
        this.expectedPolicies = expectedPolicies;
    }

    public void setParent(PKIXPolicyNode _parent)
    {
        parent = _parent;
    }
    
    public String toString()
    {
        return toString("");
    }
    
    public String toString(String _indent)
    {
        StringBuffer _buf = new StringBuffer();
        _buf.append(_indent);
        _buf.append(validPolicy);
        _buf.append(" {\n");
        
        for(int i = 0; i < children.size(); i++)
        {
            _buf.append(((PKIXPolicyNode)children.get(i)).toString(_indent + "    "));
        }
        
        _buf.append(_indent);
        _buf.append("}\n");
        return _buf.toString();
    }

    // TODO[api] Maybe remove this, the 'clone' loses its parent
    public Object clone()
    {
        return copy();
    }

    public PKIXPolicyNode copy()
    {
        Set _expectedPolicies = new HashSet();
        Iterator _iter = expectedPolicies.iterator();
        while (_iter.hasNext())
        {
            _expectedPolicies.add(_iter.next());
        }

        Set _policyQualifiers = new HashSet();
        _iter = policyQualifiers.iterator();
        while (_iter.hasNext())
        {
            _policyQualifiers.add(_iter.next());
        }

        PKIXPolicyNode copy = new PKIXPolicyNode(new ArrayList(), depth, _expectedPolicies, null, _policyQualifiers,
            validPolicy, critical);

        _iter = children.iterator();
        while (_iter.hasNext())
        {
            PKIXPolicyNode child = (PKIXPolicyNode)_iter.next();
            copy.addChild(child.copy());
        }

        return copy;
    }
}
