package org.bouncycastle.jcajce;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.PolicyQualifierInfo;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;

/**
 * Shared RFC 5280 sec. 6.1.3/6.1.4 valid-policy-tree manipulation, single-sourced from the two
 * cert-path stacks that used to carry duplicate copies (the provider's cert path validator/reviewer
 * and the PKIX revocation checker's reviewer). These are the error-reporting-free mechanics of the
 * policy algorithm - each caller keeps its own driver loop and localized diagnostics and calls in
 * here for the tree operations, which raise a plain {@link CertPathValidatorException} the caller
 * re-wraps into its own exception/message type.
 */
public class PKIXPolicyTreeUtil
{
    public static final String ANY_POLICY = "2.5.29.32.0";

    private static final String CERTIFICATE_POLICIES = Extension.certificatePolicies.getId();

    public static PKIXPolicyNode removePolicyNode(PKIXPolicyNode validPolicyTree, List[] policyNodes,
        PKIXPolicyNode _node)
    {
        PKIXPolicyNode _parent = (PKIXPolicyNode)_node.getParent();

        if (validPolicyTree == null)
        {
            return null;
        }

        if (_parent == null)
        {
            for (int j = 0; j < policyNodes.length; j++)
            {
                policyNodes[j] = new ArrayList();
            }

            return null;
        }
        else
        {
            _parent.removeChild(_node);
            removePolicyNodeRecurse(policyNodes, _node);

            return validPolicyTree;
        }
    }

    private static void removePolicyNodeRecurse(List[] policyNodes, PKIXPolicyNode _node)
    {
        policyNodes[_node.getDepth()].remove(_node);

        if (_node.hasChildren())
        {
            Iterator _iter = _node.getChildren();
            while (_iter.hasNext())
            {
                PKIXPolicyNode _child = (PKIXPolicyNode)_iter.next();
                removePolicyNodeRecurse(policyNodes, _child);
            }
        }
    }

    public static void prepareNextCertB1(int i, List[] policyNodes, String id_p, Map m_idp,
        X509Certificate cert)
        throws CertPathValidatorException
    {
        boolean idp_found = false;
        Iterator nodes_i = policyNodes[i].iterator();
        while (nodes_i.hasNext())
        {
            PKIXPolicyNode node = (PKIXPolicyNode)nodes_i.next();
            if (node.getValidPolicy().equals(id_p))
            {
                idp_found = true;
                node.setExpectedPolicies((Set)m_idp.get(id_p));
                break;
            }
        }

        if (!idp_found)
        {
            nodes_i = policyNodes[i].iterator();
            while (nodes_i.hasNext())
            {
                PKIXPolicyNode node = (PKIXPolicyNode)nodes_i.next();
                if (ANY_POLICY.equals(node.getValidPolicy()))
                {
                    Set pq = null;
                    ASN1Sequence policies;
                    try
                    {
                        policies = DERSequence.getInstance(getExtensionValue(cert, CERTIFICATE_POLICIES));
                    }
                    catch (Exception e)
                    {
                        throw new CertPathValidatorException("Certificate policies cannot be decoded.", e);
                    }
                    Enumeration e = policies.getObjects();
                    while (e.hasMoreElements())
                    {
                        PolicyInformation pinfo;
                        try
                        {
                            pinfo = PolicyInformation.getInstance(e.nextElement());
                        }
                        catch (Exception ex)
                        {
                            throw new CertPathValidatorException("Policy information cannot be decoded.", ex);
                        }
                        if (ANY_POLICY.equals(pinfo.getPolicyIdentifier().getId()))
                        {
                            try
                            {
                                pq = getQualifierSet(pinfo.getPolicyQualifiers());
                            }
                            catch (CertPathValidatorException ex)
                            {
                                throw new CertPathValidatorException(
                                    "Policy qualifier info set could not be built.", ex);
                            }
                            break;
                        }
                    }
                    boolean ci = false;
                    if (cert.getCriticalExtensionOIDs() != null)
                    {
                        ci = cert.getCriticalExtensionOIDs().contains(CERTIFICATE_POLICIES);
                    }

                    PKIXPolicyNode p_node = (PKIXPolicyNode)node.getParent();
                    if (ANY_POLICY.equals(p_node.getValidPolicy()))
                    {
                        PKIXPolicyNode c_node = new PKIXPolicyNode(new ArrayList(), i,
                            (Set)m_idp.get(id_p), p_node, pq, id_p, ci);
                        p_node.addChild(c_node);
                        policyNodes[i].add(c_node);
                    }
                    break;
                }
            }
        }
    }

    public static PKIXPolicyNode prepareNextCertB2(int i, List[] policyNodes, String id_p,
        PKIXPolicyNode validPolicyTree)
    {
        Iterator nodes_i = policyNodes[i].iterator();
        while (nodes_i.hasNext())
        {
            PKIXPolicyNode node = (PKIXPolicyNode)nodes_i.next();
            if (node.getValidPolicy().equals(id_p))
            {
                PKIXPolicyNode p_node = (PKIXPolicyNode)node.getParent();
                p_node.removeChild(node);
                nodes_i.remove();
                for (int k = (i - 1); k >= 0; k--)
                {
                    List nodes = policyNodes[k];
                    for (int l = 0; l < nodes.size(); l++)
                    {
                        PKIXPolicyNode node2 = (PKIXPolicyNode)nodes.get(l);
                        if (!node2.hasChildren())
                        {
                            validPolicyTree = removePolicyNode(validPolicyTree, policyNodes, node2);
                            if (validPolicyTree == null)
                            {
                                break;
                            }
                        }
                    }
                }
            }
        }
        return validPolicyTree;
    }

    public static boolean processCertD1i(int index, List[] policyNodes, ASN1ObjectIdentifier pOid, Set pq)
    {
        List policyNodeVec = policyNodes[index - 1];

        for (int j = 0; j < policyNodeVec.size(); j++)
        {
            PKIXPolicyNode node = (PKIXPolicyNode)policyNodeVec.get(j);
            Set expectedPolicies = node.getExpectedPolicies();

            if (expectedPolicies.contains(pOid.getId()))
            {
                Set childExpectedPolicies = new HashSet();
                childExpectedPolicies.add(pOid.getId());

                PKIXPolicyNode child = new PKIXPolicyNode(new ArrayList(), index,
                    childExpectedPolicies, node, pq, pOid.getId(), false);
                node.addChild(child);
                policyNodes[index].add(child);

                return true;
            }
        }

        return false;
    }

    public static void processCertD1ii(int index, List[] policyNodes, ASN1ObjectIdentifier _poid, Set _pq)
    {
        List policyNodeVec = policyNodes[index - 1];

        for (int j = 0; j < policyNodeVec.size(); j++)
        {
            PKIXPolicyNode _node = (PKIXPolicyNode)policyNodeVec.get(j);

            if (ANY_POLICY.equals(_node.getValidPolicy()))
            {
                Set _childExpectedPolicies = new HashSet();
                _childExpectedPolicies.add(_poid.getId());

                PKIXPolicyNode _child = new PKIXPolicyNode(new ArrayList(), index,
                    _childExpectedPolicies, _node, _pq, _poid.getId(), false);
                _node.addChild(_child);
                policyNodes[index].add(_child);
                return;
            }
        }
    }

    public static Set getQualifierSet(ASN1Sequence qualifiers)
        throws CertPathValidatorException
    {
        Set pq = new HashSet();

        if (qualifiers == null)
        {
            return pq;
        }

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ASN1OutputStream aOut = ASN1OutputStream.create(bOut);

        Enumeration e = qualifiers.getObjects();

        while (e.hasMoreElements())
        {
            try
            {
                aOut.writeObject((ASN1Encodable)e.nextElement());

                pq.add(new PolicyQualifierInfo(bOut.toByteArray()));
            }
            catch (IOException ex)
            {
                throw new CertPathValidatorException("Policy qualifier info cannot be decoded.", ex);
            }

            bOut.reset();
        }

        return pq;
    }

    private static ASN1Primitive getExtensionValue(java.security.cert.X509Extension ext, String oid)
        throws CertPathValidatorException
    {
        byte[] bytes = ext.getExtensionValue(oid);
        if (bytes == null)
        {
            return null;
        }

        try
        {
            ASN1InputStream aIn = new ASN1InputStream(bytes);
            ASN1OctetString octs = (ASN1OctetString)aIn.readObject();

            aIn = new ASN1InputStream(octs.getOctets());
            return aIn.readObject();
        }
        catch (Exception e)
        {
            throw new CertPathValidatorException("exception processing extension " + oid, e);
        }
    }
}
