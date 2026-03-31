package org.bouncycastle.asn1.x509;

import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class PKIXNameConstraintValidator
    implements NameConstraintValidator
{
    private Set excludedSubtreesDN = new HashSet();

    private Set excludedSubtreesDNS = new HashSet();

    private Set excludedSubtreesEmail = new HashSet();

    private Set excludedSubtreesURI = new HashSet();

    private Set excludedSubtreesIP = new HashSet();

    private Set excludedSubtreesOtherName = new HashSet();

    private Set permittedSubtreesDN;

    private Set permittedSubtreesDNS;

    private Set permittedSubtreesEmail;

    private Set permittedSubtreesURI;

    private Set permittedSubtreesIP;

    private Set permittedSubtreesOtherName;

    public PKIXNameConstraintValidator()
    {
    }

    /**
     * Checks if the given GeneralName is in the permitted set.
     *
     * @param name The GeneralName
     * @throws NameConstraintValidatorException If the <code>name</code>
     */
    public void checkPermitted(GeneralName name)
        throws NameConstraintValidatorException
    {
        ASN1Encodable nameValue = name.getName();

        switch (name.getTagNo())
        {
        case GeneralName.otherName:
            checkPermittedOtherName(permittedSubtreesOtherName, OtherName.getInstance(nameValue));
            break;
        case GeneralName.rfc822Name:
            checkPermittedEmail(extractNameAsString(nameValue));
            break;
        case GeneralName.dNSName:
            checkPermittedDNS(permittedSubtreesDNS, extractNameAsString(nameValue));
            break;
        case GeneralName.directoryName:
            checkPermittedDN(X500Name.getInstance(nameValue));
            break;
        case GeneralName.uniformResourceIdentifier:
            checkPermittedURI(permittedSubtreesURI, extractNameAsString(nameValue));
            break;
        case GeneralName.iPAddress:
            checkPermittedIP(permittedSubtreesIP, ASN1OctetString.getInstance(nameValue).getOctets());
            break;
        default:
            // other tags to be ignored.
        }
    }

    /**
     * Check if the given GeneralName is contained in the excluded set.
     *
     * @param name The GeneralName.
     * @throws NameConstraintValidatorException If the <code>name</code> is
     * excluded.
     */
    public void checkExcluded(GeneralName name)
        throws NameConstraintValidatorException
    {
        ASN1Encodable nameValue = name.getName();

        switch (name.getTagNo())
        {
        case GeneralName.otherName:
            checkExcludedOtherName(excludedSubtreesOtherName, OtherName.getInstance(nameValue));
            break;
        case GeneralName.rfc822Name:
            checkExcludedEmail(extractNameAsString(nameValue));
            break;
        case GeneralName.dNSName:
            checkExcludedDNS(excludedSubtreesDNS, extractNameAsString(nameValue));
            break;
        case GeneralName.directoryName:
            checkExcludedDN(X500Name.getInstance(nameValue));
            break;
        case GeneralName.uniformResourceIdentifier:
            checkExcludedURI(excludedSubtreesURI, extractNameAsString(nameValue));
            break;
        case GeneralName.iPAddress:
            checkExcludedIP(excludedSubtreesIP, ASN1OctetString.getInstance(nameValue).getOctets());
            break;
        default:
            // other tags to be ignored.
        }
    }

    public void intersectPermittedSubtree(GeneralSubtree permitted)
    {
        intersectPermittedSubtree(new GeneralSubtree[]{permitted});
    }

    /**
     * Updates the permitted set of these name constraints with the intersection
     * with the given subtree.
     *
     * @param permitted The permitted subtrees
     */
    public void intersectPermittedSubtree(GeneralSubtree[] permitted)
    {
        Map subtreesMap = new HashMap();

        // group in sets in a map ordered by tag no.
        for (int i = 0; i != permitted.length; i++)
        {
            GeneralSubtree subtree = permitted[i];
            Integer tagNo = Integers.valueOf(subtree.getBase().getTagNo());

            Set subtrees = (Set)subtreesMap.get(tagNo);
            if (subtrees == null)
            {
                subtrees = new HashSet();
                subtreesMap.put(tagNo, subtrees);
            }

            subtrees.add(subtree);
        }

        for (Iterator it = subtreesMap.entrySet().iterator(); it.hasNext();)
        {
            Map.Entry entry = (Map.Entry)it.next();

            // go through all subtree groups
            int nameType = ((Integer)entry.getKey()).intValue();
            Set subtrees = (Set)entry.getValue();

            switch (nameType)
            {
            case GeneralName.otherName:
                permittedSubtreesOtherName = intersectOtherName(permittedSubtreesOtherName, subtrees);
                break;
            case GeneralName.rfc822Name:
                permittedSubtreesEmail = intersectEmail(permittedSubtreesEmail, subtrees);
                break;
            case GeneralName.dNSName:
                permittedSubtreesDNS = intersectDNS(permittedSubtreesDNS, subtrees);
                break;
            case GeneralName.directoryName:
                permittedSubtreesDN = intersectDN(permittedSubtreesDN, subtrees);
                break;
            case GeneralName.uniformResourceIdentifier:
                permittedSubtreesURI = intersectURI(permittedSubtreesURI, subtrees);
                break;
            case GeneralName.iPAddress:
                permittedSubtreesIP = intersectIP(permittedSubtreesIP, subtrees);
                break;
            default:
                throw new IllegalStateException("Unknown tag encountered: " + nameType);
            }
        }
    }

    public void intersectEmptyPermittedSubtree(int nameType)
    {
        switch (nameType)
        {
        case GeneralName.otherName:
            permittedSubtreesOtherName = new HashSet();
            break;
        case GeneralName.rfc822Name:
            permittedSubtreesEmail = new HashSet();
            break;
        case GeneralName.dNSName:
            permittedSubtreesDNS = new HashSet();
            break;
        case GeneralName.directoryName:
            permittedSubtreesDN = new HashSet();
            break;
        case GeneralName.uniformResourceIdentifier:
            permittedSubtreesURI = new HashSet();
            break;
        case GeneralName.iPAddress:
            permittedSubtreesIP = new HashSet();
            break;
        default:
            throw new IllegalStateException("Unknown tag encountered: " + nameType);
        }
    }

    /**
     * Adds a subtree to the excluded set of these name constraints.
     *
     * @param subtree A subtree with an excluded GeneralName.
     */
    public void addExcludedSubtree(GeneralSubtree subtree)
    {
        GeneralName subtreeBase = subtree.getBase();
        ASN1Encodable nameValue = subtreeBase.getName();

        switch (subtreeBase.getTagNo())
        {
        case GeneralName.otherName:
            excludedSubtreesOtherName = unionOtherName(excludedSubtreesOtherName, OtherName.getInstance(nameValue));
            break;
        case GeneralName.rfc822Name:
            excludedSubtreesEmail = unionEmail(excludedSubtreesEmail, extractNameAsString(nameValue));
            break;
        case GeneralName.dNSName:
            excludedSubtreesDNS = unionDNS(excludedSubtreesDNS, extractNameAsString(nameValue));
            break;
        case GeneralName.directoryName:
            excludedSubtreesDN = unionDN(excludedSubtreesDN, ASN1Sequence.getInstance(nameValue));
            break;
        case GeneralName.uniformResourceIdentifier:
            excludedSubtreesURI = unionURI(excludedSubtreesURI, extractNameAsString(nameValue));
            break;
        case GeneralName.iPAddress:
            excludedSubtreesIP = unionIP(excludedSubtreesIP, ASN1OctetString.getInstance(nameValue).getOctets());
            break;
        default:
            throw new IllegalStateException("Unknown tag encountered: " + subtreeBase.getTagNo());
        }
    }

    public int hashCode()
    {
        return hashCollection(excludedSubtreesDN)
            + hashCollection(excludedSubtreesDNS)
            + hashCollection(excludedSubtreesEmail)
            + hashCollection(excludedSubtreesIP)
            + hashCollection(excludedSubtreesURI)
            + hashCollection(excludedSubtreesOtherName)
            + hashCollection(permittedSubtreesDN)
            + hashCollection(permittedSubtreesDNS)
            + hashCollection(permittedSubtreesEmail)
            + hashCollection(permittedSubtreesIP)
            + hashCollection(permittedSubtreesURI)
            + hashCollection(permittedSubtreesOtherName);
    }

    public boolean equals(Object o)
    {
        if (!(o instanceof PKIXNameConstraintValidator))
        {
            return false;
        }
        PKIXNameConstraintValidator constraintValidator = (PKIXNameConstraintValidator)o;
        return collectionsAreEqual(constraintValidator.excludedSubtreesDN, excludedSubtreesDN)
            && collectionsAreEqual(constraintValidator.excludedSubtreesDNS, excludedSubtreesDNS)
            && collectionsAreEqual(constraintValidator.excludedSubtreesEmail, excludedSubtreesEmail)
            && collectionsAreEqual(constraintValidator.excludedSubtreesIP, excludedSubtreesIP)
            && collectionsAreEqual(constraintValidator.excludedSubtreesURI, excludedSubtreesURI)
            && collectionsAreEqual(constraintValidator.excludedSubtreesOtherName, excludedSubtreesOtherName)
            && collectionsAreEqual(constraintValidator.permittedSubtreesDN, permittedSubtreesDN)
            && collectionsAreEqual(constraintValidator.permittedSubtreesDNS, permittedSubtreesDNS)
            && collectionsAreEqual(constraintValidator.permittedSubtreesEmail, permittedSubtreesEmail)
            && collectionsAreEqual(constraintValidator.permittedSubtreesIP, permittedSubtreesIP)
            && collectionsAreEqual(constraintValidator.permittedSubtreesURI, permittedSubtreesURI)
            && collectionsAreEqual(constraintValidator.permittedSubtreesOtherName, permittedSubtreesOtherName);
    }

    public void checkPermittedDN(X500Name dns)
        throws NameConstraintValidatorException
    {
        checkPermittedDN(permittedSubtreesDN, ASN1Sequence.getInstance(dns));
    }

    public void checkExcludedDN(X500Name dns)
        throws NameConstraintValidatorException
    {
        checkExcludedDN(excludedSubtreesDN, ASN1Sequence.getInstance(dns));
    }

    public void checkPermittedEmail(String email)
        throws NameConstraintValidatorException
    {
        checkPermittedEmail(permittedSubtreesEmail, email);
    }

    public void checkExcludedEmail(String email)
        throws NameConstraintValidatorException
    {
        checkExcludedEmail(excludedSubtreesEmail, email);
    }

    private static boolean withinDNSubtree(ASN1Sequence dns, ASN1Sequence subtree)
    {
        if (subtree.size() < 1 || subtree.size() > dns.size())
        {
            return false;
        }

        int start = 0;
        RDN subtreeRdnStart = RDN.getInstance(subtree.getObjectAt(0));
        for (int j = 0; j < dns.size(); j++)
        {
            start = j;
            RDN dnsRdn = RDN.getInstance(dns.getObjectAt(j));
            if (IETFUtils.rDNAreEqual(subtreeRdnStart, dnsRdn))
            {
                break;
            }
        }

        if (subtree.size() > dns.size() - start)
        {
            return false;
        }

        for (int j = 0; j < subtree.size(); j++)
        {
            // both subtree and dns are a ASN.1 Name and the elements are a RDN
            RDN subtreeRdn = RDN.getInstance(subtree.getObjectAt(j));
            RDN dnsRdn = RDN.getInstance(dns.getObjectAt(start + j));

            // check if types and values of all naming attributes are matching, other types which are not restricted are allowed, see https://tools.ietf.org/html/rfc5280#section-7.1
            if (subtreeRdn.size() == dnsRdn.size())
            {
                // Two relative distinguished names
                //   RDN1 and RDN2 match if they have the same number of naming attributes
                //   and for each naming attribute in RDN1 there is a matching naming attribute in RDN2.
                //   NOTE: this is checking the attributes in the same order, which might be not necessary, if this is a problem also IETFUtils.rDNAreEqual must be changed.
                // use new RFC 5280 comparison, NOTE: this is now different from with RFC 3280, where only binary comparison is used
                // obey RFC 5280 7.1
                // special treatment of serialNumber for GSMA SGP.22 RSP specification
                if (!subtreeRdn.getFirst().getType().equals(dnsRdn.getFirst().getType()))
                {
                    return false;
                }
                if (subtreeRdn.size() == 1 && subtreeRdn.getFirst().getType().equals(RFC4519Style.serialNumber))
                {
                    if (!dnsRdn.getFirst().getValue().toString().startsWith(subtreeRdn.getFirst().getValue().toString()))
                    {
                        return false;
                    }
                }
                else if (!IETFUtils.rDNAreEqual(subtreeRdn, dnsRdn))
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
        }

        return true;
    }

    private static void checkPermittedDN(Set permitted, ASN1Sequence dns)
        throws NameConstraintValidatorException
    {
        if (permitted != null
            && !(permitted.isEmpty() && dns.size() == 0)
            && !isDNConstrained(permitted, dns))
        {
            throw new NameConstraintValidatorException("Subject distinguished name is not from a permitted subtree");
        }
    }

    private static void checkExcludedDN(Set excluded, ASN1Sequence dns)
        throws NameConstraintValidatorException
    {
        if (isDNConstrained(excluded, dns))
        {
            throw new NameConstraintValidatorException("Subject distinguished name is from an excluded subtree");
        }
    }

    private static boolean isDNConstrained(Set constraints, ASN1Sequence dns)
    {
        Iterator it = constraints.iterator();
        while (it.hasNext())
        {
            ASN1Sequence subtree = (ASN1Sequence)it.next();
            if (withinDNSubtree(dns, subtree))
            {
                return true;
            }
        }

        return false;
    }

    private static Set intersectDN(Set permitted, Set dns)
    {
        Set intersect = new HashSet();
        for (Iterator it = dns.iterator(); it.hasNext();)
        {
            GeneralSubtree subtree = (GeneralSubtree)it.next();
            ASN1Sequence dn1 = ASN1Sequence.getInstance(subtree.getBase().getName());
            if (permitted == null)
            {
                if (dn1 != null)
                {
                    intersect.add(dn1);
                }
            }
            else
            {
                Iterator _iter = permitted.iterator();
                while (_iter.hasNext())
                {
                    ASN1Sequence dn2 = (ASN1Sequence)_iter.next();

                    if (withinDNSubtree(dn1, dn2))
                    {
                        intersect.add(dn1);
                    }
                    else if (withinDNSubtree(dn2, dn1))
                    {
                        intersect.add(dn2);
                    }
                }
            }
        }
        return intersect;
    }

    private static Set unionDN(Set excluded, ASN1Sequence dn)
    {
        if (excluded.isEmpty())
        {
            if (dn != null)
            {
                excluded.add(dn);
            }
            return excluded;
        }
        else
        {
            Set intersect = new HashSet();

            Iterator it = excluded.iterator();
            while (it.hasNext())
            {
                ASN1Sequence subtree = ASN1Sequence.getInstance(it.next());

                if (withinDNSubtree(dn, subtree))
                {
                    intersect.add(subtree);
                }
                else if (withinDNSubtree(subtree, dn))
                {
                    intersect.add(dn);
                }
                else
                {
                    intersect.add(subtree);
                    intersect.add(dn);
                }
            }

            return intersect;
        }
    }

    private static Set intersectOtherName(Set permitted, Set otherNames)
    {
        Set intersect = new HashSet();
        for (Iterator it = otherNames.iterator(); it.hasNext();)
        {
            GeneralSubtree subtree = (GeneralSubtree)it.next();
            OtherName otherName1 = OtherName.getInstance(subtree.getBase().getName());
            if (otherName1 == null)
            {
                continue;
            }

            if (permitted == null)
            {
                intersect.add(otherName1);
            }
            else
            {
                Iterator it2 = permitted.iterator();
                while (it2.hasNext())
                {
                    OtherName otherName2 = OtherName.getInstance(it2.next());

                    intersectOtherName(otherName1, otherName2, intersect);
                }
            }
        }
        return intersect;
    }

    private static void intersectOtherName(OtherName otName1, OtherName otName2, Set intersect)
    {
        if (otName1.equals(otName2))
        {
            intersect.add(otName1);
        }
    }

    private static Set unionOtherName(Set permitted, OtherName otherName)
    {
        Set union = permitted != null ? new HashSet(permitted) : new HashSet();

        union.add(otherName);

        return union;
    }

    private static Set intersectEmail(Set permitted, Set emails)
    {
        Set intersect = new HashSet();
        for (Iterator it = emails.iterator(); it.hasNext();)
        {
            String email = extractNameAsString((GeneralSubtree)it.next());

            if (permitted == null)
            {
                intersect.add(email);
            }
            else
            {
                Iterator it2 = permitted.iterator();
                while (it2.hasNext())
                {
                    String _permitted = (String)it2.next();

                    intersectEmail(email, _permitted, intersect);
                }
            }
        }
        return intersect;
    }

    private static Set unionEmail(Set excluded, String email)
    {
        if (excluded.isEmpty())
        {
            excluded.add(email);
            return excluded;
        }

        Set union = new HashSet();

        Iterator it = excluded.iterator();
        while (it.hasNext())
        {
            String _excluded = (String)it.next();

            unionEmail(_excluded, email, union);
        }

        return union;
    }

    /**
     * Returns the intersection of the permitted IP ranges in <code>permitted</code> with
     * <code>ips</code>.
     *
     * @param permitted A <code>Set</code> of permitted IP addresses with their subnet mask as byte
     * arrays.
     * @param ips The IP address with its subnet mask.
     * @return The <code>Set</code> of permitted IP ranges intersected with <code>ips</code>.
     */
    private static Set intersectIP(Set permitted, Set ips)
    {
        Set intersect = new HashSet();
        for (Iterator it = ips.iterator(); it.hasNext();)
        {
            GeneralSubtree subtree = (GeneralSubtree)it.next();
            byte[] ip = ASN1OctetString.getInstance(subtree.getBase().getName()).getOctets();
            if (permitted == null)
            {
                intersect.add(ip);
            }
            else
            {
                Iterator it2 = permitted.iterator();
                while (it2.hasNext())
                {
                    byte[] _permitted = (byte[])it2.next();

                    byte[] intersection = intersectIPRange(_permitted, ip);
                    if (intersection != null)
                    {
                        intersect.add(intersection);
                    }
                }
            }
        }
        return intersect;
    }

    /**
     * Returns the union of the excluded IP ranges in <code>excluded</code>
     * with <code>ip</code>.
     *
     * @param excluded A <code>Set</code> of excluded IP addresses with their
     *                 subnet mask as byte arrays.
     * @param ip       The IP address with its subnet mask.
     * @return The <code>Set</code> of excluded IP ranges unified with
     * <code>ip</code> as byte arrays.
     */
    private static Set unionIP(Set excluded, byte[] ip)
    {
        if (excluded.isEmpty())
        {
            if (ip != null)
            {
                excluded.add(ip);
            }
            return excluded;
        }
        else
        {
            Set union = new HashSet();

            Iterator it = excluded.iterator();
            while (it.hasNext())
            {
                byte[] _excluded = (byte[])it.next();
                union.addAll(unionIPRange(_excluded, ip));
            }

            return union;
        }
    }

    /**
     * Calculates the union if two IP ranges.
     *
     * @param ipWithSubmask1 The first IP address with its subnet mask.
     * @param ipWithSubmask2 The second IP address with its subnet mask.
     * @return A <code>Set</code> with the union of both addresses.
     */
    private static Set unionIPRange(byte[] ipWithSubmask1, byte[] ipWithSubmask2)
    {
        Set set = new HashSet();

        // difficult, adding always all IPs is not wrong
        if (Arrays.areEqual(ipWithSubmask1, ipWithSubmask2))
        {
            set.add(ipWithSubmask1);
        }
        else
        {
            set.add(ipWithSubmask1);
            set.add(ipWithSubmask2);
        }
        return set;
    }

    /**
     * Calculates the intersection if two IP ranges.
     *
     * @param ipWithSubmask1 The first IP address with its subnet mask.
     * @param ipWithSubmask2 The second IP address with its subnet mask.
     * @return A single IP address with its subnet mask as a byte array, or null.
     */
    private static byte[] intersectIPRange(byte[] ipWithSubmask1, byte[] ipWithSubmask2)
    {
        // i.e. no intersection between IPv4 and IPv6 ranges
        if (ipWithSubmask1.length != ipWithSubmask2.length)
        {
            return null;
        }

        byte[][] temp = extractIPsAndSubnetMasks(ipWithSubmask1, ipWithSubmask2);
        byte ip1[] = temp[0];
        byte subnetmask1[] = temp[1];
        byte ip2[] = temp[2];
        byte subnetmask2[] = temp[3];

        byte minMax[][] = minMaxIPs(ip1, subnetmask1, ip2, subnetmask2);
        byte[] min1 = minMax[0];
        byte[] max1 = minMax[1];
        byte[] min2 = minMax[2];
        byte[] max2 = minMax[3];

        byte[] max = min(max1, max2);
        byte[] min = max(min1, min2);

        // minimum IP address can't be bigger than max
        if (compareTo(min, max) == 1)
        {
            return null;
        }

        // OR keeps all significant bits
        byte[] ip = or(min1, min2);
        byte[] subnetmask = or(subnetmask1, subnetmask2);
        return ipWithSubnetMask(ip, subnetmask);
    }

    /**
     * Concatenates the IP address with its subnet mask.
     *
     * @param ip         The IP address.
     * @param subnetMask Its subnet mask.
     * @return The concatenated IP address with its subnet mask.
     */
    private static byte[] ipWithSubnetMask(byte[] ip, byte[] subnetMask)
    {
        return Arrays.concatenate(ip, subnetMask);
    }

    /**
     * Splits the IP addresses and their subnet mask.
     *
     * @param ipWithSubmask1 The first IP address with the subnet mask.
     * @param ipWithSubmask2 The second IP address with the subnet mask.
     * @return An array with two elements. Each element contains the IP address
     * and the subnet mask in this order.
     */
    private static byte[][] extractIPsAndSubnetMasks(byte[] ipWithSubmask1, byte[] ipWithSubmask2)
    {
        int ipLength = ipWithSubmask1.length / 2;
        byte ip1[] = new byte[ipLength];
        byte subnetmask1[] = new byte[ipLength];
        System.arraycopy(ipWithSubmask1, 0, ip1, 0, ipLength);
        System.arraycopy(ipWithSubmask1, ipLength, subnetmask1, 0, ipLength);

        byte ip2[] = new byte[ipLength];
        byte subnetmask2[] = new byte[ipLength];
        System.arraycopy(ipWithSubmask2, 0, ip2, 0, ipLength);
        System.arraycopy(ipWithSubmask2, ipLength, subnetmask2, 0, ipLength);
        return new byte[][]{ ip1, subnetmask1, ip2, subnetmask2 };
    }

    /**
     * Based on the two IP addresses and their subnet masks the IP range is
     * computed for each IP address - subnet mask pair and returned as the
     * minimum IP address and the maximum address of the range.
     *
     * @param ip1         The first IP address.
     * @param subnetmask1 The subnet mask of the first IP address.
     * @param ip2         The second IP address.
     * @param subnetmask2 The subnet mask of the second IP address.
     * @return A array with two elements. The first/second element contains the
     * min and max IP address of the first/second IP address and its
     * subnet mask.
     */
    private static byte[][] minMaxIPs(byte[] ip1, byte[] subnetmask1, byte[] ip2, byte[] subnetmask2)
    {
        int ipLength = ip1.length;
        byte[] min1 = new byte[ipLength];
        byte[] max1 = new byte[ipLength];

        byte[] min2 = new byte[ipLength];
        byte[] max2 = new byte[ipLength];

        for (int i = 0; i < ipLength; i++)
        {
            min1[i] = (byte)(ip1[i] & subnetmask1[i]);
            max1[i] = (byte)(ip1[i] & subnetmask1[i] | ~subnetmask1[i]);

            min2[i] = (byte)(ip2[i] & subnetmask2[i]);
            max2[i] = (byte)(ip2[i] & subnetmask2[i] | ~subnetmask2[i]);
        }

        return new byte[][]{ min1, max1, min2, max2 };
    }

    private static void checkPermittedEmail(Set permitted, String email)
        throws NameConstraintValidatorException
    {
        if (permitted != null
            && !(email.length() == 0 && permitted.size() == 0)
            && !isEmailConstrained(permitted, email))
        {
            throw new NameConstraintValidatorException("Subject email address is not from a permitted subtree.");
        }
    }

    private static void checkExcludedEmail(Set excluded, String email)
        throws NameConstraintValidatorException
    {
        if (isEmailConstrained(excluded, email))
        {
            throw new NameConstraintValidatorException("Email address is from an excluded subtree.");
        }
    }

    private static void checkPermittedOtherName(Set permitted, OtherName otherName)
        throws NameConstraintValidatorException
    {
        if (permitted != null && !isOtherNameConstrained(permitted, otherName))
        {
            throw new NameConstraintValidatorException("Subject OtherName is not from a permitted subtree.");
        }
    }

    private static void checkExcludedOtherName(Set excluded, OtherName otherName)
        throws NameConstraintValidatorException
    {
        if (isOtherNameConstrained(excluded, otherName))
        {
            throw new NameConstraintValidatorException("OtherName is from an excluded subtree.");
        }
    }

    /**
     * Checks if the IP <code>ip</code> is included in the permitted set
     * <code>permitted</code>.
     *
     * @param permitted A <code>Set</code> of permitted IP addresses with
     *                  their subnet mask as byte arrays.
     * @param ip        The IP address.
     * @throws NameConstraintValidatorException if the IP is not permitted.
     */
    private static void checkPermittedIP(Set permitted, byte[] ip)
        throws NameConstraintValidatorException
    {
        if (permitted != null
            && !(ip.length == 0 && permitted.size() == 0)
            && !isIPConstrained(permitted, ip))
        {
            throw new NameConstraintValidatorException("IP is not from a permitted subtree.");
        }
    }

    /**
     * Checks if the IP <code>ip</code> is included in the excluded set
     * <code>excluded</code>.
     *
     * @param excluded A <code>Set</code> of excluded IP addresses with their
     *                 subnet mask as byte arrays.
     * @param ip       The IP address.
     * @throws NameConstraintValidatorException if the IP is excluded.
     */
    private static void checkExcludedIP(Set excluded, byte[] ip)
        throws NameConstraintValidatorException
    {
        if (isIPConstrained(excluded, ip))
        {
            throw new NameConstraintValidatorException("IP is from an excluded subtree.");
        }
    }

    private static boolean isIPConstrained(Set constraints, byte[] ip)
    {
        Iterator it = constraints.iterator();
        while (it.hasNext())
        {
            byte[] constraint = (byte[])it.next();
            if (isIPConstrained(constraint, ip))
            {
                return true;
            }
        }

        return false;
    }

    /**
     * Checks if the IP address <code>ip</code> is constrained by
     * <code>constraint</code>.
     *
     * @param ip         The IP address.
     * @param constraint The constraint. This is an IP address concatenated with
     *                   its subnetmask.
     * @return <code>true</code> if constrained, <code>false</code>
     * otherwise.
     */
    private static boolean isIPConstrained(byte[] constraint, byte[] ip)
    {
        int ipLength = ip.length;

        if (ipLength != (constraint.length / 2))
        {
            return false;
        }

        byte[] subnetMask = new byte[ipLength];
        System.arraycopy(constraint, ipLength, subnetMask, 0, ipLength);

        byte[] permittedSubnetAddress = new byte[ipLength];

        byte[] ipSubnetAddress = new byte[ipLength];

        // the resulting IP address by applying the subnet mask
        for (int i = 0; i < ipLength; i++)
        {
            permittedSubnetAddress[i] = (byte)(constraint[i] & subnetMask[i]);
            ipSubnetAddress[i] = (byte)(ip[i] & subnetMask[i]);
        }

        return Arrays.areEqual(permittedSubnetAddress, ipSubnetAddress);
    }

    private static boolean isOtherNameConstrained(Set constraints, OtherName otherName)
    {
        Iterator it = constraints.iterator();
        while (it.hasNext())
        {
            OtherName constraint = OtherName.getInstance(it.next());
            if (isOtherNameConstrained(constraint, otherName))
            {
                return true;
            }
        }

        return false;
    }

    private static boolean isOtherNameConstrained(OtherName constraint, OtherName otherName)
    {
        return constraint.equals(otherName);
    }

    private static boolean isEmailConstrained(Set constraints, String email)
    {
        Iterator it = constraints.iterator();
        while (it.hasNext())
        {
            String constraint = (String)it.next();
            if (isEmailConstrained(constraint, email))
            {
                return true;
            }
        }

        return false;
    }

    private static boolean isEmailConstrained(String constraint, String email)
    {
        int atPos = constraint.indexOf('@');

        // a particular mailbox
        if (atPos > 0)
        {
            return email.equalsIgnoreCase(constraint);
        }

        String sub = email.substring(email.indexOf('@') + 1);

        // "@domain" style
        if (atPos == 0)
        {
            return sub.equalsIgnoreCase(constraint.substring(1));
        }

        // address in sub domain
        if (constraint.startsWith("."))
        {
            return withinDomain(sub, constraint);
        }

        // on particular host
        return sub.equalsIgnoreCase(constraint);
    }

    private static boolean withinDomain(String testDomain, String domain)
    {
        if (domain.startsWith("."))
        {
            domain = domain.substring(1);
        }

        String[] domainParts = Strings.split(domain, '.');
        String[] testDomainParts = Strings.split(testDomain, '.');

        // must have at least one subdomain
        if (testDomainParts.length <= domainParts.length)
        {
            return false;
        }

        int d = testDomainParts.length - domainParts.length;
        if (testDomainParts[d - 1].equals(""))
        {
            return false;
        }

        for (int i = 0; i < domainParts.length; i++)
        {
            if (!domainParts[i].equalsIgnoreCase(testDomainParts[d + i]))
            {
                return false;
            }
        }
        return true;
    }

    private static void checkExcludedDNS(Set excluded, String dns)
        throws NameConstraintValidatorException
    {
        if (isDNSConstrained(excluded, dns))
        {
            throw new NameConstraintValidatorException("DNS is from an excluded subtree.");
        }
    }

    private static void checkPermittedDNS(Set permitted, String dns)
        throws NameConstraintValidatorException
    {
        if (permitted != null
            && !(dns.length() == 0 && permitted.size() == 0)
            && !isDNSConstrained(permitted, dns))
        {
            throw new NameConstraintValidatorException("DNS is not from a permitted subtree.");
        }
    }

    private static boolean isDNSConstrained(Set constraints, String dns)
    {
        Iterator it = constraints.iterator();
        while (it.hasNext())
        {
            String constraint = (String)it.next();
            if (isDNSConstrained(constraint, dns))
            {
                return true;
            }
        }

        return false;
    }

    private static boolean isDNSConstrained(String constraint, String dns)
    {
        return dns.equalsIgnoreCase(constraint) || withinDomain(dns, constraint);
    }

    /**
     * The common part of <code>email1</code> and <code>email2</code> is
     * added to the union <code>union</code>. If <code>email1</code> and
     * <code>email2</code> have nothing in common they are added both.
     *
     * @param email1 Email address constraint 1.
     * @param email2 Email address constraint 2.
     * @param union  The union.
     */
    private static void unionEmail(String email1, String email2, Set union)
    {
        // email1 is a particular address
        if (email1.indexOf('@') != -1)
        {
            String _sub = email1.substring(email1.indexOf('@') + 1);
            // both are a particular mailbox
            if (email2.indexOf('@') != -1)
            {
                if (email1.equalsIgnoreCase(email2))
                {
                    union.add(email1);
                }
                else
                {
                    union.add(email1);
                    union.add(email2);
                }
            }
            // email2 specifies a domain
            else if (email2.startsWith("."))
            {
                if (withinDomain(_sub, email2))
                {
                    union.add(email2);
                }
                else
                {
                    union.add(email1);
                    union.add(email2);
                }
            }
            // email2 specifies a particular host
            else
            {
                if (_sub.equalsIgnoreCase(email2))
                {
                    union.add(email2);
                }
                else
                {
                    union.add(email1);
                    union.add(email2);
                }
            }
        }
        // email1 specifies a domain
        else if (email1.startsWith("."))
        {
            if (email2.indexOf('@') != -1)
            {
                String _sub = email2.substring(email2.indexOf('@') + 1);
                if (withinDomain(_sub, email1))
                {
                    union.add(email1);
                }
                else
                {
                    union.add(email1);
                    union.add(email2);
                }
            }
            // email2 specifies a domain
            else if (email2.startsWith("."))
            {
                if (isDNSConstrained(email2, email1))
                {
                    union.add(email2);
                }
                else if (withinDomain(email2, email1))
                {
                    union.add(email1);
                }
                else
                {
                    union.add(email1);
                    union.add(email2);
                }
            }
            else
            {
                if (withinDomain(email2, email1))
                {
                    union.add(email1);
                }
                else
                {
                    union.add(email1);
                    union.add(email2);
                }
            }
        }
        // email specifies a host
        else
        {
            if (email2.indexOf('@') != -1)
            {
                String _sub = email2.substring(email2.indexOf('@') + 1);
                if (_sub.equalsIgnoreCase(email1))
                {
                    union.add(email1);
                }
                else
                {
                    union.add(email1);
                    union.add(email2);
                }
            }
            // email2 specifies a domain
            else if (email2.startsWith("."))
            {
                if (withinDomain(email1, email2))
                {
                    union.add(email2);
                }
                else
                {
                    union.add(email1);
                    union.add(email2);
                }
            }
            // email2 specifies a particular host
            else
            {
                if (email1.equalsIgnoreCase(email2))
                {
                    union.add(email1);
                }
                else
                {
                    union.add(email1);
                    union.add(email2);
                }
            }
        }
    }

    private static void unionURI(String email1, String email2, Set union)
    {
        // email1 is a particular address
        if (email1.indexOf('@') != -1)
        {
            String _sub = email1.substring(email1.indexOf('@') + 1);
            // both are a particular mailbox
            if (email2.indexOf('@') != -1)
            {
                if (email1.equalsIgnoreCase(email2))
                {
                    union.add(email1);
                }
                else
                {
                    union.add(email1);
                    union.add(email2);
                }
            }
            // email2 specifies a domain
            else if (email2.startsWith("."))
            {
                if (withinDomain(_sub, email2))
                {
                    union.add(email2);
                }
                else
                {
                    union.add(email1);
                    union.add(email2);
                }
            }
            // email2 specifies a particular host
            else
            {
                if (_sub.equalsIgnoreCase(email2))
                {
                    union.add(email2);
                }
                else
                {
                    union.add(email1);
                    union.add(email2);
                }
            }
        }
        // email1 specifies a domain
        else if (email1.startsWith("."))
        {
            if (email2.indexOf('@') != -1)
            {
                String _sub = email2.substring(email2.indexOf('@') + 1);
                if (withinDomain(_sub, email1))
                {
                    union.add(email1);
                }
                else
                {
                    union.add(email1);
                    union.add(email2);
                }
            }
            // email2 specifies a domain
            else if (email2.startsWith("."))
            {
                if (isDNSConstrained(email2, email1))
                {
                    union.add(email2);
                }
                else if (withinDomain(email2, email1))
                {
                    union.add(email1);
                }
                else
                {
                    union.add(email1);
                    union.add(email2);
                }
            }
            else
            {
                if (withinDomain(email2, email1))
                {
                    union.add(email1);
                }
                else
                {
                    union.add(email1);
                    union.add(email2);
                }
            }
        }
        // email specifies a host
        else
        {
            if (email2.indexOf('@') != -1)
            {
                String _sub = email2.substring(email2.indexOf('@') + 1);
                if (_sub.equalsIgnoreCase(email1))
                {
                    union.add(email1);
                }
                else
                {
                    union.add(email1);
                    union.add(email2);
                }
            }
            // email2 specifies a domain
            else if (email2.startsWith("."))
            {
                if (withinDomain(email1, email2))
                {
                    union.add(email2);
                }
                else
                {
                    union.add(email1);
                    union.add(email2);
                }
            }
            // email2 specifies a particular host
            else
            {
                if (email1.equalsIgnoreCase(email2))
                {
                    union.add(email1);
                }
                else
                {
                    union.add(email1);
                    union.add(email2);
                }
            }
        }
    }

    private static Set intersectDNS(Set permitted, Set dnss)
    {
        Set intersect = new HashSet();
        for (Iterator it = dnss.iterator(); it.hasNext();)
        {
            String dns = extractNameAsString((GeneralSubtree)it.next());

            if (permitted == null)
            {
                intersect.add(dns);
            }
            else
            {
                Iterator _iter = permitted.iterator();
                while (_iter.hasNext())
                {
                    String _permitted = (String)_iter.next();

                    if (isDNSConstrained(dns, _permitted))
                    {
                        intersect.add(_permitted);
                    }
                    else if (withinDomain(dns, _permitted))
                    {
                        intersect.add(dns);
                    }
                    else
                    {
                        // No intersection
                    }
                }
            }
        }

        return intersect;
    }

    private static Set unionDNS(Set excluded, String dns)
    {
        if (excluded.isEmpty())
        {
            excluded.add(dns);
            return excluded;
        }

        Set union = new HashSet();

        Iterator _iter = excluded.iterator();
        while (_iter.hasNext())
        {
            String _permitted = (String)_iter.next();

            if (isDNSConstrained(dns, _permitted))
            {
                union.add(dns);
            }
            else if (withinDomain(dns, _permitted))
            {
                union.add(_permitted);
            }
            else
            {
                union.add(_permitted);
                union.add(dns);
            }
        }

        return union;
    }

    /**
     * The most restricting part from <code>email1</code> and
     * <code>email2</code> is added to the intersection <code>intersect</code>.
     *
     * @param email1    Email address constraint 1.
     * @param email2    Email address constraint 2.
     * @param intersect The intersection.
     */
    private static void intersectEmail(String email1, String email2, Set intersect)
    {
        // email1 is a particular address
        if (email1.indexOf('@') != -1)
        {
            String _sub = email1.substring(email1.indexOf('@') + 1);
            // both are a particular mailbox
            if (email2.indexOf('@') != -1)
            {
                if (email1.equalsIgnoreCase(email2))
                {
                    intersect.add(email1);
                }
            }
            // email2 specifies a domain
            else if (email2.startsWith("."))
            {
                if (withinDomain(_sub, email2))
                {
                    intersect.add(email1);
                }
            }
            // email2 specifies a particular host
            else
            {
                if (_sub.equalsIgnoreCase(email2))
                {
                    intersect.add(email1);
                }
            }
        }
        // email specifies a domain
        else if (email1.startsWith("."))
        {
            if (email2.indexOf('@') != -1)
            {
                String _sub = email2.substring(email2.indexOf('@') + 1);
                if (withinDomain(_sub, email1))
                {
                    intersect.add(email2);
                }
            }
            // email2 specifies a domain
            else if (email2.startsWith("."))
            {
                if (isDNSConstrained(email2, email1))
                {
                    intersect.add(email1);
                }
                else if (withinDomain(email2, email1))
                {
                    intersect.add(email2);
                }
                else
                {
                    // No intersection
                }
            }
            else
            {
                if (withinDomain(email2, email1))
                {
                    intersect.add(email2);
                }
            }
        }
        // email1 specifies a host
        else
        {
            if (email2.indexOf('@') != -1)
            {
                String _sub = email2.substring(email2.indexOf('@') + 1);
                if (_sub.equalsIgnoreCase(email1))
                {
                    intersect.add(email2);
                }
            }
            // email2 specifies a domain
            else if (email2.startsWith("."))
            {
                if (withinDomain(email1, email2))
                {
                    intersect.add(email1);
                }
            }
            // email2 specifies a particular host
            else
            {
                if (email1.equalsIgnoreCase(email2))
                {
                    intersect.add(email1);
                }
            }
        }
    }

    private static void checkExcludedURI(Set excluded, String uri)
        throws NameConstraintValidatorException
    {
        if (isURIConstrained(excluded, uri))
        {
            throw new NameConstraintValidatorException("URI is from an excluded subtree.");
        }
    }

    private static Set intersectURI(Set permitted, Set uris)
    {
        Set intersect = new HashSet();
        for (Iterator it = uris.iterator(); it.hasNext();)
        {
            String uri = extractNameAsString((GeneralSubtree)it.next());

            if (permitted == null)
            {
                intersect.add(uri);
            }
            else
            {
                Iterator _iter = permitted.iterator();
                while (_iter.hasNext())
                {
                    String _permitted = (String)_iter.next();
                    intersectURI(_permitted, uri, intersect);
                }
            }
        }
        return intersect;
    }

    private static Set unionURI(Set excluded, String uri)
    {
        if (excluded.isEmpty())
        {
            excluded.add(uri);
            return excluded;
        }

        Set union = new HashSet();

        Iterator _iter = excluded.iterator();
        while (_iter.hasNext())
        {
            String _excluded = (String)_iter.next();

            unionURI(_excluded, uri, union);
        }

        return union;
    }

    private static void intersectURI(String email1, String email2, Set intersect)
    {
        // email1 is a particular address
        if (email1.indexOf('@') != -1)
        {
            String _sub = email1.substring(email1.indexOf('@') + 1);
            // both are a particular mailbox
            if (email2.indexOf('@') != -1)
            {
                if (email1.equalsIgnoreCase(email2))
                {
                    intersect.add(email1);
                }
            }
            // email2 specifies a domain
            else if (email2.startsWith("."))
            {
                if (withinDomain(_sub, email2))
                {
                    intersect.add(email1);
                }
            }
            // email2 specifies a particular host
            else
            {
                if (_sub.equalsIgnoreCase(email2))
                {
                    intersect.add(email1);
                }
            }
        }
        // email specifies a domain
        else if (email1.startsWith("."))
        {
            if (email2.indexOf('@') != -1)
            {
                String _sub = email2.substring(email2.indexOf('@') + 1);
                if (withinDomain(_sub, email1))
                {
                    intersect.add(email2);
                }
            }
            // email2 specifies a domain
            else if (email2.startsWith("."))
            {
                if (isDNSConstrained(email2, email1))
                {
                    intersect.add(email1);
                }
                else if (withinDomain(email2, email1))
                {
                    intersect.add(email2);
                }
                else
                {
                    // No intersection
                }
            }
            else
            {
                if (withinDomain(email2, email1))
                {
                    intersect.add(email2);
                }
            }
        }
        // email1 specifies a host
        else
        {
            if (email2.indexOf('@') != -1)
            {
                String _sub = email2.substring(email2.indexOf('@') + 1);
                if (_sub.equalsIgnoreCase(email1))
                {
                    intersect.add(email2);
                }
            }
            // email2 specifies a domain
            else if (email2.startsWith("."))
            {
                if (withinDomain(email1, email2))
                {
                    intersect.add(email1);
                }
            }
            // email2 specifies a particular host
            else
            {
                if (email1.equalsIgnoreCase(email2))
                {
                    intersect.add(email1);
                }
            }
        }
    }

    private static void checkPermittedURI(Set permitted, String uri)
        throws NameConstraintValidatorException
    {
        if (permitted != null
            && !(uri.length() == 0 && permitted.size() == 0)
            && !isURIConstrained(permitted, uri))
        {
            throw new NameConstraintValidatorException("URI is not from a permitted subtree.");
        }
    }

    private static boolean isURIConstrained(Set constraints, String uri)
    {
        Iterator it = constraints.iterator();
        while (it.hasNext())
        {
            String constraint = ((String)it.next());
            if (isURIConstrained(constraint, uri))
            {
                return true;
            }
        }

        return false;
    }

    private static boolean isURIConstrained(String constraint, String uri)
    {
        String host = extractHostFromURL(uri);

        // in sub domain or domain
        if (constraint.startsWith("."))
        {
            return withinDomain(host, constraint);
        }

        // a host
        return host.equalsIgnoreCase(constraint);
    }

    private static String extractHostFromURL(String url)
    {
        // see RFC 1738
        // remove ':' after protocol, e.g. https:
        String sub = url.substring(url.indexOf(':') + 1);
        // extract host from Common Internet Scheme Syntax, e.g. https://
        int slashesPos = sub.indexOf("//");
        if (slashesPos != -1)
        {
            sub = sub.substring(slashesPos + 2);
        }
        // first remove port, e.g. https://test.com:21
        int portColonPos = sub.lastIndexOf(':');
        if (portColonPos != -1)
        {
            sub = sub.substring(0, portColonPos);
        }
        // remove user and password, e.g. https://john:password@test.com
        sub = sub.substring(sub.indexOf(':') + 1);
        sub = sub.substring(sub.indexOf('@') + 1);
        // remove local parts, e.g. https://test.com/bla
        int slashPos = sub.indexOf('/');
        if (slashPos != -1)
        {
            sub = sub.substring(0, slashPos);
        }
        return sub;
    }

    /**
     * Returns the maximum IP address.
     *
     * @param ip1 The first IP address.
     * @param ip2 The second IP address.
     * @return The maximum IP address.
     */
    private static byte[] max(byte[] ip1, byte[] ip2)
    {
        return compareTo(ip1, ip2) > 0 ? ip1 : ip2;
    }

    /**
     * Returns the minimum IP address.
     *
     * @param ip1 The first IP address.
     * @param ip2 The second IP address.
     * @return The minimum IP address.
     */
    private static byte[] min(byte[] ip1, byte[] ip2)
    {
        return compareTo(ip1, ip2) < 0 ? ip1 : ip2;
    }

    /**
     * Compares IP address <code>ip1</code> with <code>ip2</code>. If ip1
     * is equal to ip2 0 is returned. If ip1 is bigger 1 is returned, -1
     * otherwise.
     *
     * @param ip1 The first IP address.
     * @param ip2 The second IP address.
     * @return 0 if ip1 is equal to ip2, 1 if ip1 is bigger, -1 otherwise.
     */
    private static int compareTo(byte[] ip1, byte[] ip2)
    {
        for (int i = 0; i < ip1.length; i++)
        {
            int t1 = ip1[i] & 0xFF, t2 = ip2[i] & 0xFF;
            if (t1 < t2)
            {
                return -1;
            }
            if (t1 > t2)
            {
                return 1;
            }
        }
        return 0;
    }

    /**
     * Returns the logical OR of the IP addresses <code>ip1</code> and
     * <code>ip2</code>.
     *
     * @param ip1 The first IP address.
     * @param ip2 The second IP address.
     * @return The OR of <code>ip1</code> and <code>ip2</code>.
     */
    private static byte[] or(byte[] ip1, byte[] ip2)
    {
        byte[] temp = new byte[ip1.length];
        for (int i = 0; i < ip1.length; i++)
        {
            temp[i] = (byte)(ip1[i] | ip2[i]);
        }
        return temp;
    }

    private static int hashCollection(Collection coll)
    {
        if (coll == null)
        {
            return 0;
        }
        int hash = 0;
        Iterator it1 = coll.iterator();
        while (it1.hasNext())
        {
            Object o = it1.next();
            if (o instanceof byte[])
            {
                hash += Arrays.hashCode((byte[])o);
            }
            else
            {
                hash += o.hashCode();
            }
        }
        return hash;
    }

    private static boolean collectionsAreEqual(Collection coll1, Collection coll2)
    {
        if (coll1 == coll2)
        {
            return true;
        }
        if (coll1 == null || coll2 == null)
        {
            return false;
        }
        if (coll1.size() != coll2.size())
        {
            return false;
        }
        Iterator it1 = coll1.iterator();

        while (it1.hasNext())
        {
            Object a = it1.next();
            Iterator it2 = coll2.iterator();
            boolean found = false;
            while (it2.hasNext())
            {
                Object b = it2.next();
                if (equals(a, b))
                {
                    found = true;
                    break;
                }
            }
            if (!found)
            {
                return false;
            }
        }
        return true;
    }

    private static boolean equals(Object o1, Object o2)
    {
        if (o1 == o2)
        {
            return true;
        }
        if (o1 == null || o2 == null)
        {
            return false;
        }
        if (o1 instanceof byte[] && o2 instanceof byte[])
        {
            return Arrays.areEqual((byte[])o1, (byte[])o2);
        }
        else
        {
            return o1.equals(o2);
        }
    }

    /**
     * Stringifies an IPv4 or v6 address with subnet mask.
     *
     * @param ip The IP with subnet mask.
     * @return The stringified IP address.
     */
    private static String stringifyIP(byte[] ip)
    {
        StringBuilder temp = new StringBuilder();
        for (int i = 0; i < ip.length / 2; i++)
        {
            if (temp.length() > 0)
            {
                temp.append(".");
            }
            temp.append(Integer.toString(ip[i] & 0x00FF));
        }

        temp.append("/");
        boolean first = true;
        for (int i = ip.length / 2; i < ip.length; i++)
        {
            if (first)
            {
                first = false;
            }
            else
            {
                temp.append(".");
            }
            temp.append(Integer.toString(ip[i] & 0x00FF));
        }

        return temp.toString();
    }

    private static String stringifyIPCollection(Set ips)
    {
        StringBuilder temp = new StringBuilder();
        temp.append("[");
        for (Iterator it = ips.iterator(); it.hasNext();)
        {
            if (temp.length() > 1)
            {
                temp.append(",");
            }
            temp.append(stringifyIP((byte[])it.next()));
        }
        temp.append("]");
        return temp.toString();
    }

    private static String stringifyOtherNameCollection(Set otherNames)
    {
        StringBuilder temp = new StringBuilder();
        temp.append("[");
        for (Iterator it = otherNames.iterator(); it.hasNext();)
        {
            if (temp.length() > 1)
            {
                temp.append(",");
            }
            OtherName otherName = OtherName.getInstance(it.next());
            temp.append(otherName.getTypeID().getId());
            temp.append(":");
            try
            {
                // -DM Hex.toHexString
                temp.append(Hex.toHexString(otherName.getValue().toASN1Primitive().getEncoded()));
            }
            catch (IOException e)
            {
                temp.append(e.toString());
            }
        }
        temp.append("]");
        return temp.toString();
    }

    public String toString()
    {
        StringBuilder temp = new StringBuilder();

        addLine(temp, "permitted:");
        if (permittedSubtreesDN != null)
        {
            addLine(temp, "DN:");
            addLine(temp, permittedSubtreesDN.toString());
        }
        if (permittedSubtreesDNS != null)
        {
            addLine(temp, "DNS:");
            addLine(temp, permittedSubtreesDNS.toString());
        }
        if (permittedSubtreesEmail != null)
        {
            addLine(temp, "Email:");
            addLine(temp, permittedSubtreesEmail.toString());
        }
        if (permittedSubtreesURI != null)
        {
            addLine(temp, "URI:");
            addLine(temp, permittedSubtreesURI.toString());
        }
        if (permittedSubtreesIP != null)
        {
            addLine(temp, "IP:");
            addLine(temp, stringifyIPCollection(permittedSubtreesIP));
        }
        if (permittedSubtreesOtherName != null)
        {
            addLine(temp, "OtherName:");
            addLine(temp, stringifyOtherNameCollection(permittedSubtreesOtherName));
        }
        addLine(temp, "excluded:");
        if (!excludedSubtreesDN.isEmpty())
        {
            addLine(temp, "DN:");
            addLine(temp, excludedSubtreesDN.toString());
        }
        if (!excludedSubtreesDNS.isEmpty())
        {
            addLine(temp, "DNS:");
            addLine(temp, excludedSubtreesDNS.toString());
        }
        if (!excludedSubtreesEmail.isEmpty())
        {
            addLine(temp, "Email:");
            addLine(temp, excludedSubtreesEmail.toString());
        }
        if (!excludedSubtreesURI.isEmpty())
        {
            addLine(temp, "URI:");
            addLine(temp, excludedSubtreesURI.toString());
        }
        if (!excludedSubtreesIP.isEmpty())
        {
            addLine(temp, "IP:");
            addLine(temp, stringifyIPCollection(excludedSubtreesIP));
        }
        if (!excludedSubtreesOtherName.isEmpty())
        {
            addLine(temp, "OtherName:");
            addLine(temp, stringifyOtherNameCollection(excludedSubtreesOtherName));
        }
        return temp.toString();
    }

    private static void addLine(StringBuilder sb, String str)
    {
         sb.append(str).append(Strings.lineSeparator());
    }

    private static String extractNameAsString(GeneralSubtree subtree)
    {
        return extractNameAsString(subtree.getBase().getName());
    }

    private static String extractNameAsString(ASN1Encodable nameValue)
    {
        return ASN1IA5String.getInstance(nameValue).getString();
    }
}
