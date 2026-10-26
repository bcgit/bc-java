package org.bouncycastle.asn1.x500.style;

import java.io.IOException;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Hashtable;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1ParsingException;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;

/**
 * This class provides some default behavior and common implementation for a
 * X500NameStyle. It should be easily extendable to support implementing the
 * desired X500NameStyle.
 */
public abstract class AbstractX500NameStyle
    implements X500NameStyle
{

    /**
     * Tool function to shallow copy a Hashtable.
     *
     * @param paramsMap table to copy
     * @return the copy of the table
     */
    public static Hashtable copyHashTable(Hashtable paramsMap)
    {
        Hashtable newTable = new Hashtable();

        Enumeration keys = paramsMap.keys();
        while (keys.hasMoreElements())
        {
            Object key = keys.nextElement();
            newTable.put(key, paramsMap.get(key));
        }

        return newTable;
    }

    private int calcHashCode(ASN1Encodable enc)
    {
        String value = IETFUtils.canonicalString(enc);
        return value.hashCode();
    }

    public int calculateHashCode(X500Name name)
    {
        int hashCodeValue = 0;
        RDN[] rdns = name.getRDNs();

        // this needs to be order independent, like equals
        for (int i = 0; i != rdns.length; i++)
        {
            if (rdns[i].isMultiValued())
            {
                AttributeTypeAndValue[] atv = rdns[i].getTypesAndValues();

                for (int j = 0; j != atv.length; j++)
                {
                    hashCodeValue ^= atv[j].getType().hashCode();
                    hashCodeValue ^= calcHashCode(atv[j].getValue());
                }
            }
            else
            {
                // an RDN decoded from an empty SET has no first element - areEqual below and
                // IETFUtils.appendRDN both guard for that, this was the one copy of the check
                // that did not, so hashCode() was the only one of the three that threw
                AttributeTypeAndValue first = rdns[i].getFirst();
                if (first != null)
                {
                    hashCodeValue ^= first.getType().hashCode();
                    hashCodeValue ^= calcHashCode(first.getValue());
                }
            }
        }

        return hashCodeValue;
    }


    /**
     * For all string values starting with '#' is assumed, that these are
     * already valid ASN.1 objects encoded in hex.
     * <p>
     * All other string values are send to
     * {@link AbstractX500NameStyle#encodeStringValue(ASN1ObjectIdentifier, String)}.
     * </p>
     * Subclasses should overwrite
     * {@link AbstractX500NameStyle#encodeStringValue(ASN1ObjectIdentifier, String)}
     * to change the encoding of specific types.
     *
     * @param oid the DN name of the value.
     * @param value the String representation of the value.
     */
    public ASN1Encodable stringToValue(ASN1ObjectIdentifier oid, String value)
    {
        if (value.length() != 0 && value.charAt(0) == '#')
        {
            try
            {
                return IETFUtils.valueFromHexString(value, 1);
            }
            catch (IOException e)
            {
                throw new ASN1ParsingException("can't recode value for oid " + oid.getId());
            }
        }

        if (value.length() != 0 && value.charAt(0) == '\\')
        {
            value = value.substring(1);
        }

        return encodeStringValue(oid, value);
    }

    /**
     * Encoded every value into a UTF8String.
     * <p>
     * Subclasses should overwrite
     * this method to change the encoding of specific types.
     * </p>
     *
     * @param oid the DN oid of the value
     * @param value the String representation of the value
     * @return a the value encoded into a ASN.1 object. Never returns <code>null</code>.
     */
    protected ASN1Encodable encodeStringValue(ASN1ObjectIdentifier oid, String value)
    {
        return new DERUTF8String(value);
    }

    /**
     * Two names are equal when they carry the same multiset of RDNs, each RDN compared by
     * {@link #rdnAreEqual(RDN, RDN)}. The RDNs are first compared position by position, in the
     * order they appear or, when the first attribute types differ, in reverse (the usual two
     * encodings of one name); only when that fails are the two multisets compared, by sorting
     * the canonical form of every RDN once, so a name reached from untrusted data costs
     * n log n in its number of RDNs rather than the n squared of a pairwise search. A subclass
     * that overrides rdnAreEqual is consulted on the positional pass; the multiset pass compares
     * the canonical forms of {@link IETFUtils#canonicalString(ASN1Encodable)}.
     */
    public boolean areEqual(X500Name name1, X500Name name2)
    {
        if (name1.size() != name2.size())
        {
            return false;
        }

        RDN[] rdns1 = name1.getRDNs();
        RDN[] rdns2 = name2.getRDNs();
        int count = rdns1.length;

        if (count == 0)
        {
            return true;
        }

        boolean reverse = false;

        AttributeTypeAndValue first1 = rdns1[0].getFirst();
        AttributeTypeAndValue first2 = rdns2[0].getFirst();

        if (first1 != null && first2 != null)
        {
            reverse = !first1.getType().equals(first2.getType());  // guess forward
        }

        boolean positional = true;
        for (int i = 0; i != count && positional; i++)
        {
            positional = rdnAreEqual(rdns1[i], rdns2[reverse ? count - 1 - i : i]);
        }

        if (positional)
        {
            return true;
        }

        // the same RDNs in some other order: sort each side's canonical forms and compare in step
        RDNKey[] keys1 = canonicalKeys(rdns1);
        RDNKey[] keys2 = canonicalKeys(rdns2);

        Arrays.sort(keys1);
        Arrays.sort(keys2);

        for (int i = 0; i != count; i++)
        {
            if (keys1[i].compareTo(keys2[i]) != 0)
            {
                return false;
            }
        }

        return true;
    }

    private static RDNKey[] canonicalKeys(RDN[] rdns)
    {
        RDNKey[] keys = new RDNKey[rdns.length];

        for (int i = 0; i != rdns.length; i++)
        {
            keys[i] = new RDNKey(rdns[i]);
        }

        return keys;
    }

    /**
     * The canonical form of one RDN: its attribute types and canonical values in order, the
     * relation IETFUtils.rDNAreEqual applies, held as separate strings so no delimiter can be
     * confused with value content.
     */
    private static final class RDNKey
        implements Comparable
    {
        private final String[] types;
        private final String[] values;

        RDNKey(RDN rdn)
        {
            AttributeTypeAndValue[] atvs = rdn.getTypesAndValues();

            types = new String[atvs.length];
            values = new String[atvs.length];

            for (int i = 0; i != atvs.length; i++)
            {
                types[i] = atvs[i].getType().getId();
                values[i] = IETFUtils.canonicalString(atvs[i].getValue());
            }
        }

        public int compareTo(Object o)
        {
            RDNKey other = (RDNKey)o;

            if (types.length != other.types.length)
            {
                return types.length < other.types.length ? -1 : 1;
            }

            for (int i = 0; i != types.length; i++)
            {
                int cmp = types[i].compareTo(other.types[i]);
                if (cmp != 0)
                {
                    return cmp;
                }

                cmp = values[i].compareTo(other.values[i]);
                if (cmp != 0)
                {
                    return cmp;
                }
            }

            return 0;
        }
    }

    protected boolean rdnAreEqual(RDN rdn1, RDN rdn2)
    {
        return IETFUtils.rDNAreEqual(rdn1, rdn2);
    }
}
