package org.bouncycastle.asn1.x500.style;

import java.util.Enumeration;
import java.util.Hashtable;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;

/**
 * This class provides some default behavior and common implementation for a
 * X500NameStyle. It should be easily extendible to support implementing the
 * desired X500NameStyle.
 * 
 */
public abstract class AbstractX500NameStyle implements X500NameStyle {

	/**
	 * Tool function to shallow copy a Hashtable.
	 * 
	 * @param paramsMap table to copy
	 * @return the copy of the table
	 */
	public static Hashtable copyHashTable(Hashtable paramsMap) {
		Hashtable newTable = new Hashtable();

		Enumeration keys = paramsMap.keys();
		while (keys.hasMoreElements()) {
			Object key = keys.nextElement();
			newTable.put(key, paramsMap.get(key));
		}

		return newTable;
	}

	private int calcHashCode(ASN1Encodable enc) {
		String value = IETFUtils.valueToString(enc);
		value = IETFUtils.canonicalize(value);
		return value.hashCode();
	}

	public int calculateHashCode(X500Name name) {
		int hashCodeValue = 0;
		RDN[] rdns = name.getRDNs();

		// this needs to be order independent, like equals
		for (int i = 0; i != rdns.length; i++) {
			if (rdns[i].isMultiValued()) {
				AttributeTypeAndValue[] atv = rdns[i].getTypesAndValues();

				for (int j = 0; j != atv.length; j++) {
					hashCodeValue ^= atv[j].getType().hashCode();
					hashCodeValue ^= calcHashCode(atv[j].getValue());
				}
			} else {
				hashCodeValue ^= rdns[i].getFirst().getType().hashCode();
				hashCodeValue ^= calcHashCode(rdns[i].getFirst().getValue());
			}
		}

		return hashCodeValue;
	}
	
    public boolean areEqual(X500Name name1, X500Name name2)
    {
        RDN[] rdns1 = name1.getRDNs();
        RDN[] rdns2 = name2.getRDNs();

        if (rdns1.length != rdns2.length)
        {
            return false;
        }

        boolean reverse = false;

        if (rdns1[0].getFirst() != null && rdns2[0].getFirst() != null)
        {
            reverse = !rdns1[0].getFirst().getType().equals(rdns2[0].getFirst().getType());  // guess forward
        }

        for (int i = 0; i != rdns1.length; i++)
        {
            if (!foundMatch(reverse, rdns1[i], rdns2))
            {
                return false;
            }
        }

        return true;
    }
    
    private boolean foundMatch(boolean reverse, RDN rdn, RDN[] possRDNs)
    {
        if (reverse)
        {
            for (int i = possRDNs.length - 1; i >= 0; i--)
            {
                if (possRDNs[i] != null && rdnAreEqual(rdn, possRDNs[i]))
                {
                    possRDNs[i] = null;
                    return true;
                }
            }
        }
        else
        {
            for (int i = 0; i != possRDNs.length; i++)
            {
                if (possRDNs[i] != null && rdnAreEqual(rdn, possRDNs[i]))
                {
                    possRDNs[i] = null;
                    return true;
                }
            }
        }

        return false;
    }
    
    protected boolean rdnAreEqual(RDN rdn1, RDN rdn2)
    {
        return IETFUtils.rDNAreEqual(rdn1, rdn2);
    }

}
