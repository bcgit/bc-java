package org.bouncycastle.asn1.pkcs;

import java.math.BigInteger;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.Arrays;

/**
 * <pre>
 *     PBKDF2-params ::= SEQUENCE {
 *               salt CHOICE {
 *                      specified OCTET STRING,
 *                      otherSource AlgorithmIdentifier {{PBKDF2-SaltSources}}
 *               },
 *              iterationCount INTEGER (1..MAX),
 *              keyLength INTEGER (1..MAX) OPTIONAL,
 *              prf AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT algid-hmacWithSHA1 }
 * </pre>
 */
public class PBKDF2Params
    extends ASN1Object
{
    private static final AlgorithmIdentifier algid_hmacWithSHA1 = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA1, DERNull.INSTANCE);

    private final ASN1OctetString octStr;
    private final ASN1Integer iterationCount;
    private final ASN1Integer keyLength;
    private final AlgorithmIdentifier prf;

    /**
     * Create PBKDF2Params from the passed in object,
     *
     * @param obj either PBKDF2Params or an ASN1Sequence.
     * @return a PBKDF2Params instance.
     */
    public static PBKDF2Params getInstance(
        Object obj)
    {
        if (obj instanceof PBKDF2Params)
        {
            return (PBKDF2Params)obj;
        }

        if (obj != null)
        {
            return new PBKDF2Params(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    /**
     * Create a PBKDF2Params with the specified salt, iteration count, and algid-hmacWithSHA1 for the prf.
     *
     * @param salt           input salt.
     * @param iterationCount input iteration count.
     */
    public PBKDF2Params(
        byte[] salt,
        int iterationCount)
    {
        this(salt, iterationCount, 0);
    }

    /**
     * Create a PBKDF2Params with the specified salt, iteration count, keyLength, and algid-hmacWithSHA1 for the prf.
     *
     * @param salt           input salt.
     * @param iterationCount input iteration count.
     * @param keyLength      intended key length to be produced.
     */
    public PBKDF2Params(
        byte[] salt,
        int iterationCount,
        int keyLength)
    {
        this(salt, iterationCount, keyLength, null);
    }

    /**
     * Create a PBKDF2Params with the specified salt, iteration count, keyLength, and a defined prf.
     *
     * @param salt           input salt.
     * @param iterationCount input iteration count.
     * @param keyLength      intended key length to be produced.
     * @param prf            the pseudo-random function to use.
     */
    public PBKDF2Params(
        byte[] salt,
        int iterationCount,
        int keyLength,
        AlgorithmIdentifier prf)
    {
        this.octStr = new DEROctetString(Arrays.clone(salt));
        this.iterationCount = new ASN1Integer(iterationCount);

        if (keyLength > 0)
        {
            this.keyLength = new ASN1Integer(keyLength);
        }
        else
        {
            this.keyLength = null;
        }

        this.prf = prf;
    }

    /**
     * Create a PBKDF2Params with the specified salt, iteration count, and a defined prf.
     *
     * @param salt           input salt.
     * @param iterationCount input iteration count.
     * @param prf            the pseudo-random function to use.
     */
    public PBKDF2Params(
        byte[] salt,
        int iterationCount,
        AlgorithmIdentifier prf)
    {
        this(salt, iterationCount, 0, prf);
    }

    private PBKDF2Params(
        ASN1Sequence seq)
    {
        Enumeration e = seq.getObjects();

        octStr = (ASN1OctetString)e.nextElement();
        iterationCount = (ASN1Integer)e.nextElement();

        if (e.hasMoreElements())
        {
            Object o = e.nextElement();

            if (o instanceof ASN1Integer)
            {
                keyLength = ASN1Integer.getInstance(o);
                if (e.hasMoreElements())
                {
                    o = e.nextElement();
                }
                else
                {
                    o = null;
                }
            }
            else
            {
                keyLength = null;
            }

            if (o != null)
            {
                prf = AlgorithmIdentifier.getInstance(o);
            }
            else
            {
                prf = null;
            }
        }
        else
        {
            keyLength = null;
            prf = null;
        }
    }

    /**
     * Return the salt to use.
     *
     * @return the input salt.
     */
    public byte[] getSalt()
    {
        return octStr.getOctets();
    }

    /**
     * Return the iteration count to use.
     *
     * @return the input iteration count.
     */
    public BigInteger getIterationCount()
    {
        return iterationCount.getValue();
    }

    /**
     * Return the intended length in octets of the derived key.
     *
     * @return length in octets for derived key, if specified.
     */
    public BigInteger getKeyLength()
    {
        if (keyLength != null)
        {
            return keyLength.getValue();
        }

        return null;
    }

    /**
     * Return true if the PRF is the default (hmacWithSHA1)
     *
     * @return true if PRF is default, false otherwise.
     */
    public boolean isDefaultPrf()
    {
        return prf == null || prf.equals(algid_hmacWithSHA1);
    }

    /**
     * Return the algId of the underlying pseudo random function to use.
     *
     * @return the prf algorithm identifier.
     */
    public AlgorithmIdentifier getPrf()
    {
        if (prf != null)
        {
            return prf;
        }

        return algid_hmacWithSHA1;
    }

    /**
     * Return an ASN.1 structure suitable for encoding.
     *
     * @return the object as an ASN.1 encodable structure.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(4);

        v.add(octStr);
        v.add(iterationCount);

        if (keyLength != null)
        {
            v.add(keyLength);
        }

        if (prf != null && !prf.equals(algid_hmacWithSHA1))
        {
            v.add(prf);
        }

        return new DERSequence(v);
    }
}
