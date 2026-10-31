package org.bouncycastle.asn1.util.test;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.icao.DataGroupHash;
import org.bouncycastle.asn1.misc.CAST5CBCParameters;
import org.bouncycastle.asn1.mozilla.PublicKeyAndChallenge;
import org.bouncycastle.asn1.mozilla.SignedPublicKeyAndChallenge;
import org.bouncycastle.asn1.oiw.ElGamalParameter;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Element count checks for the fixed-size SEQUENCE types in the icao, misc, mozilla and oiw
 * packages, which have no field-order test of their own.
 */
public class MiscSequenceFieldOrderTest
    extends SimpleTest
{
    private interface Parser
    {
        Object parse(ASN1Sequence seq);
    }

    private static final ASN1Integer ONE = new ASN1Integer(1);
    private static final ASN1Encodable OCTETS = new DEROctetString(new byte[8]);
    private static final AlgorithmIdentifier RSA = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);

    public String getName()
    {
        return "MiscSequenceFieldOrder";
    }

    private static ASN1Encodable[] els(ASN1Encodable a)
    {
        return new ASN1Encodable[]{ a };
    }

    private static ASN1Encodable[] els(ASN1Encodable a, ASN1Encodable b)
    {
        return new ASN1Encodable[]{ a, b };
    }

    private static ASN1Encodable[] els(ASN1Encodable a, ASN1Encodable b, ASN1Encodable c)
    {
        return new ASN1Encodable[]{ a, b, c };
    }

    private static ASN1Encodable[] els(ASN1Encodable a, ASN1Encodable b, ASN1Encodable c, ASN1Encodable d)
    {
        return new ASN1Encodable[]{ a, b, c, d };
    }

    // round trip through the encoding so the parser sees the elements as they come off the wire
    private static ASN1Sequence wire(ASN1Encodable[] elements)
        throws IOException
    {
        return ASN1Sequence.getInstance(new DERSequence(elements).getEncoded());
    }

    private void accepts(String label, Parser parser, ASN1Encodable[] elements)
        throws IOException
    {
        try
        {
            parser.parse(wire(elements));
        }
        catch (IllegalArgumentException e)
        {
            fail(label + " rejected a valid encoding: " + e.getMessage());
        }
    }

    private void rejects(String label, Parser parser, ASN1Encodable[] elements)
        throws IOException
    {
        try
        {
            parser.parse(wire(elements));
            fail(label + " accepted an invalid encoding");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    public void performTest()
        throws Exception
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return DataGroupHash.getInstance(seq);
            }
        };
        accepts("DataGroupHash", p, els(ONE, OCTETS));
        rejects("DataGroupHash trailing element", p, els(ONE, OCTETS, ONE));
        rejects("DataGroupHash short", p, els(ONE));

        p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return CAST5CBCParameters.getInstance(seq);
            }
        };
        accepts("CAST5CBCParameters", p, els(OCTETS, ONE));
        rejects("CAST5CBCParameters trailing element", p, els(OCTETS, ONE, ONE));
        rejects("CAST5CBCParameters wrong type", p, els(ONE, ONE));

        p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return ElGamalParameter.getInstance(seq);
            }
        };
        accepts("ElGamalParameter", p, els(ONE, ONE));
        rejects("ElGamalParameter trailing element", p, els(ONE, ONE, ONE));
        rejects("ElGamalParameter wrong type", p, els(ONE, OCTETS));

        ASN1Encodable spki = new SubjectPublicKeyInfo(RSA, new byte[]{ 0 });
        ASN1Encodable challenge = new DERIA5String("challenge");
        p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return PublicKeyAndChallenge.getInstance(seq);
            }
        };
        accepts("PublicKeyAndChallenge", p, els(spki, challenge));
        rejects("PublicKeyAndChallenge trailing element", p, els(spki, challenge, ONE));

        ASN1Encodable pkac = new DERSequence(els(spki, challenge));
        ASN1Encodable sig = new DERBitString(new byte[]{ 1 });
        p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return SignedPublicKeyAndChallenge.getInstance(seq);
            }
        };
        accepts("SignedPublicKeyAndChallenge", p, els(pkac, RSA, sig));
        rejects("SignedPublicKeyAndChallenge trailing element", p, els(pkac, RSA, sig, ONE));
        rejects("SignedPublicKeyAndChallenge short", p, els(pkac, RSA));
    }

    public static void main(String[] args)
    {
        runTest(new MiscSequenceFieldOrderTest());
    }
}
