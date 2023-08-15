package org.bouncycastle.jcajce.provider.asymmetric.ies;

import java.io.IOException;
import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.jce.spec.IESParameterSpec;

public class AlgorithmParametersSpi
    extends java.security.AlgorithmParametersSpi
{
    protected boolean isASN1FormatString(String format)
    {
        return format == null || format.equals("ASN.1");
    }

    protected AlgorithmParameterSpec engineGetParameterSpec(
        Class paramSpec)
        throws InvalidParameterSpecException
    {
        if (paramSpec == null)
        {
            throw new NullPointerException("argument to getParameterSpec must not be null");
        }

        return localEngineGetParameterSpec(paramSpec);
    }

    IESParameterSpec currentSpec;

    /**
     * in the absence of a standard way of doing it this will do for
     * now...
     */
    protected byte[] engineGetEncoded()
    {
        try
        {
            ASN1EncodableVector v = new ASN1EncodableVector();

            if (currentSpec.getDerivationV() != null)
            {
                v.add(new DERTaggedObject(false, 0, new DEROctetString(currentSpec.getDerivationV())));
            }
            if (currentSpec.getEncodingV() != null)
            {
                v.add(new DERTaggedObject(false, 1, new DEROctetString(currentSpec.getEncodingV())));
            }
            v.add(new ASN1Integer(currentSpec.getMacKeySize()));
            byte[] currentSpecNonce = currentSpec.getNonce();
            if (currentSpecNonce != null)
            {
                ASN1EncodableVector cV = new ASN1EncodableVector();

                cV.add(new ASN1Integer(currentSpec.getCipherKeySize()));
                cV.add(new DEROctetString(currentSpecNonce));

                v.add(new DERSequence(cV));
            }
            v.add(currentSpec.getPointCompression() ? ASN1Boolean.TRUE : ASN1Boolean.FALSE);

            return new DERSequence(v).getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            throw new RuntimeException("Error encoding IESParameters");
        }
    }

    protected byte[] engineGetEncoded(
        String format)
    {
        if (isASN1FormatString(format) || format.equalsIgnoreCase("X.509"))
        {
            return engineGetEncoded();
        }

        return null;
    }

    protected AlgorithmParameterSpec localEngineGetParameterSpec(
        Class paramSpec)
        throws InvalidParameterSpecException
    {
        if (paramSpec == IESParameterSpec.class || paramSpec == AlgorithmParameterSpec.class)
        {
            return currentSpec;
        }

        throw new InvalidParameterSpecException("unknown parameter spec passed to ElGamal parameters object.");
    }

    protected void engineInit(
        AlgorithmParameterSpec paramSpec)
        throws InvalidParameterSpecException
    {
        if (!(paramSpec instanceof IESParameterSpec))
        {
            throw new InvalidParameterSpecException("IESParameterSpec required to initialise a IES algorithm parameters object");
        }

        this.currentSpec = (IESParameterSpec)paramSpec;
    }

    protected void engineInit(
        byte[] params)
        throws IOException
    {
        try
        {
            ASN1Sequence s = (ASN1Sequence)ASN1Primitive.fromByteArray(params);

            if (s.size() > 5)
            {
                throw new IOException("sequence too big");
            }

            byte[] derivationV = null;
            byte[] encodingV = null;
            BigInteger macKeySize = null;
            BigInteger keySize = null;
            byte[] nonce = null;
            boolean pointCompression = false;

            for (Enumeration en = s.getObjects(); en.hasMoreElements();)
            {
                Object o = en.nextElement();
                if (o instanceof ASN1TaggedObject)
                {
                    ASN1TaggedObject t = ASN1TaggedObject.getInstance(o);

                    if (t.getTagNo() == 0)
                    {
                        derivationV = ASN1OctetString.getInstance(t, false).getOctets();
                    }
                    else if (t.getTagNo() == 1)
                    {
                        encodingV = ASN1OctetString.getInstance(t, false).getOctets();
                    }
                }
                else if (o instanceof ASN1Integer)
                {
                    macKeySize = ASN1Integer.getInstance(o).getValue();
                }
                else if (o instanceof ASN1Sequence)
                {
                    ASN1Sequence seq = ASN1Sequence.getInstance(o);

                    keySize = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
                    nonce = ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets();
                }
                else if (o instanceof ASN1Boolean)
                {
                    pointCompression = ASN1Boolean.getInstance(o).isTrue();
                }
            }

            if (keySize != null)
            {
                this.currentSpec = new IESParameterSpec(
                    derivationV, encodingV, macKeySize.intValue(), keySize.intValue(), nonce, pointCompression);
            }
            else
            {
                this.currentSpec = new IESParameterSpec(
                                        derivationV, encodingV, macKeySize.intValue(), -1, null, pointCompression);
            }
        }
        catch (ClassCastException e)
        {
            throw new IOException("Not a valid IES Parameter encoding.");
        }
        catch (ArrayIndexOutOfBoundsException e)
        {
            throw new IOException("Not a valid IES Parameter encoding.");
        }
    }

    protected void engineInit(
        byte[] params,
        String format)
        throws IOException
    {
        if (isASN1FormatString(format) || format.equalsIgnoreCase("X.509"))
        {
            engineInit(params);
        }
        else
        {
            throw new IOException("Unknown parameter format " + format);
        }
    }

    protected String engineToString()
    {
        return "IES Parameters";
    }
}
