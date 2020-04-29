package org.bouncycastle.jcajce.provider.asymmetric.dh;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.util.Enumeration;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.DHParameter;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.DomainParameters;
import org.bouncycastle.asn1.x9.ValidationParams;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHValidationParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl;
import org.bouncycastle.jcajce.spec.DHDomainParameterSpec;
import org.bouncycastle.jcajce.spec.DHExtendedPrivateKeySpec;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;


public class BCDHPrivateKey
    implements DHPrivateKey, PKCS12BagAttributeCarrier
{
    static final long serialVersionUID = 311058815616901812L;
    
    private BigInteger      x;

    private transient DHParameterSpec dhSpec;
    private transient PrivateKeyInfo  info;
    private transient DHPrivateKeyParameters dhPrivateKey;

    private transient PKCS12BagAttributeCarrierImpl attrCarrier = new PKCS12BagAttributeCarrierImpl();

    protected BCDHPrivateKey()
    {
    }

    BCDHPrivateKey(
        DHPrivateKey key)
    {
        this.x = key.getX();
        this.dhSpec = key.getParams();
    }

    BCDHPrivateKey(
        DHPrivateKeySpec spec)
    {
        this.x = spec.getX();
        if (spec instanceof DHExtendedPrivateKeySpec)
        {
            this.dhSpec = ((DHExtendedPrivateKeySpec)spec).getParams();
        }
        else
        {
            this.dhSpec = new DHParameterSpec(spec.getP(), spec.getG());
        }
    }

    public BCDHPrivateKey(
        PrivateKeyInfo info)
        throws IOException
    {
        ASN1Sequence    seq = ASN1Sequence.getInstance(info.getPrivateKeyAlgorithm().getParameters());
        ASN1Integer      derX = (ASN1Integer)info.parsePrivateKey();
        ASN1ObjectIdentifier id = info.getPrivateKeyAlgorithm().getAlgorithm();

        this.info = info;
        this.x = derX.getValue();

        if (id.equals(PKCSObjectIdentifiers.dhKeyAgreement))
        {
            DHParameter params = DHParameter.getInstance(seq);

            if (params.getL() != null)
            {
                this.dhSpec = new DHParameterSpec(params.getP(), params.getG(), params.getL().intValue());
                this.dhPrivateKey = new DHPrivateKeyParameters(x,
                          new DHParameters(params.getP(), params.getG(), null, params.getL().intValue()));
            }
            else
            {
                this.dhSpec = new DHParameterSpec(params.getP(), params.getG());
                this.dhPrivateKey = new DHPrivateKeyParameters(x,
                          new DHParameters(params.getP(), params.getG()));
            }
        }
        else if (id.equals(X9ObjectIdentifiers.dhpublicnumber))
        {
            DomainParameters params = DomainParameters.getInstance(seq);

            this.dhSpec = new DHDomainParameterSpec(params.getP(), params.getQ(), params.getG(), params.getJ(), 0);
            this.dhPrivateKey = new DHPrivateKeyParameters(x,
                new DHParameters(params.getP(), params.getG(), params.getQ(), params.getJ(), null));
        }
        else
        {
            throw new IllegalArgumentException("unknown algorithm type: " + id);
        }


    }

    BCDHPrivateKey(
        DHPrivateKeyParameters params)
    {
        this.x = params.getX();
        this.dhSpec = new DHDomainParameterSpec(params.getParameters());
    }

    public String getAlgorithm()
    {
        return "DH";
    }

    /**
     * return the encoding format we produce in getEncoded().
     *
     * @return the string "PKCS#8"
     */
    public String getFormat()
    {
        return "PKCS#8";
    }

    /**
     * Return a PKCS8 representation of the key. The sequence returned
     * represents a full PrivateKeyInfo object.
     *
     * @return a PKCS8 representation of the key.
     */
    public byte[] getEncoded()
    {
        try
        {
            if (info != null)
            {
                return info.getEncoded(ASN1Encoding.DER);
            }

            PrivateKeyInfo          info;
            if (dhSpec instanceof DHDomainParameterSpec && ((DHDomainParameterSpec)dhSpec).getQ() != null)
            {
                DHParameters params = ((DHDomainParameterSpec)dhSpec).getDomainParameters();
                DHValidationParameters validationParameters = params.getValidationParameters();
                ValidationParams vParams = null;
                if (validationParameters != null)
                {
                    vParams = new ValidationParams(validationParameters.getSeed(), validationParameters.getCounter());
                }
                info = new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.dhpublicnumber, new DomainParameters(params.getP(), params.getG(), params.getQ(), params.getJ(), vParams).toASN1Primitive()), new ASN1Integer(getX()));
            }
            else
            {
                info = new PrivateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.dhKeyAgreement, new DHParameter(dhSpec.getP(), dhSpec.getG(), dhSpec.getL()).toASN1Primitive()), new ASN1Integer(getX()));
            }
            return info.getEncoded(ASN1Encoding.DER);
        }
        catch (Exception e)
        {              
            return null;
        }
    }

    public String toString()
    {
        return DHUtil.privateKeyToString("DH", x, new DHParameters(dhSpec.getP(), dhSpec.getG()));
    }

    public DHParameterSpec getParams()
    {
        return dhSpec;
    }

    public BigInteger getX()
    {
        return x;
    }

    DHPrivateKeyParameters engineGetKeyParameters()
    {
        if (dhPrivateKey != null)
        {
            return dhPrivateKey;
        }

        if (dhSpec instanceof DHDomainParameterSpec)
        {
            return new DHPrivateKeyParameters(x, ((DHDomainParameterSpec)dhSpec).getDomainParameters());
        }
        return new DHPrivateKeyParameters(x, new DHParameters(dhSpec.getP(), dhSpec.getG(), null, dhSpec.getL()));
    }

    public boolean equals(
        Object o)
    {
        if (!(o instanceof DHPrivateKey))
        {
            return false;
        }

        DHPrivateKey other = (DHPrivateKey)o;

        return this.getX().equals(other.getX())
            && this.getParams().getG().equals(other.getParams().getG())
            && this.getParams().getP().equals(other.getParams().getP())
            && this.getParams().getL() == other.getParams().getL();
    }

    public int hashCode()
    {
        return this.getX().hashCode() ^ this.getParams().getG().hashCode()
                ^ this.getParams().getP().hashCode() ^ this.getParams().getL();
    }

    public void setBagAttribute(
        ASN1ObjectIdentifier oid,
        ASN1Encodable attribute)
    {
        attrCarrier.setBagAttribute(oid, attribute);
    }

    public ASN1Encodable getBagAttribute(
        ASN1ObjectIdentifier oid)
    {
        return attrCarrier.getBagAttribute(oid);
    }

    public Enumeration getBagAttributeKeys()
    {
        return attrCarrier.getBagAttributeKeys();
    }

    private void readObject(
        ObjectInputStream   in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        this.dhSpec = new DHParameterSpec((BigInteger)in.readObject(), (BigInteger)in.readObject(), in.readInt());
        this.info = null;
        this.attrCarrier = new PKCS12BagAttributeCarrierImpl();
    }

    private void writeObject(
        ObjectOutputStream  out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(dhSpec.getP());
        out.writeObject(dhSpec.getG());
        out.writeInt(dhSpec.getL());
    }
}
