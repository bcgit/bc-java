package org.bouncycastle.jcajce.provider.asymmetric.ecgost;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.EllipticCurve;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl;
import org.bouncycastle.jce.ECGOST3410NamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPointEncoder;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECCurve;

public class BCECGOST3410PrivateKey
    implements ECPrivateKey, org.bouncycastle.jce.interfaces.ECPrivateKey, PKCS12BagAttributeCarrier, ECPointEncoder
{
    static final long serialVersionUID = 7245981689601667138L;

    private String algorithm = "ECGOST3410";
    private boolean withCompression;

    private transient ASN1Encodable gostParams;
    private transient BigInteger d;
    private transient ECParameterSpec ecSpec;
    private transient DERBitString publicKey;
    private transient PKCS12BagAttributeCarrierImpl attrCarrier = new PKCS12BagAttributeCarrierImpl();

    protected BCECGOST3410PrivateKey()
    {
    }

    public BCECGOST3410PrivateKey(
        ECPrivateKey key)
    {
        this.d = key.getS();
        this.algorithm = key.getAlgorithm();
        this.ecSpec = key.getParams();
    }

    public BCECGOST3410PrivateKey(
        org.bouncycastle.jce.spec.ECPrivateKeySpec spec)
    {
        this.d = spec.getD();

        if (spec.getParams() != null) // can be null if implicitlyCA
        {
            ECCurve curve = spec.getParams().getCurve();
            EllipticCurve ellipticCurve;

            ellipticCurve = EC5Util.convertCurve(curve, spec.getParams().getSeed());

            this.ecSpec = EC5Util.convertSpec(ellipticCurve, spec.getParams());
        }
        else
        {
            this.ecSpec = null;
        }
    }


    public BCECGOST3410PrivateKey(
        ECPrivateKeySpec spec)
    {
        this.d = spec.getS();
        this.ecSpec = spec.getParams();
    }

    public BCECGOST3410PrivateKey(
        BCECGOST3410PrivateKey key)
    {
        this.d = key.d;
        this.ecSpec = key.ecSpec;
        this.withCompression = key.withCompression;
        this.attrCarrier = key.attrCarrier;
        this.publicKey = key.publicKey;
        this.gostParams = key.gostParams;
    }

    public BCECGOST3410PrivateKey(
        String algorithm,
        ECPrivateKeyParameters params,
        BCECGOST3410PublicKey pubKey,
        ECParameterSpec spec)
    {
        this.algorithm = algorithm;
        this.d = params.getD();

        if (spec == null)
        {
            ECDomainParameters dp = params.getParameters();
            EllipticCurve ellipticCurve = EC5Util.convertCurve(dp.getCurve(), dp.getSeed());

            this.ecSpec = new ECParameterSpec(
                ellipticCurve,
                EC5Util.convertPoint(dp.getG()),
                dp.getN(),
                dp.getH().intValue());
        }
        else
        {
            this.ecSpec = spec;
        }

        this.gostParams = pubKey.getGostParams();

        publicKey = getPublicKeyDetails(pubKey);
    }

    public BCECGOST3410PrivateKey(
        String algorithm,
        ECPrivateKeyParameters params,
        BCECGOST3410PublicKey pubKey,
        org.bouncycastle.jce.spec.ECParameterSpec spec)
    {
        this.algorithm = algorithm;
        this.d = params.getD();

        if (spec == null)
        {
            ECDomainParameters dp = params.getParameters();
            EllipticCurve ellipticCurve = EC5Util.convertCurve(dp.getCurve(), dp.getSeed());

            this.ecSpec = new ECParameterSpec(
                ellipticCurve,
                EC5Util.convertPoint(dp.getG()),
                dp.getN(),
                dp.getH().intValue());
        }
        else
        {
            EllipticCurve ellipticCurve = EC5Util.convertCurve(spec.getCurve(), spec.getSeed());

            this.ecSpec = new ECParameterSpec(
                ellipticCurve,
                EC5Util.convertPoint(spec.getG()),
                spec.getN(),
                spec.getH().intValue());
        }

        this.gostParams = pubKey.getGostParams();

        publicKey = getPublicKeyDetails(pubKey);
    }

    public BCECGOST3410PrivateKey(
        String algorithm,
        ECPrivateKeyParameters params)
    {
        this.algorithm = algorithm;
        this.d = params.getD();
        this.ecSpec = null;
    }

    BCECGOST3410PrivateKey(
        PrivateKeyInfo info)
        throws IOException
    {
        populateFromPrivKeyInfo(info);
    }

    private void populateFromPrivKeyInfo(PrivateKeyInfo info)
        throws IOException
    {
        AlgorithmIdentifier pkAlg = info.getPrivateKeyAlgorithm(); 
        ASN1Encodable pkParams = pkAlg.getParameters();
        ASN1Primitive p = pkParams.toASN1Primitive();

        if (p instanceof ASN1Sequence && (ASN1Sequence.getInstance(p).size() == 2 || ASN1Sequence.getInstance(p).size() == 3))
        {
            GOST3410PublicKeyAlgParameters gParams = GOST3410PublicKeyAlgParameters.getInstance(pkParams);
            gostParams = gParams;

            ECNamedCurveParameterSpec spec = ECGOST3410NamedCurveTable.getParameterSpec(ECGOST3410NamedCurves.getName(gParams.getPublicKeyParamSet()));

            ECCurve curve = spec.getCurve();
            EllipticCurve ellipticCurve = EC5Util.convertCurve(curve, spec.getSeed());

            ecSpec = new ECNamedCurveSpec(
                ECGOST3410NamedCurves.getName(gParams.getPublicKeyParamSet()),
                ellipticCurve,
                EC5Util.convertPoint(spec.getG()),
                spec.getN(), spec.getH());

            ASN1Encodable privKey = info.parsePrivateKey();

            if (privKey instanceof ASN1Integer)
            {
                this.d = ASN1Integer.getInstance(privKey).getPositiveValue();
            }
            else
            {
                byte[] encVal = ASN1OctetString.getInstance(privKey).getOctets();
                byte[] dVal = new byte[encVal.length];

                for (int i = 0; i != encVal.length; i++)
                {
                    dVal[i] = encVal[encVal.length - 1 - i];
                }

                this.d = new BigInteger(1, dVal);
            }
        }
        else
        {
            // for backwards compatibility
            X962Parameters params = X962Parameters.getInstance(pkParams);

            if (params.isNamedCurve())
            {
                ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(params.getParameters());
                X9ECParameters ecP = ECUtil.getNamedCurveByOid(oid);

                if (ecP == null)
                {
                    throw new IllegalStateException();
                }

                String curveName = ECUtil.getCurveName(oid);

                EllipticCurve ellipticCurve = EC5Util.convertCurve(ecP.getCurve(), ecP.getSeed());

                ecSpec = new ECNamedCurveSpec(
                    curveName,
                    ellipticCurve,
                    EC5Util.convertPoint(ecP.getG()),
                    ecP.getN(),
                    ecP.getH());
            }
            else if (params.isImplicitlyCA())
            {
                ecSpec = null;
            }
            else
            {
                X9ECParameters ecP = X9ECParameters.getInstance(params.getParameters());
                EllipticCurve ellipticCurve = EC5Util.convertCurve(ecP.getCurve(), ecP.getSeed());

                this.ecSpec = new ECParameterSpec(
                    ellipticCurve,
                    EC5Util.convertPoint(ecP.getG()),
                    ecP.getN(),
                    ecP.getH().intValue());
            }

            ASN1Encodable privKey = info.parsePrivateKey();
            if (privKey instanceof ASN1Integer)
            {
                ASN1Integer derD = ASN1Integer.getInstance(privKey);

                this.d = derD.getValue();
            }
            else
            {
                org.bouncycastle.asn1.sec.ECPrivateKey ec = org.bouncycastle.asn1.sec.ECPrivateKey.getInstance(privKey);

                this.d = ec.getKey();
                this.publicKey = ec.getPublicKey();
            }
        }
    }

    public String getAlgorithm()
    {
        return algorithm;
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
        if (gostParams != null)
        {
            byte[] encKey = new byte[32];

            extractBytes(encKey, 0, this.getS());

            try
            {
                PrivateKeyInfo info = new PrivateKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_2001, gostParams), new DEROctetString(encKey));

                return info.getEncoded(ASN1Encoding.DER);
            }
            catch (IOException e)
            {
                return null;
            }
        }
        else
        {
            X962Parameters params;
            int orderBitLength;

            if (ecSpec instanceof ECNamedCurveSpec)
            {
                ASN1ObjectIdentifier curveOid = ECUtil.getNamedCurveOid(((ECNamedCurveSpec)ecSpec).getName());
                if (curveOid == null)  // guess it's the OID
                {
                    curveOid = new ASN1ObjectIdentifier(((ECNamedCurveSpec)ecSpec).getName());
                }
                params = new X962Parameters(curveOid);
                orderBitLength = ECUtil.getOrderBitLength(BouncyCastleProvider.CONFIGURATION, ecSpec.getOrder(), this.getS());
            }
            else if (ecSpec == null)
            {
                params = new X962Parameters(DERNull.INSTANCE);
                orderBitLength = ECUtil.getOrderBitLength(BouncyCastleProvider.CONFIGURATION, null, this.getS());
            }
            else
            {
                ECCurve curve = EC5Util.convertCurve(ecSpec.getCurve());

                X9ECParameters ecP = new X9ECParameters(
                    curve,
                    new X9ECPoint(EC5Util.convertPoint(curve, ecSpec.getGenerator()), withCompression),
                    ecSpec.getOrder(),
                    BigInteger.valueOf(ecSpec.getCofactor()),
                    ecSpec.getCurve().getSeed());

                params = new X962Parameters(ecP);
                orderBitLength = ECUtil.getOrderBitLength(BouncyCastleProvider.CONFIGURATION, ecSpec.getOrder(), this.getS());
            }

            PrivateKeyInfo info;
            org.bouncycastle.asn1.sec.ECPrivateKey keyStructure;

            if (publicKey != null)
            {
                keyStructure = new org.bouncycastle.asn1.sec.ECPrivateKey(orderBitLength, this.getS(), publicKey, params);
            }
            else
            {
                keyStructure = new org.bouncycastle.asn1.sec.ECPrivateKey(orderBitLength, this.getS(), params);
            }

            try
            {
                info = new PrivateKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_2001, params.toASN1Primitive()), keyStructure.toASN1Primitive());

                return info.getEncoded(ASN1Encoding.DER);
            }
            catch (IOException e)
            {
                return null;
            }
        }
    }

    private void extractBytes(byte[] encKey, int offSet, BigInteger bI)
    {
        byte[] val = bI.toByteArray();
        if (val.length < 32)
        {
            byte[] tmp = new byte[32];
            System.arraycopy(val, 0, tmp, tmp.length - val.length, val.length);
            val = tmp;
        }

        for (int i = 0; i != 32; i++)
        {
            encKey[offSet + i] = val[val.length - 1 - i];
        }
    }

    public ECParameterSpec getParams()
    {
        return ecSpec;
    }

    public org.bouncycastle.jce.spec.ECParameterSpec getParameters()
    {
        if (ecSpec == null)
        {
            return null;
        }

        return EC5Util.convertSpec(ecSpec);
    }

    org.bouncycastle.jce.spec.ECParameterSpec engineGetSpec()
    {
        if (ecSpec != null)
        {
            return EC5Util.convertSpec(ecSpec);
        }

        return BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();
    }

    public BigInteger getS()
    {
        return d;
    }

    public BigInteger getD()
    {
        return d;
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

    public void setPointFormat(String style)
    {
        withCompression = !("UNCOMPRESSED".equalsIgnoreCase(style));
    }

    public boolean equals(Object o)
    {
        if (!(o instanceof BCECGOST3410PrivateKey))
        {
            return false;
        }

        BCECGOST3410PrivateKey other = (BCECGOST3410PrivateKey)o;

        return getD().equals(other.getD()) && (engineGetSpec().equals(other.engineGetSpec()));
    }

    public int hashCode()
    {
        return getD().hashCode() ^ engineGetSpec().hashCode();
    }

    public String toString()
    {
        return ECUtil.privateKeyToString(algorithm, d, engineGetSpec());
    }

    private DERBitString getPublicKeyDetails(BCECGOST3410PublicKey pub)
    {
        try
        {
            SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(pub.getEncoded()));

            return info.getPublicKeyData();
        }
        catch (IOException e)
        {   // should never happen
            return null;
        }
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        byte[] enc = (byte[])in.readObject();

        populateFromPrivKeyInfo(PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(enc)));

        this.attrCarrier = new PKCS12BagAttributeCarrierImpl();
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}
