package org.bouncycastle.jcajce.provider.asymmetric.ecgost;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECGOST3410Parameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
import org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
import org.bouncycastle.jce.ECGOST3410NamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPointEncoder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECCurve;

public class BCECGOST3410PublicKey
    implements ECPublicKey, org.bouncycastle.jce.interfaces.ECPublicKey, ECPointEncoder
{
    static final long serialVersionUID = 7026240464295649314L;

    private String algorithm = "ECGOST3410";
    private boolean withCompression;

    private transient ECPublicKeyParameters   ecPublicKey;
    private transient ECParameterSpec ecSpec;
    private transient ASN1Encodable gostParams;

    public BCECGOST3410PublicKey(
        BCECGOST3410PublicKey key)
    {
        this.ecPublicKey = key.ecPublicKey;
        this.ecSpec = key.ecSpec;
        this.withCompression = key.withCompression;
        this.gostParams = key.gostParams;
    }

    public BCECGOST3410PublicKey(
        ECPublicKeySpec spec)
    {
        this.ecSpec = spec.getParams();
        this.ecPublicKey = new ECPublicKeyParameters(EC5Util.convertPoint(ecSpec, spec.getW()), EC5Util.getDomainParameters(null, spec.getParams()));
    }

    public BCECGOST3410PublicKey(
        org.bouncycastle.jce.spec.ECPublicKeySpec spec,
        ProviderConfiguration configuration)
    {
        if (spec.getParams() != null) // can be null if implictlyCa
        {
            ECCurve curve = spec.getParams().getCurve();
            EllipticCurve ellipticCurve = EC5Util.convertCurve(curve, spec.getParams().getSeed());

            // this may seem a little long-winded but it's how we pick up the custom curve.
            this.ecPublicKey = new ECPublicKeyParameters(
                spec.getQ(), ECUtil.getDomainParameters(configuration, spec.getParams()));
            this.ecSpec = EC5Util.convertSpec(ellipticCurve, spec.getParams());
        }
        else
        {
            org.bouncycastle.jce.spec.ECParameterSpec s = configuration.getEcImplicitlyCa();

            this.ecPublicKey = new ECPublicKeyParameters(s.getCurve().createPoint(spec.getQ().getAffineXCoord().toBigInteger(), spec.getQ().getAffineYCoord().toBigInteger()), EC5Util.getDomainParameters(configuration, (ECParameterSpec)null));
            this.ecSpec = null;
        }
    }

    public BCECGOST3410PublicKey(
        String algorithm,
        ECPublicKeyParameters params,
        ECParameterSpec spec)
    {
        ECDomainParameters      dp = params.getParameters();

        if (dp instanceof ECGOST3410Parameters)
        {
            ECGOST3410Parameters p = (ECGOST3410Parameters)dp;

            this.gostParams = new GOST3410PublicKeyAlgParameters(p.getPublicKeyParamSet(),
                                                p.getDigestParamSet(), p.getEncryptionParamSet());
        }

        this.algorithm = algorithm;
        this.ecPublicKey = params;

        if (spec == null)
        {
            EllipticCurve ellipticCurve = EC5Util.convertCurve(dp.getCurve(), dp.getSeed());

            this.ecSpec = createSpec(ellipticCurve, dp);
        }
        else
        {
            this.ecSpec = spec;
        }
    }

    public BCECGOST3410PublicKey(
        String algorithm,
        ECPublicKeyParameters params,
        org.bouncycastle.jce.spec.ECParameterSpec spec)
    {
        ECDomainParameters dp = params.getParameters();

        this.algorithm = algorithm;
        this.ecPublicKey = params;

        if (spec == null)
        {
            EllipticCurve ellipticCurve = EC5Util.convertCurve(dp.getCurve(), dp.getSeed());

            this.ecSpec = createSpec(ellipticCurve, dp);
        }
        else
        {
            EllipticCurve ellipticCurve = EC5Util.convertCurve(spec.getCurve(), spec.getSeed());

            this.ecSpec = EC5Util.convertSpec(ellipticCurve, spec);
        }
    }

    /*
     * called for implicitCA
     */
    public BCECGOST3410PublicKey(
        String algorithm,
        ECPublicKeyParameters params)
    {
        this.algorithm = algorithm;
        this.ecPublicKey = params;
        this.ecSpec = null;
    }

    private ECParameterSpec createSpec(EllipticCurve ellipticCurve, ECDomainParameters dp)
    {
        return new ECParameterSpec(
            ellipticCurve,
            EC5Util.convertPoint(dp.getG()),
            dp.getN(),
            dp.getH().intValue());
    }

    public BCECGOST3410PublicKey(
        ECPublicKey key)
    {
        this.algorithm = key.getAlgorithm();
        this.ecSpec = key.getParams();
        this.ecPublicKey = new ECPublicKeyParameters(EC5Util.convertPoint(this.ecSpec, key.getW()), EC5Util.getDomainParameters(null, key.getParams()));
    }

    BCECGOST3410PublicKey(
        SubjectPublicKeyInfo info)
    {
        populateFromPubKeyInfo(info);
    }

    private void populateFromPubKeyInfo(SubjectPublicKeyInfo info)
    {
        DERBitString bits = info.getPublicKeyData();
        ASN1OctetString key;
        this.algorithm = "ECGOST3410";

        try
        {
            key = (ASN1OctetString)ASN1Primitive.fromByteArray(bits.getBytes());
        }
        catch (IOException ex)
        {
            throw new IllegalArgumentException("error recovering public key");
        }

        byte[] keyEnc = key.getOctets();

        byte[] x9Encoding = new byte[65];
        x9Encoding[0] = 0x04;
        for (int i = 1; i <= 32; ++i)
        {
            x9Encoding[i     ] = keyEnc[32 - i];
            x9Encoding[i + 32] = keyEnc[64 - i];
        }

        ASN1ObjectIdentifier paramOID;

        if (info.getAlgorithm().getParameters() instanceof ASN1ObjectIdentifier)
        {
            paramOID = ASN1ObjectIdentifier.getInstance(info.getAlgorithm().getParameters());
            gostParams = paramOID;
        }
        else
        {
            GOST3410PublicKeyAlgParameters params = GOST3410PublicKeyAlgParameters.getInstance(info.getAlgorithm().getParameters());
            gostParams = params;
            paramOID = params.getPublicKeyParamSet();

        }

        ECNamedCurveParameterSpec spec = ECGOST3410NamedCurveTable.getParameterSpec(ECGOST3410NamedCurves.getName(paramOID));

        ECCurve curve = spec.getCurve();
        EllipticCurve ellipticCurve = EC5Util.convertCurve(curve, spec.getSeed());

        this.ecPublicKey = new ECPublicKeyParameters(curve.decodePoint(x9Encoding), ECUtil.getDomainParameters(null, spec));

        this.ecSpec = new ECNamedCurveSpec(
            ECGOST3410NamedCurves.getName(paramOID),
            ellipticCurve,
            EC5Util.convertPoint(spec.getG()),
            spec.getN(), spec.getH());
    }

    public String getAlgorithm()
    {
        return algorithm;
    }

    public String getFormat()
    {
        return "X.509";
    }

    public byte[] getEncoded()
    {
        ASN1Encodable params;
        SubjectPublicKeyInfo info;

        params = getGostParams();

        if (params == null)
        {
            if (ecSpec instanceof ECNamedCurveSpec)
            {
                params = new GOST3410PublicKeyAlgParameters(
                    ECGOST3410NamedCurves.getOID(((ECNamedCurveSpec)ecSpec).getName()),
                    CryptoProObjectIdentifiers.gostR3411_94_CryptoProParamSet);
            }
            else
            {   // strictly speaking this may not be applicable...
                ECCurve curve = EC5Util.convertCurve(ecSpec.getCurve());

                X9ECParameters ecP = new X9ECParameters(
                    curve,
                    new X9ECPoint(EC5Util.convertPoint(curve, ecSpec.getGenerator()), withCompression),
                    ecSpec.getOrder(),
                    BigInteger.valueOf(ecSpec.getCofactor()),
                    ecSpec.getCurve().getSeed());

                params = new X962Parameters(ecP);
            }
        }

        BigInteger bX = this.ecPublicKey.getQ().getAffineXCoord().toBigInteger();
        BigInteger bY = this.ecPublicKey.getQ().getAffineYCoord().toBigInteger();

        byte[] encKey = new byte[64];
        extractBytes(encKey, 0, bX);
        extractBytes(encKey, 32, bY);

        try
        {
            info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_2001, params), new DEROctetString(encKey));
        }
        catch (IOException e)
        {
            return null;
        }

        return KeyUtil.getEncodedSubjectPublicKeyInfo(info);
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
        if (ecSpec == null)     // implictlyCA
        {
            return null;
        }

        return EC5Util.convertSpec(ecSpec);
    }

    public ECPoint getW()
    {
        return EC5Util.convertPoint(ecPublicKey.getQ());
    }

    public org.bouncycastle.math.ec.ECPoint getQ()
    {
        if (ecSpec == null)
        {
            return ecPublicKey.getQ().getDetachedPoint();
        }

        return ecPublicKey.getQ();
    }

    ECPublicKeyParameters engineGetKeyParameters()
    {
        return ecPublicKey;
    }

    org.bouncycastle.jce.spec.ECParameterSpec engineGetSpec()
    {
        if (ecSpec != null)
        {
            return EC5Util.convertSpec(ecSpec);
        }

        return BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();
    }

    public String toString()
    {
        return ECUtil.publicKeyToString(algorithm, ecPublicKey.getQ(), engineGetSpec());
    }

    public void setPointFormat(String style)
    {
        withCompression = !("UNCOMPRESSED".equalsIgnoreCase(style));
    }

    public boolean equals(Object o)
    {
        if (!(o instanceof BCECGOST3410PublicKey))
        {
            return false;
        }

        BCECGOST3410PublicKey other = (BCECGOST3410PublicKey)o;

        return ecPublicKey.getQ().equals(other.ecPublicKey.getQ()) && (engineGetSpec().equals(other.engineGetSpec()));
    }

    public int hashCode()
    {
        return ecPublicKey.getQ().hashCode() ^ engineGetSpec().hashCode();
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        byte[] enc = (byte[])in.readObject();

        populateFromPubKeyInfo(SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(enc)));
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }

    ASN1Encodable getGostParams()
    {
        if (gostParams == null && ecSpec instanceof ECNamedCurveSpec)
        {
            this.gostParams = new GOST3410PublicKeyAlgParameters(
                ECGOST3410NamedCurves.getOID(((ECNamedCurveSpec)ecSpec).getName()),
                CryptoProObjectIdentifiers.gostR3411_94_CryptoProParamSet);
        }

        return gostParams;
    }
}
