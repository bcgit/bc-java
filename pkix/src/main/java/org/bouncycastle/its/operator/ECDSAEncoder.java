package org.bouncycastle.its.operator;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EccP256CurvePoint;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EccP384CurvePoint;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EcdsaP256Signature;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EcdsaP384Signature;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Point256;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Point384;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Signature;
import org.bouncycastle.util.BigIntegers;

public class ECDSAEncoder
{
    /**
     * Return the X9.62 DER encoding of the r and s values in the passed in IEEE 1609.2 signature.
     * <p>
     * IEEE 1609.2 (EcdsaP256Signature, EcdsaP384Signature) allows rSig to carry either the integer r, as the
     * choice x-only, or the point R, as compressed-y-0, compressed-y-1 or uncompressed at the sender's discretion.
     * In the latter case r is the x coordinate of R reduced mod n. The choice fill carries no r value and is rejected.
     * </p>
     *
     * @param signature the signature to convert.
     * @return the DER encoded SEQUENCE of r and s.
     */
    public static byte[] toX962(Signature signature)
    {
        BigInteger r;
        byte[] s;
        if (signature.getChoice() == Signature.ecdsaNistP256Signature || signature.getChoice() == Signature.ecdsaBrainpoolP256r1Signature)
        {
            EcdsaP256Signature sig = EcdsaP256Signature.getInstance(signature.getSignature());
            r = getR(signature.getChoice(), sig.getRSig());
            s = sig.getSSig().getOctets();
        }
        else
        {
            EcdsaP384Signature sig = EcdsaP384Signature.getInstance(signature.getSignature());
            r = getR(signature.getChoice(), sig.getRSig());
            s = sig.getSSig().getOctets();
        }

        try
        {
            return new DERSequence(
                new ASN1Integer(r),
                new ASN1Integer(BigIntegers.fromUnsignedByteArray(s))
            ).getEncoded();
        }
        catch (IOException ioException)
        {
            throw new RuntimeException("der encoding r & s");
        }
    }

    /**
     * Return the passed in IEEE 1609.2 signature with rSig in the form x-only.
     * <p>
     * IEEE 1609.2 (EcdsaP256Signature, EcdsaP384Signature): "If this structure is encoded for hashing, the
     * EccP256CurvePoint in rSig shall be taken to be of form x-only." - this is the form to use when a structure
     * carrying a signature, such as a certificate, is hashed to calculate a HashedId8.
     * </p>
     *
     * @param signature the signature to convert.
     * @return signature if rSig is already of form x-only, otherwise an equivalent signature with rSig of form x-only.
     */
    public static Signature toXOnly(Signature signature)
    {
        if (signature.getChoice() == Signature.ecdsaNistP256Signature || signature.getChoice() == Signature.ecdsaBrainpoolP256r1Signature)
        {
            EcdsaP256Signature sig = EcdsaP256Signature.getInstance(signature.getSignature());
            if (sig.getRSig().getChoice() == EccP256CurvePoint.xonly)
            {
                return signature;
            }

            byte[] r = BigIntegers.asUnsignedByteArray(32, getR(signature.getChoice(), sig.getRSig()));
            return new Signature(signature.getChoice(), new EcdsaP256Signature(EccP256CurvePoint.xOnly(r), sig.getSSig()));
        }
        else
        {
            EcdsaP384Signature sig = EcdsaP384Signature.getInstance(signature.getSignature());
            if (sig.getRSig().getChoice() == EccP384CurvePoint.xonly)
            {
                return signature;
            }

            byte[] r = BigIntegers.asUnsignedByteArray(48, getR(signature.getChoice(), sig.getRSig()));
            return new Signature(signature.getChoice(), new EcdsaP384Signature(EccP384CurvePoint.xOnly(r), sig.getSSig()));
        }
    }

    private static BigInteger getR(int sigChoice, EccP256CurvePoint rSig)
    {
        switch (rSig.getChoice())
        {
        case EccP256CurvePoint.xonly:
            return BigIntegers.fromUnsignedByteArray(ASN1OctetString.getInstance(rSig.getEccp256CurvePoint()).getOctets());
        case EccP256CurvePoint.compressedY0:
        case EccP256CurvePoint.compressedY1:
            return reduceX(sigChoice, ASN1OctetString.getInstance(rSig.getEccp256CurvePoint()).getOctets());
        case EccP256CurvePoint.uncompressedP256:
            return reduceX(sigChoice, Point256.getInstance(rSig.getEccp256CurvePoint()).getX().getOctets());
        default:
            throw new IllegalArgumentException("rSig choice " + rSig.getChoice() + " does not carry an r value");
        }
    }

    private static BigInteger getR(int sigChoice, EccP384CurvePoint rSig)
    {
        switch (rSig.getChoice())
        {
        case EccP384CurvePoint.xonly:
            return BigIntegers.fromUnsignedByteArray(ASN1OctetString.getInstance(rSig.getEccP384CurvePoint()).getOctets());
        case EccP384CurvePoint.compressedY0:
        case EccP384CurvePoint.compressedY1:
            return reduceX(sigChoice, ASN1OctetString.getInstance(rSig.getEccP384CurvePoint()).getOctets());
        case EccP384CurvePoint.uncompressedP384:
            return reduceX(sigChoice, Point384.getInstance(rSig.getEccP384CurvePoint()).getX().getOctets());
        default:
            throw new IllegalArgumentException("rSig choice " + rSig.getChoice() + " does not carry an r value");
        }
    }

    // the x coordinate of R is an integer mod p, r is that integer mod n (IEEE 1609.2, EcdsaP256Signature NOTE)
    private static BigInteger reduceX(int sigChoice, byte[] x)
    {
        ASN1ObjectIdentifier curveID;
        switch (sigChoice)
        {
        case Signature.ecdsaNistP256Signature:
            curveID = SECObjectIdentifiers.secp256r1;
            break;
        case Signature.ecdsaBrainpoolP256r1Signature:
            curveID = TeleTrusTObjectIdentifiers.brainpoolP256r1;
            break;
        case Signature.ecdsaBrainpoolP384r1Signature:
            curveID = TeleTrusTObjectIdentifiers.brainpoolP384r1;
            break;
        default:
            throw new IllegalArgumentException("unknown signature choice " + sigChoice);
        }

        return BigIntegers.fromUnsignedByteArray(x).mod(ECNamedCurveTable.getByOID(curveID).getN());
    }

    public static Signature toITS(ASN1ObjectIdentifier curveID, byte[] dsaEncoding)
    {
        ASN1Sequence asn1Sig = ASN1Sequence.getInstance(dsaEncoding);

        if (curveID.equals(SECObjectIdentifiers.secp256r1))
        {
            return new Signature(Signature.ecdsaNistP256Signature, new EcdsaP256Signature(
                new EccP256CurvePoint(EccP256CurvePoint.xonly, new DEROctetString(BigIntegers.asUnsignedByteArray(32, ASN1Integer.getInstance(asn1Sig.getObjectAt(0)).getValue()))),
                new DEROctetString(BigIntegers.asUnsignedByteArray(32, ASN1Integer.getInstance(asn1Sig.getObjectAt(1)).getValue()))));
        }
        if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP256r1))
        {
            return new Signature(Signature.ecdsaBrainpoolP256r1Signature, new EcdsaP256Signature(
                new EccP256CurvePoint(EccP256CurvePoint.xonly, new DEROctetString(BigIntegers.asUnsignedByteArray(32, ASN1Integer.getInstance(asn1Sig.getObjectAt(0)).getValue()))),
                new DEROctetString(BigIntegers.asUnsignedByteArray(32, ASN1Integer.getInstance(asn1Sig.getObjectAt(1)).getValue()))));
        }
        if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP384r1))
        {
            return new Signature(Signature.ecdsaBrainpoolP384r1Signature, new EcdsaP384Signature(
                new EccP384CurvePoint(EccP384CurvePoint.xonly, new DEROctetString(BigIntegers.asUnsignedByteArray(48, ASN1Integer.getInstance(asn1Sig.getObjectAt(0)).getValue()))),
                new DEROctetString(BigIntegers.asUnsignedByteArray(48, ASN1Integer.getInstance(asn1Sig.getObjectAt(1)).getValue()))));
        }

        throw new IllegalArgumentException("unknown curveID");
    }
}
