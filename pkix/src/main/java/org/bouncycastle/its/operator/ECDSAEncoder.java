package org.bouncycastle.its.operator;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EccP256CurvePoint;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EccP384CurvePoint;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EcdsaP256Signature;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EcdsaP384Signature;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Signature;
import org.bouncycastle.util.BigIntegers;

public class ECDSAEncoder
{
    /**
     * Return the X9.62 DER encoding of the r and s values in the passed in IEEE 1609.2 signature.
     * <p>
     * IEEE 1609.2 sec. 6.3.29 and sec. 6.3.30 represent r as an EccP256CurvePoint (EccP384CurvePoint)
     * "indicating the selection x-only", so any other choice is refused: compressed-y-0 and
     * compressed-y-1 carry the same x octets, which would otherwise give one signature several
     * interchangeable encodings, and fill and uncompressed carry no octet string to read at all.
     * </p>
     *
     * @param signature the signature to convert.
     * @return the DER encoded SEQUENCE of r and s.
     */
    public static byte[] toX962(Signature signature)
    {
        byte[] r;
        byte[] s;
        if (signature.getChoice() == Signature.ecdsaNistP256Signature || signature.getChoice() == Signature.ecdsaBrainpoolP256r1Signature)
        {
            EcdsaP256Signature sig = EcdsaP256Signature.getInstance(signature.getSignature());
            EccP256CurvePoint rSig = sig.getRSig();
            if (rSig.getChoice() != EccP256CurvePoint.xonly)
            {
                throw new IllegalArgumentException("rSig must be of form x-only");
            }
            r = ASN1OctetString.getInstance(rSig.getEccp256CurvePoint()).getOctets();
            s = sig.getSSig().getOctets();
        }
        else
        {
            EcdsaP384Signature sig = EcdsaP384Signature.getInstance(signature.getSignature());
            EccP384CurvePoint rSig = sig.getRSig();
            if (rSig.getChoice() != EccP384CurvePoint.xonly)
            {
                throw new IllegalArgumentException("rSig must be of form x-only");
            }
            r = ASN1OctetString.getInstance(rSig.getEccP384CurvePoint()).getOctets();
            s = sig.getSSig().getOctets();
        }

        try
        {
            return new DERSequence(
                new ASN1Integer(BigIntegers.fromUnsignedByteArray(r)),
                new ASN1Integer(BigIntegers.fromUnsignedByteArray(s))
            ).getEncoded();
        }
        catch (IOException ioException)
        {
            throw new RuntimeException("der encoding r & s");
        }
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
