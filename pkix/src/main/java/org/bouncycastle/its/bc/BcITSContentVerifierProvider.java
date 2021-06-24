package org.bouncycastle.its.bc;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.its.ITSCertificate;
import org.bouncycastle.its.operator.ITSContentVerifierProvider;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.oer.OEREncoder;
import org.bouncycastle.oer.its.EccCurvePoint;
import org.bouncycastle.oer.its.EccP256CurvePoint;
import org.bouncycastle.oer.its.EccP384CurvePoint;
import org.bouncycastle.oer.its.PublicVerificationKey;
import org.bouncycastle.oer.its.ToBeSignedCertificate;
import org.bouncycastle.oer.its.VerificationKeyIndicator;
import org.bouncycastle.oer.its.template.IEEE1609dot2;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDefaultDigestProvider;
import org.bouncycastle.util.Arrays;

public class BcITSContentVerifierProvider
    implements ITSContentVerifierProvider
{
    private final ITSCertificate issuer;
    private final byte[] parentData;
    private final AlgorithmIdentifier digestAlgo;
    private final ECPublicKeyParameters pubParams;
    private final int sigChoice;

    public BcITSContentVerifierProvider(ITSCertificate issuer)
        throws IOException
    {
        this.issuer = issuer;
        this.parentData = issuer.getEncoded();
        ToBeSignedCertificate toBeSignedCertificate =
            issuer.toASN1Structure().getCertificateBase().getToBeSignedCertificate();
        VerificationKeyIndicator vki = toBeSignedCertificate.getVerificationKeyIndicator();

        if (vki.getObject() instanceof PublicVerificationKey)
        {
            PublicVerificationKey pvi = PublicVerificationKey.getInstance(vki.getObject());
            X9ECParameters params;

            sigChoice = pvi.getChoice();

            switch (pvi.getChoice())
            {
            case PublicVerificationKey.ecdsaNistP256:
                params = NISTNamedCurves.getByOID(SECObjectIdentifiers.secp256r1);
                digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
                break;
            case PublicVerificationKey.ecdsaBrainpoolP256r1:
                params = TeleTrusTNamedCurves.getByOID(TeleTrusTObjectIdentifiers.brainpoolP256r1);
                digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
                break;
            case PublicVerificationKey.ecdsaBrainpoolP384r1:
                params = TeleTrusTNamedCurves.getByOID(TeleTrusTObjectIdentifiers.brainpoolP384r1);
                digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384);
                break;
            default:
                throw new IllegalStateException("unknown key type");
            }
            ECCurve curve = params.getCurve();

            ASN1Encodable pviCurvePoint = pvi.getCurvePoint();
            final EccCurvePoint itsPoint;
            if (pviCurvePoint instanceof EccCurvePoint)
            {
                itsPoint = (EccCurvePoint)pvi.getCurvePoint();
            }
            else
            {
                throw new IllegalStateException("extension to public verification key not supported");
            }

            byte[] key;

            if (itsPoint instanceof EccP256CurvePoint)
            {
                key = itsPoint.getEncodedPoint();
            }
            else if (itsPoint instanceof EccP384CurvePoint)
            {
                key = itsPoint.getEncodedPoint();
            }
            else
            {
                throw new IllegalStateException("unknown key type");
            }

            ECPoint point = curve.decodePoint(key).normalize();
            pubParams = new ECPublicKeyParameters(point,
                new ECDomainParameters(
                    params.getCurve(),
                    params.getG(),
                    params.getN(),
                    params.getH(),
                    params.getSeed()));
        }
        else
        {
            throw new IllegalStateException("not public verification key");
        }
    }

    public ITSCertificate getAssociatedCertificate()
    {
        return issuer;
    }

    public boolean hasAssociatedCertificate()
    {
        return issuer != null;
    }

    @Override
    public ContentVerifier get(final int verifierAlgorithmIdentifier)
        throws OperatorCreationException
    {
        if (sigChoice != verifierAlgorithmIdentifier)
        {
            throw new OperatorCreationException("wrong verifier for algorithm: " + verifierAlgorithmIdentifier);
        }

        final Digest digest = BcDefaultDigestProvider.INSTANCE.get(digestAlgo);

        final byte[] parentDigest = new byte[digest.getDigestSize()];

        digest.update(parentData, 0, parentData.length);

        digest.doFinal(parentDigest, 0);

        final byte[] parentTBSDigest = issuer.getIssuer().isSelf() ? new byte[digest.getDigestSize()] : null;

        if (parentTBSDigest != null)
        {
            byte[] enc = OEREncoder.toByteArray(issuer.toASN1Structure().getCertificateBase().getToBeSignedCertificate(), IEEE1609dot2.tbsCertificate);
            digest.update(enc, 0, enc.length);
            digest.doFinal(parentTBSDigest, 0);
        }

        final OutputStream os = new OutputStream()
        {
            @Override
            public void write(int b)
                throws IOException
            {
                digest.update((byte)b);
            }

            @Override
            public void write(byte[] b)
                throws IOException
            {
                digest.update(b, 0, b.length);
            }

            @Override
            public void write(byte[] b, int off, int len)
                throws IOException
            {
                digest.update(b, off, len);
            }
        };

        return new ContentVerifier()
        {
            final DSADigestSigner signer = new DSADigestSigner(new ECDSASigner(),
                BcDefaultDigestProvider.INSTANCE.get(digestAlgo));

            public AlgorithmIdentifier getAlgorithmIdentifier()
            {
                return null;
            }

            public OutputStream getOutputStream()
            {
                return os;
            }

            public boolean verify(byte[] expected)
            {
                byte[] clientCertDigest = new byte[digest.getDigestSize()];

                digest.doFinal(clientCertDigest, 0);

                signer.init(false, pubParams);

                signer.update(clientCertDigest, 0, clientCertDigest.length);

                //
                // if this is true we are a self signed certificate verifying our own
                // signature.
                //
                if (parentTBSDigest != null && Arrays.areEqual(clientCertDigest, parentTBSDigest))
                {
                    byte[] empty = new byte[digest.getDigestSize()];
                    digest.doFinal(empty, 0);
                    signer.update(empty, 0, empty.length);
                }
                else
                {
                    signer.update(parentDigest, 0, parentDigest.length);
                }

                return signer.verifySignature(expected);
            }
        };
    }
}
