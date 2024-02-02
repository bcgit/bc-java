package org.bouncycastle.its.bc;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.its.ITSCertificate;
import org.bouncycastle.its.operator.ITSContentVerifierProvider;
import org.bouncycastle.oer.OEREncoder;
import org.bouncycastle.oer.its.ieee1609dot2.ToBeSignedCertificate;
import org.bouncycastle.oer.its.ieee1609dot2.VerificationKeyIndicator;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.PublicVerificationKey;
import org.bouncycastle.oer.its.template.ieee1609dot2.IEEE1609dot2;
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
            issuer.toASN1Structure().getToBeSigned();
        VerificationKeyIndicator vki = toBeSignedCertificate.getVerifyKeyIndicator();

        if (vki.getVerificationKeyIndicator() instanceof PublicVerificationKey)
        {
            PublicVerificationKey pvi = PublicVerificationKey.getInstance(vki.getVerificationKeyIndicator());
            sigChoice = pvi.getChoice();

            switch (pvi.getChoice())
            {
            case PublicVerificationKey.ecdsaNistP256:
                digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
                break;
            case PublicVerificationKey.ecdsaBrainpoolP256r1:
                digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
                break;
            case PublicVerificationKey.ecdsaBrainpoolP384r1:
                digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384);
                break;
            default:
                throw new IllegalStateException("unknown key type");
            }

            pubParams = (ECPublicKeyParameters)new BcITSPublicVerificationKey(pvi).getKey();
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
            byte[] enc = OEREncoder.toByteArray(issuer.toASN1Structure().getToBeSigned(), IEEE1609dot2.ToBeSignedCertificate.build());
            digest.update(enc, 0, enc.length);
            digest.doFinal(parentTBSDigest, 0);
        }

        final OutputStream os = new OutputStream()
        {
            public void write(int b)
                throws IOException
            {
                digest.update((byte)b);
            }

            public void write(byte[] b)
                throws IOException
            {
                digest.update(b, 0, b.length);
            }

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

                // System.out.println("Verify: "+ Hex.toHexString(clientCertDigest));


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

                    // System.out.println("Empty: "+Hex.toHexString(empty));

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
