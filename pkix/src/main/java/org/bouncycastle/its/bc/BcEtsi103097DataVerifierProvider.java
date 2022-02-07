package org.bouncycastle.its.bc;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.its.operator.ETSIDataVerifierProvider;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Signature;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDefaultDigestProvider;

public class BcEtsi103097DataVerifierProvider
    implements ETSIDataVerifierProvider
{

    private final ASN1ObjectIdentifier curveID;
    private final AlgorithmIdentifier digestAlgo;
    private final ECPublicKeyParameters pubParams;
    private final int sigChoice;

    public BcEtsi103097DataVerifierProvider(ECPublicKeyParameters publicKey)
    {

        this.curveID = ((ECNamedDomainParameters)publicKey.getParameters()).getName();
        if (curveID.equals(SECObjectIdentifiers.secp256r1))
        {
            digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
            sigChoice = Signature.ecdsaNistP256Signature;
        }
        else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP256r1))
        {
            digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
            sigChoice = Signature.ecdsaBrainpoolP256r1Signature;
        }
        else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP384r1))
        {
            digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384);
            sigChoice = Signature.ecdsaBrainpoolP384r1Signature;
        }
        else
        {
            throw new IllegalArgumentException("unknown key type");
        }

        this.pubParams = publicKey;

    }

    public ContentVerifier getContentVerifier(int signatureChoice)
        throws OperatorCreationException
    {

        if (sigChoice != signatureChoice)
        {
            throw new OperatorCreationException("wrong verifier for algorithm: " + signatureChoice);
        }

        final Digest digest = BcDefaultDigestProvider.INSTANCE.get(digestAlgo);

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

        final DSADigestSigner signer = new DSADigestSigner(new ECDSASigner(), digest);
        signer.init(false, pubParams);

        return new ContentVerifier()
        {
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

                return signer.verifySignature(expected);
            }
        };
    }
}
