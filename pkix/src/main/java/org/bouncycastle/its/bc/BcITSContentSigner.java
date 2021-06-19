package org.bouncycastle.its.bc;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.io.DigestOutputStream;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.its.ITSCertificate;
import org.bouncycastle.its.ITSContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDefaultDigestProvider;

public class BcITSContentSigner
    implements ITSContentSigner
{
    private final ECPrivateKeyParameters privKey;
    private final ITSCertificate signerCert;
    private final AlgorithmIdentifier digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
    private final Digest digest;
    private final byte[] parentData;
    private final ASN1ObjectIdentifier curveID;

    public BcITSContentSigner(ECPrivateKeyParameters privKey, ITSCertificate signerCert)
    {
        this.privKey = privKey;
        this.curveID = ((ECNamedDomainParameters)privKey.getParameters()).getName();
        this.signerCert = signerCert;
        try
        {
            this.digest = BcDefaultDigestProvider.INSTANCE.get(digestAlgo);
            this.parentData = signerCert.getEncoded();
        }
        catch (OperatorCreationException e)
        {
            throw new IllegalStateException("cannot create digest: " + e.getMessage());
        }
        catch (IOException e)
        {
            throw new IllegalStateException("signer certificate encoding failed: " + e.getMessage());
        }
    }

    public ITSCertificate getAssociatedCertificate()
    {
        return signerCert;
    }

    public AlgorithmIdentifier getAlgorithmIdentifier()
    {
        return null;
    }
    
    public OutputStream getOutputStream()
    {
        return new DigestOutputStream(digest);
    }

    public byte[] getSignature()
    {
        byte[] clientCertDigest = new byte[digest.getDigestSize()];

        digest.doFinal(clientCertDigest, 0);

        final byte[] parentDigest = new byte[digest.getDigestSize()];

        digest.update(parentData, 0, parentData.length);

        digest.doFinal(parentDigest, 0);

        final DSADigestSigner signer = new DSADigestSigner(new ECDSASigner(), digest);

        signer.init(true, privKey);

        signer.update(clientCertDigest, 0, clientCertDigest.length);

        signer.update(parentDigest, 0, parentDigest.length);

        return signer.generateSignature();
    }
}
