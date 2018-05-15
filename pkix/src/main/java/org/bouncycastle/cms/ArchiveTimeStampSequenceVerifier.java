package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.ArchiveTimeStampChain;
import org.bouncycastle.asn1.cms.ArchiveTimeStampSequence;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Date;

public class ArchiveTimeStampSequenceVerifier {

    private ArchiveTimeStampSequence archiveTimeStampSequence;

    public ArchiveTimeStampSequenceVerifier(final ArchiveTimeStampSequence sequence) {

        this.archiveTimeStampSequence = sequence;
    }

    public void validate(final Object data)
        throws ArchiveTimeStampValidationException, NoSuchAlgorithmException, TSPException, IOException, PartialHashTreeVerificationException, CertificateException, OperatorCreationException {

        final ArchiveTimeStampChainVerifier verifier = new ArchiveTimeStampChainVerifier();

        verifier.setPrevGenTime(new Date(0L)); //Assumes that the EvidenceRecord was not
        // generated before epoch
        verifier.setPrevExpTime(new Date());

        ASN1Sequence chains = ASN1Sequence
            .getInstance(archiveTimeStampSequence.toASN1Primitive());

        for (int i = 0; i < chains.size(); i++) {
            final ArchiveTimeStampChain chain = ArchiveTimeStampChain.getInstance(chains
                .getObjectAt(i));

            verifier.setAtsc(getAtsc(i));
            verifier.setArchiveTimeStampChain(chain);
            verifier.validate(data);

            verifier.setPrevExpTime(verifier.getArchiveTimeStampVerifier().getExpiryDate());
            verifier.setPrevGenTime(verifier.getArchiveTimeStampVerifier().getGenTime());
        }
    }

    private byte[] getAtsc(final int index)
        throws NoSuchAlgorithmException, IOException
    {
        if (index == 0)
        {
            return null;
        }
        final ASN1EncodableVector vector = new ASN1EncodableVector();
        final ASN1Sequence archiveTimeStampChains = archiveTimeStampSequence
            .getArchiveTimeStampChains();

        for (int i = 0; i < index; i++)
        {
            final ArchiveTimeStampChain chain = ArchiveTimeStampChain.getInstance(
                archiveTimeStampChains.getObjectAt(i));
            vector.add(chain);
        }

        final ASN1Sequence sequence = new DERSequence(vector);
        final ArchiveTimeStampSequence subSequence = ArchiveTimeStampSequence.getInstance(sequence);

        return subSequence.getEncoded("DER");
    }


}
