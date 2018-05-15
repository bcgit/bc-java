package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.ArchiveTimeStamp;
import org.bouncycastle.asn1.cms.ArchiveTimeStampChain;
import org.bouncycastle.asn1.cms.ArchiveTimeStampSequence;
import org.bouncycastle.asn1.cms.EvidenceRecord;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.Enumeration;

public class EvidenceRecordVerifier {

    private String securityProvider;

    public EvidenceRecordVerifier(final String securityProvider)
    {
        this.securityProvider = securityProvider;
    }

    /**
     * Validates a provided {@link EvidenceRecord} against a provided object
     */
    public void validate(final EvidenceRecord evidenceRecord, final Object data)
        throws ArchiveTimeStampValidationException, NoSuchAlgorithmException, TSPException, IOException, PartialHashTreeVerificationException, CertificateException, OperatorCreationException {
        ArchiveTimeStampSequence sequence = getArchiveTimestampSequence(evidenceRecord);
        ArchiveTimeStampSequenceVerifier verifier = new ArchiveTimeStampSequenceVerifier(sequence);
        verifier.validate(data);
        validateLastATS(sequence);
    }

    private void validateLastATS(final ArchiveTimeStampSequence sequence)
        throws OperatorCreationException, CertificateException, TSPException, IOException {
        ASN1Sequence chains = ASN1Sequence.getInstance(sequence.toASN1Primitive());
        ArchiveTimeStampChain chain = ArchiveTimeStampChain
            .getInstance(chains.getObjectAt(chains.size() - 1));
        ASN1Sequence archiveTimestamps = chain.getArchiveTimestamps();

        ArchiveTimeStamp ats = ArchiveTimeStamp
            .getInstance(archiveTimestamps.getObjectAt(archiveTimestamps.size() - 1));

        checkArchiveTimeStampValid(ats);
    }

    /**
     * Retrieves the {@link ArchiveTimeStampSequence} of a provided {@link EvidenceRecord}
     *
     * @param evidenceRecord
     * @return
     */
    private ArchiveTimeStampSequence getArchiveTimestampSequence(final EvidenceRecord evidenceRecord) {

        ASN1Sequence instance = ASN1Sequence.getInstance(evidenceRecord.toASN1Primitive());
        Enumeration objects = instance.getObjects();

        while (objects.hasMoreElements()) {
            Object o = objects.nextElement();
            if (o instanceof ArchiveTimeStampSequence) {
                return ArchiveTimeStampSequence.getInstance(o);
            }
        }

        throw new IllegalArgumentException("no archivetimestamp sequence found in provided object");
    }

    /**
     * In order to complete the non-repudiation proof for the data objects, the last Archive
     * Timestamp has to be valid at the time the verification is performed.
     * @param ats
     */
    private void checkArchiveTimeStampValid(final ArchiveTimeStamp ats)
        throws IOException, TSPException, CertificateException, OperatorCreationException
    {
        final TimeStampToken timeStampToken = new TimeStampToken(ats.getTimeStamp());

        final Store<X509CertificateHolder> certificateStore = timeStampToken.getCertificates();
        final Collection<X509CertificateHolder> certs = certificateStore.getMatches(timeStampToken.getSID());
        final X509CertificateHolder holder = certs.iterator().next();

        timeStampToken.validate(new JcaSimpleSignerInfoVerifierBuilder().setProvider(securityProvider).build
            (holder));
    }
}
