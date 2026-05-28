package org.bouncycastle.cert;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.util.AggregateRuntimeException;

/**
 * Collects the problems found while decoding an X.509 certificate, instead of throwing
 * on the first one, for diagnostic and reporting use (github #1508).
 * <p>
 * The strict decode path - {@link X509CertificateHolder}, {@code Certificate.getInstance(...)}
 * and the underlying ASN.1 types - deliberately fails fast and is <b>unchanged</b>. This
 * reviewer re-invokes those same strict decoders at a finer granularity inside a
 * catch-and-continue harness: a failure in one component is recorded as a {@link Finding}
 * rather than aborting the whole parse, so problems in sibling components are not masked.
 * Nothing here relaxes a check or admits a certificate the strict path would reject - when
 * any component fails, the recovered {@link X509CertificateHolder} is {@code null} and the
 * reasons are listed in {@link Review#getFindings()}.
 * <p>
 * This is the lightweight, JCA-free counterpart to the validation-side
 * {@code PKIXCertPathReviewer}: a reporting layer over the parser, not a permissive parser.
 * <p>
 * <b>Granularity:</b> problems are localised to the three top-level certificate components -
 * {@code tbsCertificate}, {@code signatureAlgorithm} and {@code signature} - and, within the
 * tbsCertificate, every repeated/malformed extension is reported individually at
 * {@code tbsCertificate.extensions} (the extensions sub-parse returns its problems grouped in
 * an {@link AggregateRuntimeException}, which this reviewer expands). The tbsCertificate and
 * its extensions are enumerated via the shared collect-all parse
 * ({@code TBSCertificate.reviewStructure} / {@code Extensions.reviewStructure}), so the strict
 * constructor and this reviewer apply exactly the same rules from a single source. Localising
 * each remaining individual tbsCertificate scalar field (serialNumber, validity, ...) rather
 * than reporting the first such failure is a possible further refinement.
 */
public class X509CertificateReviewer
{
    /**
     * The severity of a {@link Finding}. Every problem reported by this first cut is an
     * {@link #ERROR}; {@link #WARNING} is reserved for the follow-up (e.g. a violated
     * RFC 5280 "SHOULD", or a defect accepted only because a relaxation property is set).
     */
    public enum Severity
    {
        ERROR,
        WARNING
    }

    /**
     * A single problem found during review.
     */
    public static class Finding
    {
        private final Severity severity;
        private final String location;
        private final String message;
        private final Throwable cause;

        Finding(Severity severity, String location, String message, Throwable cause)
        {
            this.severity = severity;
            this.location = location;
            this.message = message;
            this.cause = cause;
        }

        /**
         * @return ERROR or WARNING.
         */
        public Severity getSeverity()
        {
            return severity;
        }

        /**
         * @return where in the structure the problem was found, e.g. "tbsCertificate".
         */
        public String getLocation()
        {
            return location;
        }

        /**
         * @return the problem text - the wording of the strict decoder's own exception
         *         where the finding came from one.
         */
        public String getMessage()
        {
            return message;
        }

        /**
         * @return the exception the finding was derived from, or null.
         */
        public Throwable getCause()
        {
            return cause;
        }

        public String toString()
        {
            return severity + " [" + location + "] " + message;
        }
    }

    /**
     * The outcome of a review: the list of findings, plus the recovered certificate when
     * the structure decoded cleanly.
     */
    public static class Review
    {
        private final List findings;
        private final X509CertificateHolder certificate;

        Review(List findings, X509CertificateHolder certificate)
        {
            this.findings = Collections.unmodifiableList(findings);
            this.certificate = certificate;
        }

        /**
         * @return true if no ERROR-severity findings were recorded.
         */
        public boolean isValid()
        {
            for (int i = 0; i != findings.size(); i++)
            {
                if (((Finding)findings.get(i)).getSeverity() == Severity.ERROR)
                {
                    return false;
                }
            }
            return true;
        }

        /**
         * @return an unmodifiable list of all findings, in the order they were found
         *         (empty if the certificate decoded cleanly).
         */
        public List getFindings()
        {
            return findings;
        }

        /**
         * @return true if a certificate could be recovered (only when there are no ERROR findings).
         */
        public boolean hasCertificate()
        {
            return certificate != null;
        }

        /**
         * @return the recovered certificate, or null if any component failed to decode.
         */
        public X509CertificateHolder getCertificate()
        {
            return certificate;
        }
    }

    /**
     * Review a DER/BER encoded certificate.
     *
     * @param encoding the candidate certificate bytes.
     * @return the review outcome; never null, never throws for malformed input.
     */
    public static Review reviewStructure(byte[] encoding)
    {
        List findings = new ArrayList();

        ASN1Primitive primitive;
        try
        {
            primitive = ASN1Primitive.fromByteArray(encoding);
        }
        catch (IOException e)
        {
            return error(findings, "encoding", "not a valid DER/BER encoding: " + messageOf(e), e);
        }
        catch (RuntimeException e)
        {
            return error(findings, "encoding", "not a valid DER/BER encoding: " + messageOf(e), e);
        }

        ASN1Sequence certSeq;
        try
        {
            certSeq = ASN1Sequence.getInstance(primitive);
        }
        catch (RuntimeException e)
        {
            return error(findings, "certificate", "top-level structure is not a SEQUENCE: " + messageOf(e), e);
        }

        return reviewSequence(certSeq, findings);
    }

    /**
     * Review an already-decoded certificate SEQUENCE.
     *
     * @param certificateSequence the candidate {@code Certificate} SEQUENCE.
     * @return the review outcome; never null, never throws.
     */
    public static Review reviewStructure(ASN1Sequence certificateSequence)
    {
        return reviewSequence(certificateSequence, new ArrayList());
    }

    private static Review reviewSequence(ASN1Sequence certSeq, List findings)
    {
        if (certSeq.size() != 3)
        {
            return error(findings, "certificate",
                "sequence wrong size for a certificate: expected 3 elements, got " + certSeq.size(), null);
        }

        // Probe each top-level component independently against the strict decoder, so a
        // failure in one does not hide problems in the others.
        try
        {
            TBSCertificate.getInstance(certSeq.getObjectAt(0));
        }
        catch (RuntimeException e)
        {
            // enumerate every tbsCertificate problem the strict path would have thrown
            // (bad version, empty issuer, profile violations, repeated extensions, ...) via
            // the shared collect-all parse, rather than reporting only the first.
            List problems = collectTbsProblems(certSeq.getObjectAt(0));
            if (problems.isEmpty())
            {
                findings.add(new Finding(Severity.ERROR, "tbsCertificate", messageOf(e), e));
            }
            else
            {
                for (int i = 0; i != problems.size(); i++)
                {
                    addTbsFinding(findings, (Throwable)problems.get(i));
                }
            }
        }

        try
        {
            AlgorithmIdentifier.getInstance(certSeq.getObjectAt(1));
        }
        catch (RuntimeException e)
        {
            findings.add(new Finding(Severity.ERROR, "signatureAlgorithm", messageOf(e), e));
        }

        try
        {
            ASN1BitString.getInstance(certSeq.getObjectAt(2));
        }
        catch (RuntimeException e)
        {
            findings.add(new Finding(Severity.ERROR, "signature", messageOf(e), e));
        }

        X509CertificateHolder certificate = null;
        if (isValid(findings))
        {
            // every component decoded; this assembles exactly what the strict path produces.
            try
            {
                certificate = new X509CertificateHolder(Certificate.getInstance(certSeq));
            }
            catch (RuntimeException e)
            {
                findings.add(new Finding(Severity.ERROR, "certificate", messageOf(e), e));
            }
        }

        return new Review(findings, certificate);
    }

    private static void addTbsFinding(List findings, Throwable problem)
    {
        // the extensions sub-parse groups its problems under one AggregateRuntimeException;
        // expand it so each malformed/repeated extension is its own finding.
        if (problem instanceof AggregateRuntimeException)
        {
            List nested = ((AggregateRuntimeException)problem).getExceptions();
            for (int i = 0; i != nested.size(); i++)
            {
                Throwable child = (Throwable)nested.get(i);
                findings.add(new Finding(Severity.ERROR, "tbsCertificate.extensions", messageOf(child), child));
            }
        }
        else
        {
            findings.add(new Finding(Severity.ERROR, "tbsCertificate", messageOf(problem), problem));
        }
    }

    private static List collectTbsProblems(ASN1Encodable tbs)
    {
        try
        {
            return TBSCertificate.reviewStructure(ASN1Sequence.getInstance(tbs));
        }
        catch (RuntimeException e)
        {
            // tbsCertificate is not even a SEQUENCE - nothing to enumerate.
            return Collections.EMPTY_LIST;
        }
    }

    private static boolean isValid(List findings)
    {
        for (int i = 0; i != findings.size(); i++)
        {
            if (((Finding)findings.get(i)).getSeverity() == Severity.ERROR)
            {
                return false;
            }
        }
        return true;
    }

    private static Review error(List findings, String location, String message, Throwable cause)
    {
        findings.add(new Finding(Severity.ERROR, location, message, cause));
        return new Review(findings, null);
    }

    private static String messageOf(Throwable e)
    {
        String m = e.getMessage();
        return (m != null) ? m : e.getClass().getName();
    }
}
