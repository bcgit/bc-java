package org.bouncycastle.mail.smime.validator;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import javax.mail.Address;
import javax.mail.MessagingException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.jcajce.JcaCertStoreBuilder;
import org.bouncycastle.cert.jcajce.JcaX500NameUtil;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JcaX509CertSelectorConverter;
import org.bouncycastle.mail.smime.SMIMESigned;
import org.bouncycastle.pkix.jcajce.CertPathReviewerException;
import org.bouncycastle.pkix.jcajce.PKIXCertPathReviewer;
import org.bouncycastle.pkix.util.ErrorBundle;
import org.bouncycastle.pkix.util.filter.TrustedInput;
import org.bouncycastle.pkix.util.filter.UntrustedInput;
import org.bouncycastle.util.Integers;

public class SignedMailValidator
{
    private static final String RESOURCE_NAME = "org.bouncycastle.mail.smime.validator.SignedMailValidatorMessages";

    private static final Class DEFAULT_CERT_PATH_REVIEWER = PKIXCertPathReviewer.class;

    private static final int shortKeyLength = 512;

    // (365.25*30)*24*3600*1000
    private static final long THIRTY_YEARS_IN_MILLI_SEC = 21915l * 12l * 3600l * 1000l;

    private static final JcaX509CertSelectorConverter SELECTOR_CONVERTER = new JcaX509CertSelectorConverter();

    private static final int KU_DIGITAL_SIGNATURE = 0;
    private static final int KU_NON_REPUDIATION = 1;

    private static final Locale locale = Locale.getDefault();

    private CertStore certs;

    private SignerInformationStore signers;

    private Map results;

    private String[] fromAddresses;

    private Class certPathReviewerClass;

    /**
     * Validates the signed {@link MimeMessage} message. The {@link PKIXParameters} from
     * <code>param</code> are used for the certificate path validation. The actual
     * {@link PKIXParameters} used for the certificate path validation are a copy of <code>param</code>
     * with the following changes:<br>
     * - The validation date is changed to the signature time.<br>
     * - A CertStore with certificates and CRLs from the mail message is added to the CertStores.<br>
     * <br>
     * In <code>param</code> it's also possible to add additional CertStores with intermediate
     * certificates and/or CRLs which then are also used for the validation.
     *
     * @param message the signed {@link MimeMessage}.
     * @param param the parameters for the certificate path validation.
     * @throws SignedMailValidatorException if the message is not a signed message or if an
     * exception occurs reading the message.
     */
    public SignedMailValidator(MimeMessage message, PKIXParameters param) throws SignedMailValidatorException
    {
        this(message, param, DEFAULT_CERT_PATH_REVIEWER);
    }

    /**
     * Validates the signed {@link MimeMessage} message. The {@link PKIXParameters} from
     * <code>param</code> are used for the certificate path validation. The actual
     * {@link PKIXParameters} used for the certificate path validation are a copy of <code>param</code>
     * with the following changes:<br>
     * - The validation date is changed to the signature time.<br>
     * - A CertStore with certificates and CRLs from the mail message is added to the CertStores.<br>
     * <br>
     * In <code>param</code> it's also possible to add additional CertStores with intermediate
     * certificates and/or CRLs which then are also used for the validation.
     *
     * @param message the signed {@link MimeMessage}.
     * @param param the parameters for the certificate path validation.
     * @param certPathReviewerClass a subclass of {@link PKIXCertPathReviewer}. The SignedMailValidator
     * uses objects of this type for the cert path vailidation. The class must have an empty
     * constructor.
     * @throws SignedMailValidatorException if the message is not a signed message or if an exception
     * occurs reading the message.
     * @throws IllegalArgumentException if the certPathReviewerClass is not a subclass of
     * {@link PKIXCertPathReviewer} or objects of certPathReviewerClass can not be instantiated.
     */
    public SignedMailValidator(MimeMessage message, PKIXParameters param, Class certPathReviewerClass)
        throws SignedMailValidatorException
    {
        this.certPathReviewerClass = certPathReviewerClass;
        boolean isSubclass = DEFAULT_CERT_PATH_REVIEWER.isAssignableFrom(certPathReviewerClass);
        if (!isSubclass)
        {
            throw new IllegalArgumentException(
                "certPathReviewerClass is not a subclass of " + DEFAULT_CERT_PATH_REVIEWER.getName());
        }

        try
        {
            // check if message is multipart signed
            SMIMESigned s;
            if (message.isMimeType("multipart/signed"))
            {
                MimeMultipart mimemp = (MimeMultipart) message.getContent();
                s = new SMIMESigned(mimemp);
            }
            else if (message.isMimeType("application/pkcs7-mime") || message.isMimeType("application/x-pkcs7-mime"))
            {
                s = new SMIMESigned(message);
            }
            else
            {
                ErrorBundle msg = createErrorBundle("SignedMailValidator.noSignedMessage");
                throw new SignedMailValidatorException(msg);
            }

            // save certstore and signerInformationStore
            certs = new JcaCertStoreBuilder()
                .addCertificates(s.getCertificates())
                .addCRLs(s.getCRLs())
                .setProvider("BC")
                .build();
            signers = s.getSignerInfos();

            // save "from" addresses from message
            Address[] froms = message.getFrom();
            InternetAddress sender = null;
            try
            {
                if (message.getHeader("Sender") != null)
                {
                    sender = new InternetAddress(message.getHeader("Sender")[0]);
                }
            }
            catch (MessagingException ex)
            {
                // ignore garbage in Sender: header
            }

            int fromsLength = (froms != null) ? froms.length : 0;
            fromAddresses = new String[fromsLength + ((sender != null) ? 1 : 0)];
            for (int i = 0; i < fromsLength; i++)
            {
                InternetAddress inetAddr = (InternetAddress) froms[i];
                fromAddresses[i] = inetAddr.getAddress();
            }
            if (sender != null)
            {
                fromAddresses[fromsLength] = sender.getAddress();
            }

            // initialize results
            results = new HashMap();
        }
        catch (Exception e)
        {
            if (e instanceof SignedMailValidatorException)
            {
                throw (SignedMailValidatorException) e;
            }
            // exception reading message
            ErrorBundle msg = createErrorBundle("SignedMailValidator.exceptionReadingMessage", e);
            throw new SignedMailValidatorException(msg, e);
        }

        // validate signatures
        validateSignatures(param);
    }

    protected void validateSignatures(PKIXParameters pkixParam)
    {
        JcaSimpleSignerInfoVerifierBuilder signerInfoVerifierBuilder = new JcaSimpleSignerInfoVerifierBuilder()
                  .setProvider("BC");
        validateSignatures(signerInfoVerifierBuilder, pkixParam);
    }

    protected void validateSignatures(JcaSimpleSignerInfoVerifierBuilder signerInfoVerifierBuilder, PKIXParameters pkixParam)
    {
        PKIXParameters usedParameters = (PKIXParameters)pkixParam.clone();

        // add CRLs and certs from mail
        usedParameters.addCertStore(certs);

        Collection c = signers.getSigners();
        Iterator it = c.iterator();

        // check each signer
        while (it.hasNext())
        {
            List errors = new ArrayList();
            List notifications = new ArrayList();

            SignerInformation signer = (SignerInformation)it.next();
            // signer certificate
            X509Certificate signerCert = null;

            try
            {
                X509CertSelector selector = SELECTOR_CONVERTER.getCertSelector(signer.getSID());
                signerCert = findFirstCert(usedParameters.getCertStores(), selector, null);
            }
            catch (CertStoreException cse)
            {
                ErrorBundle msg = createErrorBundle("SignedMailValidator.exceptionRetrievingSignerCert", cse);
                errors.add(msg);
            }

            if (signerCert == null)
            {
                // no signer certificate found
                ErrorBundle msg = createErrorBundle("SignedMailValidator.noSignerCert");
                errors.add(msg);
                results.put(signer, new ValidationResult(null, false, errors, notifications, null));
                continue;
            }

            boolean validSignature;
            try
            {
                SignerInformationVerifier verifier = signerInfoVerifierBuilder
                                .build(signerCert.getPublicKey());

                // check signature
                validSignature = isValidSignature(verifier, signer, errors);
            }
            catch (Exception e)
            {
                validSignature = false;
                ErrorBundle msg = createErrorBundle("SignedMailValidator.exceptionVerifyingSignature", e);
                errors.add(msg);
            }

            // check signer certificate (mail address, key usage, etc)
            checkSignerCert(signerCert, errors, notifications);

            // notify if a signed receipt request is in the message
            AttributeTable atab = signer.getSignedAttributes();
            if (atab != null)
            {
                Attribute attr = atab.get(PKCSObjectIdentifiers.id_aa_receiptRequest);
                if (attr != null)
                {
                    ErrorBundle msg = createErrorBundle("SignedMailValidator.signedReceiptRequest");
                    notifications.add(msg);
                }
            }

            // check certificate path

            // get signing time if possible, otherwise use current time as signing time
            Date signTime = getSignatureTime(signer);
            if (signTime == null) // no signing time was found
            {
                ErrorBundle msg = createErrorBundle("SignedMailValidator.noSigningTime");
                notifications.add(msg);
                signTime = pkixParam.getDate();
                if (signTime == null)
                {
                    signTime = new Date();
                }
            }
            else
            {
                // check if certificate was valid at signing time
                try
                {
                    signerCert.checkValidity(signTime);
                }
                catch (CertificateExpiredException e)
                {
                    ErrorBundle msg = createErrorBundle("SignedMailValidator.certExpired",
                        new Object[]{ new TrustedInput(signTime), new TrustedInput(signerCert.getNotAfter()) });
                    errors.add(msg);
                }
                catch (CertificateNotYetValidException e)
                {
                    ErrorBundle msg = createErrorBundle("SignedMailValidator.certNotYetValid",
                        new Object[]{ new TrustedInput(signTime), new TrustedInput(signerCert.getNotBefore()) });
                    errors.add(msg);
                }
            }
            usedParameters.setDate(signTime);

            try
            {
                // construct cert chain
                ArrayList userCertStores = new ArrayList();
                userCertStores.add(certs);

                Object[] cpres = createCertPath(signerCert, usedParameters.getTrustAnchors(), pkixParam.getCertStores(),
                    userCertStores);
                CertPath certPath = (CertPath)cpres[0];
                List userProvidedList = (List)cpres[1];

                // validate cert chain
                PKIXCertPathReviewer review;
                try
                {
                    review = (PKIXCertPathReviewer)certPathReviewerClass.newInstance();
                }
                catch (IllegalAccessException e)
                {
                    throw new IllegalArgumentException("Cannot instantiate object of type "
                        + certPathReviewerClass.getName() + ": " + e.getMessage());
                }
                catch (InstantiationException e)
                {
                    throw new IllegalArgumentException("Cannot instantiate object of type "
                        + certPathReviewerClass.getName() + ": " + e.getMessage());
                }
                review.init(certPath, usedParameters);
                if (!review.isValidCertPath())
                {
                    ErrorBundle msg = createErrorBundle("SignedMailValidator.certPathInvalid");
                    errors.add(msg);
                }
                results.put(signer,
                    new ValidationResult(review, validSignature, errors, notifications, userProvidedList));
            }
            catch (GeneralSecurityException gse)
            {
                // cannot create cert path
                ErrorBundle msg = createErrorBundle("SignedMailValidator.exceptionCreateCertPath", gse);
                errors.add(msg);
                results.put(signer, new ValidationResult(null, validSignature, errors, notifications, null));
            }
            catch (CertPathReviewerException cpre)
            {
                // cannot initialize certpathreviewer - wrong parameters
                errors.add(cpre.getErrorMessage());
                results.put(signer, new ValidationResult(null, validSignature, errors, notifications, null));
            }
        }
    }

    public static Set getEmailAddresses(X509Certificate cert) throws IOException, CertificateEncodingException
    {
        HashSet addresses = new HashSet();

        RDN[] rdns = JcaX500NameUtil.getSubject(cert).getRDNs(PKCSObjectIdentifiers.pkcs_9_at_emailAddress);
        for (int i = 0; i < rdns.length; i++)
        {
            AttributeTypeAndValue[] atVs = rdns[i].getTypesAndValues();

            for (int j = 0; j != atVs.length; j++)
            {
                if (PKCSObjectIdentifiers.pkcs_9_at_emailAddress.equals(atVs[j].getType()))
                {
                    String email = ((ASN1String)atVs[j].getValue()).getString().toLowerCase(locale);
                    addresses.add(email);
                }
            }
        }

        byte[] sanExtValue = cert.getExtensionValue(Extension.subjectAlternativeName.getId());
        if (sanExtValue != null)
        {
            GeneralNames san = GeneralNames.getInstance(JcaX509ExtensionUtils.parseExtensionValue(sanExtValue));

            GeneralName[] names = san.getNames();
            for (int i = 0; i < names.length; ++i)
            {
                GeneralName name = names[i];
                if (name.getTagNo() == GeneralName.rfc822Name)
                {
                    String email = ASN1IA5String.getInstance(name.getName()).getString().toLowerCase(locale);
                    addresses.add(email);
                }
            }
        }

        return addresses;
    }

    protected void checkSignerCert(X509Certificate cert, List errors, List notifications)
    {
        // get key length
        PublicKey key = cert.getPublicKey();
        int keyLength = -1;
        if (key instanceof RSAPublicKey)
        {
            keyLength = ((RSAPublicKey) key).getModulus().bitLength();
        }
        else if (key instanceof DSAPublicKey)
        {
            keyLength = ((DSAPublicKey) key).getParams().getP().bitLength();
        }
        if (keyLength != -1 && keyLength <= shortKeyLength)
        {
            ErrorBundle msg = createErrorBundle(
                "SignedMailValidator.shortSigningKey",
                new Object[]{ Integers.valueOf(keyLength) });
            notifications.add(msg);
        }

        // warn if certificate has very long validity period
        long validityPeriod = cert.getNotAfter().getTime() - cert.getNotBefore().getTime();
        if (validityPeriod > THIRTY_YEARS_IN_MILLI_SEC)
        {
            ErrorBundle msg = createErrorBundle(
                "SignedMailValidator.longValidity",
                new Object[]{ new TrustedInput(cert.getNotBefore()), new TrustedInput(cert.getNotAfter()) });
            notifications.add(msg);
        }

        // check key usage if digitalSignature or nonRepudiation is set
        boolean[] keyUsage = cert.getKeyUsage();
        if (!supportsKeyUsage(keyUsage, KU_DIGITAL_SIGNATURE) &&
            !supportsKeyUsage(keyUsage, KU_NON_REPUDIATION))
        {
            ErrorBundle msg = createErrorBundle("SignedMailValidator.signingNotPermitted");
            errors.add(msg);
        }

        // check extended key usage
        try
        {
            byte[] ekuExtValue = cert.getExtensionValue(Extension.extendedKeyUsage.getId());
            if (ekuExtValue != null)
            {
                ExtendedKeyUsage eku = ExtendedKeyUsage.getInstance(
                    JcaX509ExtensionUtils.parseExtensionValue(ekuExtValue));

                if (!eku.hasKeyPurposeId(KeyPurposeId.anyExtendedKeyUsage) &&
                    !eku.hasKeyPurposeId(KeyPurposeId.id_kp_emailProtection))
                {
                    ErrorBundle msg = createErrorBundle("SignedMailValidator.extKeyUsageNotPermitted");
                    errors.add(msg);
                }
            }
        }
        catch (Exception e)
        {
            ErrorBundle msg = createErrorBundle("SignedMailValidator.extKeyUsageError", e);
            errors.add(msg);
        }

        // cert has an email address
        try
        {
            Set certEmails = getEmailAddresses(cert);
            if (certEmails.isEmpty())
            {
                // error no email address in signing certificate
                ErrorBundle msg = createErrorBundle("SignedMailValidator.noEmailInCert");
                errors.add(msg);
            }
            else if (!hasAnyFromAddress(certEmails, fromAddresses))
            {
                ErrorBundle msg = createErrorBundle(
                    "SignedMailValidator.emailFromCertMismatch",
                    new Object[]{ new UntrustedInput(addressesToString(fromAddresses)), new UntrustedInput(certEmails) });
                errors.add(msg);
            }
        }
        catch (Exception e)
        {
            ErrorBundle msg = createErrorBundle("SignedMailValidator.certGetEmailError", e);
            errors.add(msg);
        }
    }

    static boolean hasAnyFromAddress(Set certEmails, String[] fromAddresses)
    {
        // check if email in cert is equal to the from address in the message
        for (int i = 0; i < fromAddresses.length; ++i)
        {
            if (certEmails.contains(fromAddresses[i].toLowerCase(locale)))
            {
                return true;
            }
        }
        return false;
    }

    static String addressesToString(Object[] a)
    {
        if (a == null)
        {
            return "null";
        }

        StringBuilder b = new StringBuilder();
        b.append('[');

        for (int i = 0; i != a.length; i++)
        {
            if (i > 0)
            {
                b.append(", ");
            }
            b.append(String.valueOf(a[i]));
        }

        return b.append(']').toString();
    }

    public static Date getSignatureTime(SignerInformation signer)
    {
        AttributeTable atab = signer.getSignedAttributes();
        if (atab != null)
        {
            Attribute attr = atab.get(CMSAttributes.signingTime);
            if (attr != null)
            {
                Time t = Time.getInstance(attr.getAttrValues().getObjectAt(0));
                return t.getDate();
            }
        }
        return null;
    }

    /**
     * @param signerCert the end of the path
     * @param trustanchors trust anchors for the path
     * @param certStores
     * @return the resulting certificate path.
     * @throws GeneralSecurityException
     */
    public static CertPath createCertPath(X509Certificate signerCert, Set trustanchors, List certStores)
        throws GeneralSecurityException
    {
        Object[] results = createCertPath(signerCert, trustanchors, certStores, null);
        return (CertPath)results[0];
    }

    /**
     * Returns an Object array containing a CertPath and a List of Booleans. The list contains the value
     * <code>true</code> if the corresponding certificate in the CertPath was taken from the user
     * provided CertStores.
     *
     * @param signerCert the end of the path
     * @param trustAnchors trust anchors for the path
     * @param systemCertStores list of {@link CertStore} provided by the system
     * @param userCertStores list of {@link CertStore} provided by the user
     * @return a CertPath and a List of booleans.
     * @throws GeneralSecurityException
     */
    public static Object[] createCertPath(X509Certificate signerCert, Set trustAnchors, List systemCertStores,
        List userCertStores) throws GeneralSecurityException
    {
        if (signerCert == null)
        {
            throw new NullPointerException("'signerCert' cannot be null");
        }

        LinkedHashSet certSet = new LinkedHashSet();
        ArrayList userProvidedList = new ArrayList();

        X509Certificate cert = signerCert;
        boolean certIsSystemProvided = false;

        X509Certificate providedCert = getProvidedCert(trustAnchors, systemCertStores, signerCert);
        if (providedCert != null)
        {
            cert = providedCert;
            certIsSystemProvided = true;
        }

        TrustAnchor trustAnchor = null;

        // add other certs to the cert path
        do
        {
            certSet.add(cert);
            userProvidedList.add(Boolean.valueOf(!certIsSystemProvided));

            // check if cert issuer is Trustanchor
            trustAnchor = findTrustAnchorForCert(cert, trustAnchors);
            if (trustAnchor != null)
            {
                break;
            }

            // add next cert to path

            X509CertSelector issuerSelector = createIssuerSelector(cert);

            cert = findFirstCert(systemCertStores, issuerSelector, certSet);
            certIsSystemProvided = (cert != null);

            if (cert == null && userCertStores != null)
            {
                cert = findFirstCert(userCertStores, issuerSelector, certSet);
            }
        }
        while (cert != null);

        // if a trust anchor was found - try to find a self-signed certificate of the trust anchor
        if (trustAnchor != null)
        {
            X509Certificate trustedCert = trustAnchor.getTrustedCert(); // Can be null

            if (trustedCert != null &&
                trustedCert.getSubjectX500Principal().equals(trustedCert.getIssuerX500Principal()))
            {
                if (certSet.add(trustedCert))
                {
                    userProvidedList.add(Boolean.FALSE);
                }
            }
            else
            {
                X509CertSelector taSelector = new X509CertSelector();

                byte[] certIssuerEncoding = cert.getIssuerX500Principal().getEncoded(); 
                try
                {
                    taSelector.setSubject(certIssuerEncoding);
                    taSelector.setIssuer(certIssuerEncoding);
                }
                catch (IOException e)
                {
                    throw new IllegalStateException(e.toString());
                }

                cert = findFirstCert(systemCertStores, taSelector, certSet);
                certIsSystemProvided = (cert != null);

                if (cert == null && userCertStores != null)
                {
                    cert = findFirstCert(userCertStores, taSelector, certSet);
                }

                if (cert != null)
                {
                    try
                    {
                        cert.verify(cert.getPublicKey(), "BC");

                        certSet.add(cert);
                        userProvidedList.add(Boolean.valueOf(!certIsSystemProvided));
                    }
                    catch (GeneralSecurityException gse)
                    {
                        // wrong cert
                    }
                }
            }
        }

        CertPath certPath = CertificateFactory.getInstance("X.509", "BC").generateCertPath(new ArrayList(certSet));
        return new Object[]{ certPath, userProvidedList };
    }

    public CertStore getCertsAndCRLs()
    {
        return certs;
    }

    public SignerInformationStore getSignerInformationStore()
    {
        return signers;
    }

    public ValidationResult getValidationResult(SignerInformation signer) throws SignedMailValidatorException
    {
        if (signers.getSigners(signer.getSID()).isEmpty())
        {
            // the signer is not part of the SignerInformationStore
            // he has not signed the message
            ErrorBundle msg = createErrorBundle("SignedMailValidator.wrongSigner");
            throw new SignedMailValidatorException(msg);
        }

        return (ValidationResult)results.get(signer);
    }

    public static class ValidationResult
    {
        private PKIXCertPathReviewer review;
        private List errors;
        private List notifications;
        private List userProvidedCerts;
        private boolean signVerified;

        ValidationResult(PKIXCertPathReviewer review, boolean verified, List errors, List notifications,
            List userProvidedCerts)
        {
            this.review = review;
            this.errors = errors;
            this.notifications = notifications;
            this.signVerified = verified;
            this.userProvidedCerts = userProvidedCerts;
        }

        /**
         * Returns a list of error messages of type {@link ErrorBundle}.
         *
         * @return List of error messages
         */
        public List getErrors()
        {
            return errors;
        }

        /**
         * Returns a list of notification messages of type {@link ErrorBundle}.
         *
         * @return List of notification messages
         */
        public List getNotifications()
        {
            return notifications;
        }

        /**
         * @return the PKIXCertPathReviewer for the CertPath of this signature or null if an Exception
         * occurred.
         */
        public PKIXCertPathReviewer getCertPathReview()
        {
            return review;
        }

        /**
         * @return the CertPath for this signature or null if an Exception occurred.
         */
        public CertPath getCertPath()
        {
            return review != null ? review.getCertPath() : null;
        }

        /**
         * @return a List of Booleans that are true if the corresponding certificate in the CertPath was
         * taken from the CertStore of the SMIME message
         */
        public List getUserProvidedCerts()
        {
            return userProvidedCerts;
        }

        /**
         * @return true if the signature corresponds to the public key of the signer
         */
        public boolean isVerifiedSignature()
        {
            return signVerified;
        }

        /**
         * @return true if the signature is valid (ie. if it corresponds to the public key of the signer and
         * the cert path for the signers certificate is also valid)
         */
        public boolean isValidSignature()
        {
            return review != null && signVerified && review.isValidCertPath() && errors.isEmpty();
        }
    }

    private static ErrorBundle createErrorBundle(String id)
    {
        ErrorBundle msg = new ErrorBundle(RESOURCE_NAME, id);
        msg.setClassLoader(SignedMailValidator.class.getClassLoader());

        return msg;
    }

    private static ErrorBundle createErrorBundle(String id, Object[] arguments)
    {
        ErrorBundle msg = new ErrorBundle(RESOURCE_NAME, id, arguments);
        msg.setClassLoader(SignedMailValidator.class.getClassLoader());

        return msg;
    }

    private static ErrorBundle createErrorBundle(String id, Exception e)
    {
        return createErrorBundle(id, new Object[]{ e.getMessage(), e, e.getClass().getName() });
    }

    private static X509CertSelector createIssuerSelector(X509Certificate cert)
    {
        // add next cert to path
        X509CertSelector selector = new X509CertSelector();
        try
        {
            selector.setSubject(cert.getIssuerX500Principal().getEncoded());
        }
        catch (IOException e)
        {
            throw new IllegalStateException(e.toString());
        }

        byte[] akiExtValue = cert.getExtensionValue(Extension.authorityKeyIdentifier.getId());
        if (akiExtValue != null)
        {
            try
            {
                AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(
                    JcaX509ExtensionUtils.parseExtensionValue(akiExtValue));

                ASN1OctetString keyIdentifier = aki.getKeyIdentifierObject();
                if (keyIdentifier != null)
                {
                    selector.setSubjectKeyIdentifier(keyIdentifier.getEncoded(ASN1Encoding.DER));
                }
            }
            catch (IOException ioe)
            {
                // ignore
            }
        }

        return selector;
    }

    private static X509Certificate findFirstCert(List certStores, X509CertSelector selector, Set ignoreCerts)
        throws CertStoreException
    {
        X509CertSelector altSelector = null;

        Iterator certStoreIter = certStores.iterator();
        while (certStoreIter.hasNext())
        {
            CertStore certStore = (CertStore)certStoreIter.next();
            Collection certs = certStore.getCertificates(selector);

            // sometimes the subjectKeyIdentifier in a TA certificate, even when the authorityKeyIdentifier is set.
            // where this happens we roll back to a simpler match to make sure we've got all the possibilities.
            if (certs.isEmpty() && selector.getSubjectKeyIdentifier() != null)
            {
                if (altSelector == null)
                {
                    altSelector = (X509CertSelector)selector.clone();
                    altSelector.setSubjectKeyIdentifier(null);
                }

                certs = certStore.getCertificates(altSelector);
            }

            Iterator certIter = certs.iterator();
            while (certIter.hasNext())
            {
                X509Certificate nextCert = (X509Certificate)certIter.next();
                if (ignoreCerts == null || !ignoreCerts.contains(nextCert))
                {
                    return nextCert;
                }
            }
        }
        return null;
    }

    private static TrustAnchor findTrustAnchorForCert(X509Certificate cert, Set trustAnchors)
    {
        Iterator trustAnchorIter = trustAnchors.iterator();
        if (trustAnchorIter.hasNext())
        {
            X500Principal certIssuer = cert.getIssuerX500Principal();

            do
            {
                TrustAnchor trustAnchor = (TrustAnchor)trustAnchorIter.next();

                try
                {
                    X509Certificate taCert = trustAnchor.getTrustedCert();
                    if (taCert != null)
                    {
                        if (certIssuer.equals(taCert.getSubjectX500Principal()))
                        {
                            cert.verify(taCert.getPublicKey(), "BC");
                            return trustAnchor;
                        }
                    }
                    else
                    {
                        if (certIssuer.getName().equals(trustAnchor.getCAName()))
                        {
                            cert.verify(trustAnchor.getCAPublicKey(), "BC");
                            return trustAnchor;
                        }
                    }
                }
                catch (Exception e)
                {
                }
            }
            while (trustAnchorIter.hasNext());
        }
        return null;
    }

    private static X509Certificate getProvidedCert(Set trustAnchors, List certStores, X509Certificate cert)
        throws CertStoreException
    {
        Iterator trustAnchorIter = trustAnchors.iterator();
        while (trustAnchorIter.hasNext())
        {
            TrustAnchor trustAnchor = (TrustAnchor)trustAnchorIter.next();
            X509Certificate taCert = trustAnchor.getTrustedCert();
            if (taCert != null && taCert.equals(cert))
            {
                return taCert;
            }
        }

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(cert);

        return findFirstCert(certStores, selector, null);
    }

    private static boolean isValidSignature(SignerInformationVerifier verifier, SignerInformation signer, List errors)
    {
        boolean validSignature = false;
        try
        {
            validSignature = signer.verify(verifier);
            if (!validSignature)
            {
                ErrorBundle msg = createErrorBundle("SignedMailValidator.signatureNotVerified");
                errors.add(msg);
            }
        }
        catch (Exception e)
        {
            ErrorBundle msg = createErrorBundle("SignedMailValidator.exceptionVerifyingSignature", e);
            errors.add(msg);
        }
        return validSignature;
    }

    private static boolean supportsKeyUsage(boolean[] ku, int kuBit)
    {
        return null == ku || (ku.length > kuBit && ku[kuBit]);
    }
}
