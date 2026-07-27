package org.bouncycastle.asn1.x509;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.util.Arrays;

/**
 * Validator for the CRL scope rules of RFC 5280 sec. 6.3.3: the (b)(1) cRLIssuer check, the
 * (b)(2) issuing distribution point checks, the (c) delta CRL consistency checks and the (d)
 * reasons intersection. The methods work purely on ASN.1 structures so the JCA cert path
 * implementations in the provider and in the PKIX revocation checker can share them - the
 * scope analogue of {@link PKIXNameConstraintValidator}.
 */
public class PKIXCRLValidator
{
    /**
     * A reasons mask asserting all revocation reasons.
     */
    public static final int ALL_REASONS = ReasonFlags.aACompromise | ReasonFlags.affiliationChanged |
        ReasonFlags.cACompromise | ReasonFlags.certificateHold | ReasonFlags.cessationOfOperation |
        ReasonFlags.keyCompromise | ReasonFlags.privilegeWithdrawn | ReasonFlags.unused | ReasonFlags.superseded;

    /**
     * Return true if {@link #checkDistributionPointName} will need the CRL issuer name for the
     * passed in issuing distribution point - i.e. its distribution point name is relative to
     * the CRL issuer.
     */
    public static boolean requiresCRLIssuer(IssuingDistributionPoint idp)
    {
        return idp != null && idp.getDistributionPoint() != null
            && idp.getDistributionPoint().getType() == DistributionPointName.NAME_RELATIVE_TO_CRL_ISSUER;
    }

    /**
     * Return true if {@link #checkDistributionPointName} will need the certificate issuer name
     * for the passed in issuing distribution point and distribution point - i.e. the DP name is
     * relative to the CRL issuer and the DP carries no cRLIssuer to resolve it against.
     */
    public static boolean requiresCertificateIssuer(IssuingDistributionPoint idp, DistributionPoint dp)
    {
        return idp != null && idp.getDistributionPoint() != null
            && dp.getDistributionPoint() != null
            && dp.getDistributionPoint().getType() == DistributionPointName.NAME_RELATIVE_TO_CRL_ISSUER
            && dp.getCRLIssuer() == null;
    }

    /**
     * RFC 5280 sec. 6.3.3 (b)(2)(i): if the distribution point name is present in the IDP CRL
     * extension and the distribution field is present in the DP, verify that one of the names
     * in the IDP matches one of the names in the DP; if the distribution field is omitted from
     * the DP, verify that one of the names in the IDP matches one of the names in the cRLIssuer
     * field of the DP.
     *
     * @param idp        the CRL's issuing distribution point (may be null - no checks apply).
     * @param dp         the distribution point from the certificate.
     * @param crlIssuer  the CRL issuer name; only required when {@link #requiresCRLIssuer}.
     * @param certIssuer the certificate issuer name; only required when {@link #requiresCertificateIssuer}.
     * @throws CRLValidatorException if no match is found or the DP is malformed.
     */
    public static void checkDistributionPointName(IssuingDistributionPoint idp, DistributionPoint dp,
        X500Name crlIssuer, X500Name certIssuer)
        throws CRLValidatorException
    {
        if (idp == null || idp.getDistributionPoint() == null)
        {
            return;
        }

        // make list of names
        DistributionPointName dpName = idp.getDistributionPoint();
        List names = new ArrayList();

        if (dpName.getType() == DistributionPointName.FULL_NAME)
        {
            GeneralName[] genNames = GeneralNames.getInstance(dpName.getName()).getNames();
            for (int j = 0; j < genNames.length; j++)
            {
                names.add(genNames[j]);
            }
        }
        if (dpName.getType() == DistributionPointName.NAME_RELATIVE_TO_CRL_ISSUER)
        {
            ASN1Sequence seq = ASN1Sequence.getInstance(crlIssuer.toASN1Primitive());

            int count = seq.size();
            ASN1EncodableVector vec = new ASN1EncodableVector(count + 1);
            for (int i = 0; i < count; ++i)
            {
                vec.add(seq.getObjectAt(i));
            }
            vec.add(dpName.getName());

            names.add(new GeneralName(X500Name.getInstance(new DERSequence(vec))));
        }

        boolean matches = false;

        // verify that one of the names in the IDP matches one of the names in the DP
        if (dp.getDistributionPoint() != null)
        {
            dpName = dp.getDistributionPoint();
            GeneralName[] genNames = null;
            if (dpName.getType() == DistributionPointName.FULL_NAME)
            {
                genNames = GeneralNames.getInstance(dpName.getName()).getNames();
            }
            if (dpName.getType() == DistributionPointName.NAME_RELATIVE_TO_CRL_ISSUER)
            {
                if (dp.getCRLIssuer() != null)
                {
                    genNames = dp.getCRLIssuer().getNames();
                }
                else
                {
                    genNames = new GeneralName[]{ new GeneralName(certIssuer) };
                }
                for (int j = 0; j < genNames.length; j++)
                {
                    ASN1Sequence seq = ASN1Sequence.getInstance(genNames[j].getName().toASN1Primitive());

                    int count = seq.size();
                    ASN1EncodableVector vec = new ASN1EncodableVector(count + 1);
                    for (int i = 0; i < count; ++i)
                    {
                        vec.add(seq.getObjectAt(i));
                    }
                    vec.add(dpName.getName());

                    genNames[j] = new GeneralName(X500Name.getInstance(new DERSequence(vec)));
                }
            }
            if (genNames != null)
            {
                for (int j = 0; j < genNames.length; j++)
                {
                    if (names.contains(genNames[j]))
                    {
                        matches = true;
                        break;
                    }
                }
            }
            if (!matches)
            {
                // github #800: include the conflicting names so operators can see which CRL
                // was returned for which cert DP.
                throw new CRLValidatorException(
                    "No match for certificate CRL issuing distribution point name to cRLIssuer CRL distribution point."
                        + " cert DP names: " + java.util.Arrays.asList(genNames)
                        + "; CRL IDP names: " + names);
            }
        }
        // verify that one of the names in the IDP matches one of the names in the cRLIssuer
        // field of the DP
        else
        {
            if (dp.getCRLIssuer() == null)
            {
                throw new CRLValidatorException("Either the cRLIssuer or the distributionPoint field must "
                    + "be contained in DistributionPoint.");
            }
            GeneralName[] genNames = dp.getCRLIssuer().getNames();
            for (int j = 0; j < genNames.length; j++)
            {
                if (names.contains(genNames[j]))
                {
                    matches = true;
                    break;
                }
            }
            if (!matches)
            {
                // github #800: include the conflicting names so operators can see which CRL
                // was returned for which cert cRLIssuer.
                throw new CRLValidatorException(
                    "No match for certificate CRL issuing distribution point name to cRLIssuer CRL distribution point."
                        + " cert cRLIssuer names: " + java.util.Arrays.asList(genNames)
                        + "; CRL IDP names: " + names);
            }
        }
    }

    /**
     * RFC 5280 sec. 6.3.3 (b)(2)(ii)-(iv): the onlyContainsUserCerts, onlyContainsCACerts and
     * onlyContainsAttributeCerts checks.
     *
     * @param idp                  the CRL's issuing distribution point (may be null - no checks apply).
     * @param certBasicConstraints the certificate's basic constraints extension, null if absent.
     * @param isCertificate        true for a public key certificate, false for an attribute certificate.
     * @throws CRLValidatorException if the certificate is outside the CRL's asserted scope.
     */
    public static void checkOnlyContains(IssuingDistributionPoint idp, BasicConstraints certBasicConstraints,
        boolean isCertificate)
        throws CRLValidatorException
    {
        if (idp == null)
        {
            return;
        }

        if (isCertificate)
        {
            // (b) (2) (ii)
            if (idp.onlyContainsUserCerts() && (certBasicConstraints != null && certBasicConstraints.isCA()))
            {
                throw new CRLValidatorException("CA Cert CRL only contains user certificates.");
            }

            // (b) (2) (iii)
            if (idp.onlyContainsCACerts() && (certBasicConstraints == null || !certBasicConstraints.isCA()))
            {
                throw new CRLValidatorException("End CRL only contains CA certificates.");
            }
        }

        // (b) (2) (iv)
        if (idp.onlyContainsAttributeCerts())
        {
            throw new CRLValidatorException("onlyContainsAttributeCerts boolean is asserted.");
        }
    }

    /**
     * RFC 5280 sec. 6.3.3 (b)(1), cRLIssuer present in the DP: verify that the issuer field in
     * the complete CRL matches cRLIssuer in the DP and that the CRL is an indirect CRL.
     *
     * @param dp               the distribution point, with a cRLIssuer field present.
     * @param crlIssuerEncoded the DER encoding of the CRL's issuer name.
     * @param isIndirect       whether the CRL's issuing distribution point asserts indirectCRL.
     * @throws CRLValidatorException if the issuer does not match or the CRL is not indirect.
     */
    public static void checkCRLIssuer(DistributionPoint dp, byte[] crlIssuerEncoded, boolean isIndirect)
        throws CRLValidatorException
    {
        boolean matchIssuer = false;

        GeneralName[] genNames = dp.getCRLIssuer().getNames();
        for (int j = 0; j < genNames.length; j++)
        {
            if (genNames[j].getTagNo() == GeneralName.directoryName)
            {
                try
                {
                    if (Arrays.areEqual(genNames[j].getName().toASN1Primitive().getEncoded(), crlIssuerEncoded))
                    {
                        matchIssuer = true;
                    }
                }
                catch (IOException e)
                {
                    throw new CRLValidatorException(
                        "CRL issuer information from distribution point cannot be decoded.", e);
                }
            }
        }
        if (matchIssuer && !isIndirect)
        {
            throw new CRLValidatorException("Distribution point contains cRLIssuer field but CRL is not indirect.");
        }
        if (!matchIssuer)
        {
            throw new CRLValidatorException("CRL issuer of CRL does not match CRL issuer of distribution point.");
        }
    }

    /**
     * RFC 5280 sec. 6.3.3 (c)(2): the complete CRL and delta CRL must carry matching issuing
     * distribution point extensions (or both omit them).
     *
     * @throws CRLValidatorException if the issuing distribution points do not match.
     */
    public static void checkDeltaIssuingDistributionPoint(IssuingDistributionPoint completeIDP,
        IssuingDistributionPoint deltaIDP)
        throws CRLValidatorException
    {
        boolean match = false;
        if (completeIDP == null)
        {
            if (deltaIDP == null)
            {
                match = true;
            }
        }
        else
        {
            if (completeIDP.equals(deltaIDP))
            {
                match = true;
            }
        }
        if (!match)
        {
            throw new CRLValidatorException(
                "Issuing distribution point extension from delta CRL and complete CRL does not match.");
        }
    }

    /**
     * RFC 5280 sec. 6.3.3 (c)(3): the complete CRL and delta CRL must both carry an authority
     * key identifier, and the two must match.
     *
     * @throws CRLValidatorException if either key identifier is absent or they do not match.
     */
    public static void checkDeltaAuthorityKeyIdentifiers(ASN1Primitive completeKeyIdentifier,
        ASN1Primitive deltaKeyIdentifier)
        throws CRLValidatorException
    {
        if (completeKeyIdentifier == null)
        {
            throw new CRLValidatorException("CRL authority key identifier is null.");
        }

        if (deltaKeyIdentifier == null)
        {
            throw new CRLValidatorException("Delta CRL authority key identifier is null.");
        }

        if (!completeKeyIdentifier.equals(deltaKeyIdentifier))
        {
            throw new CRLValidatorException(
                "Delta CRL authority key identifier does not match complete CRL authority key identifier.");
        }
    }

    /**
     * RFC 5280 sec. 6.3.3 (i)/(j): whether a CRL entry's revocation takes effect for the
     * validation date - it does when the date is not before the entry's revocation date, and
     * additionally, whatever the dates, for the unspecified, keyCompromise, cACompromise and
     * aACompromise reasons.
     *
     * @param validDate      the date validation is being performed for.
     * @param revocationDate the CRL entry's revocation date.
     * @param reasonCodeValue the entry's {@link CRLReason} code, {@link CRLReason#unspecified} if absent.
     * @return true if the certificate is to be treated as revoked at validDate.
     */
    public static boolean isRevocationEffective(Date validDate, Date revocationDate,
        int reasonCodeValue)
    {
        return !(validDate.getTime() < revocationDate.getTime())
            || reasonCodeValue == CRLReason.unspecified
            || reasonCodeValue == CRLReason.keyCompromise
            || reasonCodeValue == CRLReason.cACompromise
            || reasonCodeValue == CRLReason.aACompromise;
    }

    /**
     * RFC 5280 sec. 6.3.3 (d)(1)-(d)(4): intersect the reasons asserted by the CRL's issuing
     * distribution point and the certificate's distribution point; absent reasons are
     * interpreted as all reasons.
     *
     * @return the intersected {@link ReasonFlags} reasons.
     */
    public static int intersectReasons(IssuingDistributionPoint idp, DistributionPoint dp)
    {
        int idpFlags = ALL_REASONS;
        if (idp != null && idp.getOnlySomeReasons() != null)
        {
            idpFlags = idp.getOnlySomeReasons().intValue();
        }

        int dpFlags = ALL_REASONS;
        if (dp.getReasons() != null)
        {
            dpFlags = dp.getReasons().intValue();
        }

        return idpFlags & dpFlags;
    }
}
