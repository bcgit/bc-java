package com.github.gv2011.bcasn.asn1.test;

import java.lang.reflect.Method;
import java.math.BigInteger;
import java.util.Date;
import java.util.Vector;

import com.github.gv2011.bcasn.asn1.ASN1EncodableVector;
import com.github.gv2011.bcasn.asn1.ASN1Enumerated;
import com.github.gv2011.bcasn.asn1.ASN1GeneralizedTime;
import com.github.gv2011.bcasn.asn1.ASN1Integer;
import com.github.gv2011.bcasn.asn1.ASN1Object;
import com.github.gv2011.bcasn.asn1.ASN1ObjectIdentifier;
import com.github.gv2011.bcasn.asn1.ASN1TaggedObject;
import com.github.gv2011.bcasn.asn1.ASN1UTCTime;
import com.github.gv2011.bcasn.asn1.DERBMPString;
import com.github.gv2011.bcasn.asn1.DERBitString;
import com.github.gv2011.bcasn.asn1.DERGeneralString;
import com.github.gv2011.bcasn.asn1.DERIA5String;
import com.github.gv2011.bcasn.asn1.DERNull;
import com.github.gv2011.bcasn.asn1.DERNumericString;
import com.github.gv2011.bcasn.asn1.DEROctetString;
import com.github.gv2011.bcasn.asn1.DERPrintableString;
import com.github.gv2011.bcasn.asn1.DERSequence;
import com.github.gv2011.bcasn.asn1.DERSet;
import com.github.gv2011.bcasn.asn1.DERT61String;
import com.github.gv2011.bcasn.asn1.DERTaggedObject;
import com.github.gv2011.bcasn.asn1.DERUTF8String;
import com.github.gv2011.bcasn.asn1.DERUniversalString;
import com.github.gv2011.bcasn.asn1.DERVisibleString;
import com.github.gv2011.bcasn.asn1.cmp.CAKeyUpdAnnContent;
import com.github.gv2011.bcasn.asn1.cmp.CMPCertificate;
import com.github.gv2011.bcasn.asn1.cmp.CRLAnnContent;
import com.github.gv2011.bcasn.asn1.cmp.CertConfirmContent;
import com.github.gv2011.bcasn.asn1.cmp.CertOrEncCert;
import com.github.gv2011.bcasn.asn1.cmp.CertRepMessage;
import com.github.gv2011.bcasn.asn1.cmp.CertResponse;
import com.github.gv2011.bcasn.asn1.cmp.CertifiedKeyPair;
import com.github.gv2011.bcasn.asn1.cmp.Challenge;
import com.github.gv2011.bcasn.asn1.cmp.ErrorMsgContent;
import com.github.gv2011.bcasn.asn1.cmp.GenMsgContent;
import com.github.gv2011.bcasn.asn1.cmp.GenRepContent;
import com.github.gv2011.bcasn.asn1.cmp.InfoTypeAndValue;
import com.github.gv2011.bcasn.asn1.cmp.KeyRecRepContent;
import com.github.gv2011.bcasn.asn1.cmp.OOBCertHash;
import com.github.gv2011.bcasn.asn1.cmp.PBMParameter;
import com.github.gv2011.bcasn.asn1.cmp.PKIBody;
import com.github.gv2011.bcasn.asn1.cmp.PKIConfirmContent;
import com.github.gv2011.bcasn.asn1.cmp.PKIFailureInfo;
import com.github.gv2011.bcasn.asn1.cmp.PKIFreeText;
import com.github.gv2011.bcasn.asn1.cmp.PKIHeader;
import com.github.gv2011.bcasn.asn1.cmp.PKIMessage;
import com.github.gv2011.bcasn.asn1.cmp.PKIMessages;
import com.github.gv2011.bcasn.asn1.cmp.PKIStatus;
import com.github.gv2011.bcasn.asn1.cmp.PKIStatusInfo;
import com.github.gv2011.bcasn.asn1.cmp.POPODecKeyChallContent;
import com.github.gv2011.bcasn.asn1.cmp.POPODecKeyRespContent;
import com.github.gv2011.bcasn.asn1.cmp.PollRepContent;
import com.github.gv2011.bcasn.asn1.cmp.PollReqContent;
import com.github.gv2011.bcasn.asn1.cmp.ProtectedPart;
import com.github.gv2011.bcasn.asn1.cmp.RevAnnContent;
import com.github.gv2011.bcasn.asn1.cmp.RevDetails;
import com.github.gv2011.bcasn.asn1.cmp.RevRepContent;
import com.github.gv2011.bcasn.asn1.cmp.RevReqContent;
import com.github.gv2011.bcasn.asn1.cms.Attribute;
import com.github.gv2011.bcasn.asn1.cms.Attributes;
import com.github.gv2011.bcasn.asn1.cms.AuthEnvelopedData;
import com.github.gv2011.bcasn.asn1.cms.AuthenticatedData;
import com.github.gv2011.bcasn.asn1.cms.CompressedData;
import com.github.gv2011.bcasn.asn1.cms.ContentInfo;
import com.github.gv2011.bcasn.asn1.cms.EncryptedContentInfo;
import com.github.gv2011.bcasn.asn1.cms.EncryptedData;
import com.github.gv2011.bcasn.asn1.cms.EnvelopedData;
import com.github.gv2011.bcasn.asn1.cms.Evidence;
import com.github.gv2011.bcasn.asn1.cms.IssuerAndSerialNumber;
import com.github.gv2011.bcasn.asn1.cms.KEKIdentifier;
import com.github.gv2011.bcasn.asn1.cms.KEKRecipientInfo;
import com.github.gv2011.bcasn.asn1.cms.KeyAgreeRecipientIdentifier;
import com.github.gv2011.bcasn.asn1.cms.KeyAgreeRecipientInfo;
import com.github.gv2011.bcasn.asn1.cms.KeyTransRecipientInfo;
import com.github.gv2011.bcasn.asn1.cms.MetaData;
import com.github.gv2011.bcasn.asn1.cms.OriginatorIdentifierOrKey;
import com.github.gv2011.bcasn.asn1.cms.OriginatorInfo;
import com.github.gv2011.bcasn.asn1.cms.OriginatorPublicKey;
import com.github.gv2011.bcasn.asn1.cms.OtherKeyAttribute;
import com.github.gv2011.bcasn.asn1.cms.OtherRecipientInfo;
import com.github.gv2011.bcasn.asn1.cms.PasswordRecipientInfo;
import com.github.gv2011.bcasn.asn1.cms.RecipientEncryptedKey;
import com.github.gv2011.bcasn.asn1.cms.RecipientIdentifier;
import com.github.gv2011.bcasn.asn1.cms.RecipientInfo;
import com.github.gv2011.bcasn.asn1.cms.RecipientKeyIdentifier;
import com.github.gv2011.bcasn.asn1.cms.SignerIdentifier;
import com.github.gv2011.bcasn.asn1.cms.SignerInfo;
import com.github.gv2011.bcasn.asn1.cms.TimeStampAndCRL;
import com.github.gv2011.bcasn.asn1.cms.TimeStampTokenEvidence;
import com.github.gv2011.bcasn.asn1.cms.TimeStampedData;
import com.github.gv2011.bcasn.asn1.cms.ecc.MQVuserKeyingMaterial;
import com.github.gv2011.bcasn.asn1.crmf.AttributeTypeAndValue;
import com.github.gv2011.bcasn.asn1.crmf.CertId;
import com.github.gv2011.bcasn.asn1.crmf.CertReqMessages;
import com.github.gv2011.bcasn.asn1.crmf.CertReqMsg;
import com.github.gv2011.bcasn.asn1.crmf.CertRequest;
import com.github.gv2011.bcasn.asn1.crmf.CertTemplate;
import com.github.gv2011.bcasn.asn1.crmf.Controls;
import com.github.gv2011.bcasn.asn1.crmf.EncKeyWithID;
import com.github.gv2011.bcasn.asn1.crmf.EncryptedKey;
import com.github.gv2011.bcasn.asn1.crmf.EncryptedValue;
import com.github.gv2011.bcasn.asn1.crmf.OptionalValidity;
import com.github.gv2011.bcasn.asn1.crmf.PKIArchiveOptions;
import com.github.gv2011.bcasn.asn1.crmf.PKIPublicationInfo;
import com.github.gv2011.bcasn.asn1.crmf.PKMACValue;
import com.github.gv2011.bcasn.asn1.crmf.POPOPrivKey;
import com.github.gv2011.bcasn.asn1.crmf.POPOSigningKey;
import com.github.gv2011.bcasn.asn1.crmf.POPOSigningKeyInput;
import com.github.gv2011.bcasn.asn1.crmf.ProofOfPossession;
import com.github.gv2011.bcasn.asn1.crmf.SinglePubInfo;
import com.github.gv2011.bcasn.asn1.cryptopro.ECGOST3410ParamSetParameters;
import com.github.gv2011.bcasn.asn1.cryptopro.GOST28147Parameters;
import com.github.gv2011.bcasn.asn1.cryptopro.GOST3410ParamSetParameters;
import com.github.gv2011.bcasn.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import com.github.gv2011.bcasn.asn1.eac.CVCertificate;
import com.github.gv2011.bcasn.asn1.eac.CVCertificateRequest;
import com.github.gv2011.bcasn.asn1.eac.CertificateBody;
import com.github.gv2011.bcasn.asn1.eac.PublicKeyDataObject;
import com.github.gv2011.bcasn.asn1.eac.RSAPublicKey;
import com.github.gv2011.bcasn.asn1.eac.UnsignedInteger;
import com.github.gv2011.bcasn.asn1.esf.CommitmentTypeIndication;
import com.github.gv2011.bcasn.asn1.esf.CommitmentTypeQualifier;
import com.github.gv2011.bcasn.asn1.esf.CompleteRevocationRefs;
import com.github.gv2011.bcasn.asn1.esf.CrlIdentifier;
import com.github.gv2011.bcasn.asn1.esf.CrlListID;
import com.github.gv2011.bcasn.asn1.esf.CrlOcspRef;
import com.github.gv2011.bcasn.asn1.esf.CrlValidatedID;
import com.github.gv2011.bcasn.asn1.esf.OcspIdentifier;
import com.github.gv2011.bcasn.asn1.esf.OcspListID;
import com.github.gv2011.bcasn.asn1.esf.OcspResponsesID;
import com.github.gv2011.bcasn.asn1.esf.OtherHash;
import com.github.gv2011.bcasn.asn1.esf.OtherHashAlgAndValue;
import com.github.gv2011.bcasn.asn1.esf.OtherRevRefs;
import com.github.gv2011.bcasn.asn1.esf.OtherRevVals;
import com.github.gv2011.bcasn.asn1.esf.RevocationValues;
import com.github.gv2011.bcasn.asn1.esf.SPUserNotice;
import com.github.gv2011.bcasn.asn1.esf.SPuri;
import com.github.gv2011.bcasn.asn1.esf.SigPolicyQualifierInfo;
import com.github.gv2011.bcasn.asn1.esf.SigPolicyQualifiers;
import com.github.gv2011.bcasn.asn1.esf.SignaturePolicyId;
import com.github.gv2011.bcasn.asn1.esf.SignaturePolicyIdentifier;
import com.github.gv2011.bcasn.asn1.esf.SignerAttribute;
import com.github.gv2011.bcasn.asn1.esf.SignerLocation;
import com.github.gv2011.bcasn.asn1.ess.ContentHints;
import com.github.gv2011.bcasn.asn1.ess.ContentIdentifier;
import com.github.gv2011.bcasn.asn1.ess.ESSCertID;
import com.github.gv2011.bcasn.asn1.ess.ESSCertIDv2;
import com.github.gv2011.bcasn.asn1.ess.OtherCertID;
import com.github.gv2011.bcasn.asn1.ess.OtherSigningCertificate;
import com.github.gv2011.bcasn.asn1.ess.SigningCertificate;
import com.github.gv2011.bcasn.asn1.ess.SigningCertificateV2;
import com.github.gv2011.bcasn.asn1.icao.CscaMasterList;
import com.github.gv2011.bcasn.asn1.icao.DataGroupHash;
import com.github.gv2011.bcasn.asn1.icao.LDSSecurityObject;
import com.github.gv2011.bcasn.asn1.icao.LDSVersionInfo;
import com.github.gv2011.bcasn.asn1.isismtt.ocsp.CertHash;
import com.github.gv2011.bcasn.asn1.isismtt.ocsp.RequestedCertificate;
import com.github.gv2011.bcasn.asn1.isismtt.x509.AdditionalInformationSyntax;
import com.github.gv2011.bcasn.asn1.isismtt.x509.AdmissionSyntax;
import com.github.gv2011.bcasn.asn1.isismtt.x509.Admissions;
import com.github.gv2011.bcasn.asn1.isismtt.x509.DeclarationOfMajority;
import com.github.gv2011.bcasn.asn1.isismtt.x509.MonetaryLimit;
import com.github.gv2011.bcasn.asn1.isismtt.x509.NamingAuthority;
import com.github.gv2011.bcasn.asn1.isismtt.x509.ProcurationSyntax;
import com.github.gv2011.bcasn.asn1.isismtt.x509.ProfessionInfo;
import com.github.gv2011.bcasn.asn1.isismtt.x509.Restriction;
import com.github.gv2011.bcasn.asn1.misc.CAST5CBCParameters;
import com.github.gv2011.bcasn.asn1.misc.IDEACBCPar;
import com.github.gv2011.bcasn.asn1.mozilla.PublicKeyAndChallenge;
import com.github.gv2011.bcasn.asn1.ocsp.BasicOCSPResponse;
import com.github.gv2011.bcasn.asn1.ocsp.CertID;
import com.github.gv2011.bcasn.asn1.ocsp.CertStatus;
import com.github.gv2011.bcasn.asn1.ocsp.CrlID;
import com.github.gv2011.bcasn.asn1.ocsp.OCSPRequest;
import com.github.gv2011.bcasn.asn1.ocsp.OCSPResponse;
import com.github.gv2011.bcasn.asn1.ocsp.OCSPResponseStatus;
import com.github.gv2011.bcasn.asn1.ocsp.Request;
import com.github.gv2011.bcasn.asn1.ocsp.ResponderID;
import com.github.gv2011.bcasn.asn1.ocsp.ResponseBytes;
import com.github.gv2011.bcasn.asn1.ocsp.ResponseData;
import com.github.gv2011.bcasn.asn1.ocsp.RevokedInfo;
import com.github.gv2011.bcasn.asn1.ocsp.Signature;
import com.github.gv2011.bcasn.asn1.ocsp.SingleResponse;
import com.github.gv2011.bcasn.asn1.ocsp.TBSRequest;
import com.github.gv2011.bcasn.asn1.oiw.OIWObjectIdentifiers;
import com.github.gv2011.bcasn.asn1.pkcs.AuthenticatedSafe;
import com.github.gv2011.bcasn.asn1.pkcs.CertificationRequest;
import com.github.gv2011.bcasn.asn1.pkcs.CertificationRequestInfo;
import com.github.gv2011.bcasn.asn1.pkcs.DHParameter;
import com.github.gv2011.bcasn.asn1.pkcs.EncryptedPrivateKeyInfo;
import com.github.gv2011.bcasn.asn1.pkcs.MacData;
import com.github.gv2011.bcasn.asn1.pkcs.PBEParameter;
import com.github.gv2011.bcasn.asn1.pkcs.PBES2Parameters;
import com.github.gv2011.bcasn.asn1.pkcs.PBKDF2Params;
import com.github.gv2011.bcasn.asn1.pkcs.PKCS12PBEParams;
import com.github.gv2011.bcasn.asn1.pkcs.Pfx;
import com.github.gv2011.bcasn.asn1.pkcs.PrivateKeyInfo;
import com.github.gv2011.bcasn.asn1.pkcs.RC2CBCParameter;
import com.github.gv2011.bcasn.asn1.pkcs.RSAESOAEPparams;
import com.github.gv2011.bcasn.asn1.pkcs.RSAPrivateKey;
import com.github.gv2011.bcasn.asn1.pkcs.RSASSAPSSparams;
import com.github.gv2011.bcasn.asn1.pkcs.SafeBag;
import com.github.gv2011.bcasn.asn1.pkcs.SignedData;
import com.github.gv2011.bcasn.asn1.sec.ECPrivateKey;
import com.github.gv2011.bcasn.asn1.smime.SMIMECapabilities;
import com.github.gv2011.bcasn.asn1.smime.SMIMECapability;
import com.github.gv2011.bcasn.asn1.tsp.Accuracy;
import com.github.gv2011.bcasn.asn1.tsp.MessageImprint;
import com.github.gv2011.bcasn.asn1.tsp.TSTInfo;
import com.github.gv2011.bcasn.asn1.tsp.TimeStampReq;
import com.github.gv2011.bcasn.asn1.tsp.TimeStampResp;
import com.github.gv2011.bcasn.asn1.x500.DirectoryString;
import com.github.gv2011.bcasn.asn1.x500.RDN;
import com.github.gv2011.bcasn.asn1.x500.X500Name;
import com.github.gv2011.bcasn.asn1.x509.AccessDescription;
import com.github.gv2011.bcasn.asn1.x509.AlgorithmIdentifier;
import com.github.gv2011.bcasn.asn1.x509.AttCertIssuer;
import com.github.gv2011.bcasn.asn1.x509.AttCertValidityPeriod;
import com.github.gv2011.bcasn.asn1.x509.AttributeCertificate;
import com.github.gv2011.bcasn.asn1.x509.AttributeCertificateInfo;
import com.github.gv2011.bcasn.asn1.x509.AuthorityInformationAccess;
import com.github.gv2011.bcasn.asn1.x509.AuthorityKeyIdentifier;
import com.github.gv2011.bcasn.asn1.x509.BasicConstraints;
import com.github.gv2011.bcasn.asn1.x509.CRLDistPoint;
import com.github.gv2011.bcasn.asn1.x509.CRLNumber;
import com.github.gv2011.bcasn.asn1.x509.CRLReason;
import com.github.gv2011.bcasn.asn1.x509.Certificate;
import com.github.gv2011.bcasn.asn1.x509.CertificateList;
import com.github.gv2011.bcasn.asn1.x509.CertificatePair;
import com.github.gv2011.bcasn.asn1.x509.CertificatePolicies;
import com.github.gv2011.bcasn.asn1.x509.DSAParameter;
import com.github.gv2011.bcasn.asn1.x509.DigestInfo;
import com.github.gv2011.bcasn.asn1.x509.DisplayText;
import com.github.gv2011.bcasn.asn1.x509.DistributionPoint;
import com.github.gv2011.bcasn.asn1.x509.DistributionPointName;
import com.github.gv2011.bcasn.asn1.x509.ExtendedKeyUsage;
import com.github.gv2011.bcasn.asn1.x509.Extensions;
import com.github.gv2011.bcasn.asn1.x509.GeneralName;
import com.github.gv2011.bcasn.asn1.x509.GeneralNames;
import com.github.gv2011.bcasn.asn1.x509.GeneralSubtree;
import com.github.gv2011.bcasn.asn1.x509.Holder;
import com.github.gv2011.bcasn.asn1.x509.IetfAttrSyntax;
import com.github.gv2011.bcasn.asn1.x509.IssuerSerial;
import com.github.gv2011.bcasn.asn1.x509.IssuingDistributionPoint;
import com.github.gv2011.bcasn.asn1.x509.NameConstraints;
import com.github.gv2011.bcasn.asn1.x509.NoticeReference;
import com.github.gv2011.bcasn.asn1.x509.ObjectDigestInfo;
import com.github.gv2011.bcasn.asn1.x509.PolicyInformation;
import com.github.gv2011.bcasn.asn1.x509.PolicyMappings;
import com.github.gv2011.bcasn.asn1.x509.PolicyQualifierInfo;
import com.github.gv2011.bcasn.asn1.x509.PrivateKeyUsagePeriod;
import com.github.gv2011.bcasn.asn1.x509.RoleSyntax;
import com.github.gv2011.bcasn.asn1.x509.SubjectDirectoryAttributes;
import com.github.gv2011.bcasn.asn1.x509.SubjectKeyIdentifier;
import com.github.gv2011.bcasn.asn1.x509.SubjectPublicKeyInfo;
import com.github.gv2011.bcasn.asn1.x509.TBSCertList;
import com.github.gv2011.bcasn.asn1.x509.TBSCertificate;
import com.github.gv2011.bcasn.asn1.x509.TBSCertificateStructure;
import com.github.gv2011.bcasn.asn1.x509.Target;
import com.github.gv2011.bcasn.asn1.x509.TargetInformation;
import com.github.gv2011.bcasn.asn1.x509.Targets;
import com.github.gv2011.bcasn.asn1.x509.Time;
import com.github.gv2011.bcasn.asn1.x509.UserNotice;
import com.github.gv2011.bcasn.asn1.x509.V2Form;
import com.github.gv2011.bcasn.asn1.x509.X509CertificateStructure;
import com.github.gv2011.bcasn.asn1.x509.X509Extensions;
import com.github.gv2011.bcasn.asn1.x509.qualified.BiometricData;
import com.github.gv2011.bcasn.asn1.x509.qualified.Iso4217CurrencyCode;
import com.github.gv2011.bcasn.asn1.x509.qualified.MonetaryValue;
import com.github.gv2011.bcasn.asn1.x509.qualified.QCStatement;
import com.github.gv2011.bcasn.asn1.x509.qualified.SemanticsInformation;
import com.github.gv2011.bcasn.asn1.x509.qualified.TypeOfBiometricData;
import com.github.gv2011.bcasn.asn1.x509.sigi.NameOrPseudonym;
import com.github.gv2011.bcasn.asn1.x509.sigi.PersonalData;
import com.github.gv2011.bcasn.asn1.x9.DHDomainParameters;
import com.github.gv2011.bcasn.asn1.x9.DHPublicKey;
import com.github.gv2011.bcasn.asn1.x9.DHValidationParms;
import com.github.gv2011.bcasn.asn1.x9.X962Parameters;
import com.github.gv2011.bcasn.asn1.x9.X9ECParameters;
import com.github.gv2011.bcasn.util.Integers;
import com.github.gv2011.bcasn.util.encoders.Base64;

import junit.framework.TestCase;

public class GetInstanceTest
    extends TestCase
{
    public static byte[]  attrCert = Base64.decode(
            "MIIHQDCCBqkCAQEwgZChgY2kgYowgYcxHDAaBgkqhkiG9w0BCQEWDW1sb3JjaEB2"
          + "dC5lZHUxHjAcBgNVBAMTFU1hcmt1cyBMb3JjaCAobWxvcmNoKTEbMBkGA1UECxMS"
          + "VmlyZ2luaWEgVGVjaCBVc2VyMRAwDgYDVQQLEwdDbGFzcyAyMQswCQYDVQQKEwJ2"
          + "dDELMAkGA1UEBhMCVVMwgYmkgYYwgYMxGzAZBgkqhkiG9w0BCQEWDHNzaGFoQHZ0"
          + "LmVkdTEbMBkGA1UEAxMSU3VtaXQgU2hhaCAoc3NoYWgpMRswGQYDVQQLExJWaXJn"
          + "aW5pYSBUZWNoIFVzZXIxEDAOBgNVBAsTB0NsYXNzIDExCzAJBgNVBAoTAnZ0MQsw"
          + "CQYDVQQGEwJVUzANBgkqhkiG9w0BAQQFAAIBBTAiGA8yMDAzMDcxODE2MDgwMloY"
          + "DzIwMDMwNzI1MTYwODAyWjCCBU0wggVJBgorBgEEAbRoCAEBMYIFORaCBTU8UnVs"
          + "ZSBSdWxlSWQ9IkZpbGUtUHJpdmlsZWdlLVJ1bGUiIEVmZmVjdD0iUGVybWl0Ij4K"
          + "IDxUYXJnZXQ+CiAgPFN1YmplY3RzPgogICA8U3ViamVjdD4KICAgIDxTdWJqZWN0"
          + "TWF0Y2ggTWF0Y2hJZD0idXJuOm9hc2lzOm5hbWVzOnRjOnhhY21sOjEuMDpmdW5j"
          + "dGlvbjpzdHJpbmctZXF1YWwiPgogICAgIDxBdHRyaWJ1dGVWYWx1ZSBEYXRhVHlw"
          + "ZT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjc3RyaW5nIj4KICAg"
          + "ICAgIENOPU1hcmt1cyBMb3JjaDwvQXR0cmlidXRlVmFsdWU+CiAgICAgPFN1Ympl"
          + "Y3RBdHRyaWJ1dGVEZXNpZ25hdG9yIEF0dHJpYnV0ZUlkPSJ1cm46b2FzaXM6bmFt"
          + "ZXM6dGM6eGFjbWw6MS4wOnN1YmplY3Q6c3ViamVjdC1pZCIgRGF0YVR5cGU9Imh0"
          + "dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hI3N0cmluZyIgLz4gCiAgICA8"
          + "L1N1YmplY3RNYXRjaD4KICAgPC9TdWJqZWN0PgogIDwvU3ViamVjdHM+CiAgPFJl"
          + "c291cmNlcz4KICAgPFJlc291cmNlPgogICAgPFJlc291cmNlTWF0Y2ggTWF0Y2hJ"
          + "ZD0idXJuOm9hc2lzOm5hbWVzOnRjOnhhY21sOjEuMDpmdW5jdGlvbjpzdHJpbmct"
          + "ZXF1YWwiPgogICAgIDxBdHRyaWJ1dGVWYWx1ZSBEYXRhVHlwZT0iaHR0cDovL3d3"
          + "dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjYW55VVJJIj4KICAgICAgaHR0cDovL3p1"
          + "bmkuY3MudnQuZWR1PC9BdHRyaWJ1dGVWYWx1ZT4KICAgICA8UmVzb3VyY2VBdHRy"
          + "aWJ1dGVEZXNpZ25hdG9yIEF0dHJpYnV0ZUlkPSJ1cm46b2FzaXM6bmFtZXM6dGM6"
          + "eGFjbWw6MS4wOnJlc291cmNlOnJlc291cmNlLWlkIiBEYXRhVHlwZT0iaHR0cDov"
          + "L3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjYW55VVJJIiAvPiAKICAgIDwvUmVz"
          + "b3VyY2VNYXRjaD4KICAgPC9SZXNvdXJjZT4KICA8L1Jlc291cmNlcz4KICA8QWN0"
          + "aW9ucz4KICAgPEFjdGlvbj4KICAgIDxBY3Rpb25NYXRjaCBNYXRjaElkPSJ1cm46"
          + "b2FzaXM6bmFtZXM6dGM6eGFjbWw6MS4wOmZ1bmN0aW9uOnN0cmluZy1lcXVhbCI+"
          + "CiAgICAgPEF0dHJpYnV0ZVZhbHVlIERhdGFUeXBlPSJodHRwOi8vd3d3LnczLm9y"
          + "Zy8yMDAxL1hNTFNjaGVtYSNzdHJpbmciPgpEZWxlZ2F0ZSBBY2Nlc3MgICAgIDwv"
          + "QXR0cmlidXRlVmFsdWU+CgkgIDxBY3Rpb25BdHRyaWJ1dGVEZXNpZ25hdG9yIEF0"
          + "dHJpYnV0ZUlkPSJ1cm46b2FzaXM6bmFtZXM6dGM6eGFjbWw6MS4wOmFjdGlvbjph"
          + "Y3Rpb24taWQiIERhdGFUeXBlPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNj"
          + "aGVtYSNzdHJpbmciIC8+IAogICAgPC9BY3Rpb25NYXRjaD4KICAgPC9BY3Rpb24+"
          + "CiAgPC9BY3Rpb25zPgogPC9UYXJnZXQ+CjwvUnVsZT4KMA0GCSqGSIb3DQEBBAUA"
          + "A4GBAGiJSM48XsY90HlYxGmGVSmNR6ZW2As+bot3KAfiCIkUIOAqhcphBS23egTr"
          + "6asYwy151HshbPNYz+Cgeqs45KkVzh7bL/0e1r8sDVIaaGIkjHK3CqBABnfSayr3"
          + "Rd1yBoDdEv8Qb+3eEPH6ab9021AsLEnJ6LWTmybbOpMNZ3tv");

    byte[]  cert1 = Base64.decode(
        "MIIDXjCCAsegAwIBAgIBBzANBgkqhkiG9w0BAQQFADCBtzELMAkGA1UEBhMCQVUx"
            + "ETAPBgNVBAgTCFZpY3RvcmlhMRgwFgYDVQQHEw9Tb3V0aCBNZWxib3VybmUxGjAY"
            + "BgNVBAoTEUNvbm5lY3QgNCBQdHkgTHRkMR4wHAYDVQQLExVDZXJ0aWZpY2F0ZSBB"
            + "dXRob3JpdHkxFTATBgNVBAMTDENvbm5lY3QgNCBDQTEoMCYGCSqGSIb3DQEJARYZ"
            + "d2VibWFzdGVyQGNvbm5lY3Q0LmNvbS5hdTAeFw0wMDA2MDIwNzU2MjFaFw0wMTA2"
            + "MDIwNzU2MjFaMIG4MQswCQYDVQQGEwJBVTERMA8GA1UECBMIVmljdG9yaWExGDAW"
            + "BgNVBAcTD1NvdXRoIE1lbGJvdXJuZTEaMBgGA1UEChMRQ29ubmVjdCA0IFB0eSBM"
            + "dGQxFzAVBgNVBAsTDldlYnNlcnZlciBUZWFtMR0wGwYDVQQDExR3d3cyLmNvbm5l"
            + "Y3Q0LmNvbS5hdTEoMCYGCSqGSIb3DQEJARYZd2VibWFzdGVyQGNvbm5lY3Q0LmNv"
            + "bS5hdTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEArvDxclKAhyv7Q/Wmr2re"
            + "Gw4XL9Cnh9e+6VgWy2AWNy/MVeXdlxzd7QAuc1eOWQkGQEiLPy5XQtTY+sBUJ3AO"
            + "Rvd2fEVJIcjf29ey7bYua9J/vz5MG2KYo9/WCHIwqD9mmG9g0xLcfwq/s8ZJBswE"
            + "7sb85VU+h94PTvsWOsWuKaECAwEAAaN3MHUwJAYDVR0RBB0wG4EZd2VibWFzdGVy"
            + "QGNvbm5lY3Q0LmNvbS5hdTA6BglghkgBhvhCAQ0ELRYrbW9kX3NzbCBnZW5lcmF0"
            + "ZWQgY3VzdG9tIHNlcnZlciBjZXJ0aWZpY2F0ZTARBglghkgBhvhCAQEEBAMCBkAw"
            + "DQYJKoZIhvcNAQEEBQADgYEAotccfKpwSsIxM1Hae8DR7M/Rw8dg/RqOWx45HNVL"
            + "iBS4/3N/TO195yeQKbfmzbAA2jbPVvIvGgTxPgO1MP4ZgvgRhasaa0qCJCkWvpM4"
            + "yQf33vOiYQbpv4rTwzU8AmRlBG45WdjyNIigGV+oRc61aKCTnLq7zB8N3z1TF/bF"
            + "5/8=");

    private final byte[] v2CertList = Base64.decode(
          "MIICjTCCAfowDQYJKoZIhvcNAQECBQAwXzELMAkGA1UEBhMCVVMxIDAeBgNVBAoT"
        + "F1JTQSBEYXRhIFNlY3VyaXR5LCBJbmMuMS4wLAYDVQQLEyVTZWN1cmUgU2VydmVy"
        + "IENlcnRpZmljYXRpb24gQXV0aG9yaXR5Fw05NTA1MDIwMjEyMjZaFw05NTA2MDEw"
        + "MDAxNDlaMIIBaDAWAgUCQQAABBcNOTUwMjAxMTcyNDI2WjAWAgUCQQAACRcNOTUw"
        + "MjEwMDIxNjM5WjAWAgUCQQAADxcNOTUwMjI0MDAxMjQ5WjAWAgUCQQAADBcNOTUw"
        + "MjI1MDA0NjQ0WjAWAgUCQQAAGxcNOTUwMzEzMTg0MDQ5WjAWAgUCQQAAFhcNOTUw"
        + "MzE1MTkxNjU0WjAWAgUCQQAAGhcNOTUwMzE1MTk0MDQxWjAWAgUCQQAAHxcNOTUw"
        + "MzI0MTk0NDMzWjAWAgUCcgAABRcNOTUwMzI5MjAwNzExWjAWAgUCcgAAERcNOTUw"
        + "MzMwMDIzNDI2WjAWAgUCQQAAIBcNOTUwNDA3MDExMzIxWjAWAgUCcgAAHhcNOTUw"
        + "NDA4MDAwMjU5WjAWAgUCcgAAQRcNOTUwNDI4MTcxNzI0WjAWAgUCcgAAOBcNOTUw"
        + "NDI4MTcyNzIxWjAWAgUCcgAATBcNOTUwNTAyMDIxMjI2WjANBgkqhkiG9w0BAQIF"
        + "AAN+AHqOEJXSDejYy0UwxxrH/9+N2z5xu/if0J6qQmK92W0hW158wpJg+ovV3+wQ"
        + "wvIEPRL2rocL0tKfAsVq1IawSJzSNgxG0lrcla3MrJBnZ4GaZDu4FutZh72MR3Gt"
        + "JaAL3iTJHJD55kK2D/VoyY1djlsPuNh6AEgdVwFAyp0v");

    private static final Object[] NULL_ARGS = new Object[] { null };

    private void doFullGetInstanceTest(final Class clazz, final ASN1Object o1)
        throws Exception
    {
        Method m;

        try
        {
            m = clazz.getMethod("getInstance", Object.class);
        }
        catch (final NoSuchMethodException e)
        {
            fail("no getInstance method found");
            return;
        }

        ASN1Object o2 = (ASN1Object)m.invoke(clazz, NULL_ARGS);
        if (o2 != null)
        {
            fail(clazz.getName() + " null failed");
        }

        o2 = (ASN1Object)m.invoke(clazz, o1);

        if (!o1.equals(o2) || !clazz.isInstance(o2))
        {
            fail(clazz.getName() + " equality failed");
        }

        o2 = (ASN1Object)m.invoke(clazz, o1.getEncoded());
        if (!o1.equals(o2) || !clazz.isInstance(o2))
        {
            fail(clazz.getName() + " encoded equality failed");
        }

        o2 = (ASN1Object)m.invoke(clazz, o1.toASN1Primitive());
        if (!o1.equals(o2) || !clazz.isInstance(o2))
        {
            fail(clazz.getName() + " sequence equality failed");
        }

        try
        {
            m = clazz.getMethod("getInstance", ASN1TaggedObject.class, Boolean.TYPE);
        }
        catch (final NoSuchMethodException e)
        {
            return;
        }

        ASN1TaggedObject t = new DERTaggedObject(true, 0, o1);
        o2 = (ASN1Object)m.invoke(clazz, t, true);
        if (!o1.equals(o2) || !clazz.isInstance(o2))
        {
            fail(clazz.getName() + " tag equality failed");
        }

        t = new DERTaggedObject(true, 0, o1.toASN1Primitive());
        o2 = (ASN1Object)m.invoke(clazz, t, true);
        if (!o1.equals(o2) || !clazz.isInstance(o2))
        {
            fail(clazz.getName() + " tag equality failed");
        }

        t = ASN1TaggedObject.getInstance(t.getEncoded());
        o2 = (ASN1Object)m.invoke(clazz, t, true);
        if (!o1.equals(o2) || !clazz.isInstance(o2))
        {
            fail(clazz.getName() + " tag equality failed");
        }

        t = new DERTaggedObject(false, 0, o1);
        o2 = (ASN1Object)m.invoke(clazz, t, false);
        if (!o1.equals(o2) || !clazz.isInstance(o2))
        {
            fail(clazz.getName() + " tag equality failed");
        }

        t = new DERTaggedObject(false, 0, o1.toASN1Primitive());
        o2 = (ASN1Object)m.invoke(clazz, t, false);
        if (!o1.equals(o2) || !clazz.isInstance(o2))
        {
            fail(clazz.getName() + " tag equality failed");
        }

        t = ASN1TaggedObject.getInstance(t.getEncoded());
        o2 = (ASN1Object)m.invoke(clazz, t, false);
        if (!o1.equals(o2) || !clazz.isInstance(o2))
        {
            fail(clazz.getName() + " tag equality failed");
        }
    }

    public void testGetInstance()
        throws Exception
    {
        doFullGetInstanceTest(DERPrintableString.class, new DERPrintableString("hello world"));
        doFullGetInstanceTest(DERBMPString.class, new DERBMPString("hello world"));
        doFullGetInstanceTest(DERUTF8String.class, new DERUTF8String("hello world"));
        doFullGetInstanceTest(DERUniversalString.class, new DERUniversalString(new byte[20]));
        doFullGetInstanceTest(DERIA5String.class, new DERIA5String("hello world"));
        doFullGetInstanceTest(DERGeneralString.class, new DERGeneralString("hello world"));
        doFullGetInstanceTest(DERNumericString.class, new DERNumericString("hello world"));
        doFullGetInstanceTest(DERNumericString.class, new DERNumericString("99999", true));
        doFullGetInstanceTest(DERT61String.class, new DERT61String("hello world"));
        doFullGetInstanceTest(DERVisibleString.class, new DERVisibleString("hello world"));

        doFullGetInstanceTest(ASN1Integer.class, new ASN1Integer(1));
        doFullGetInstanceTest(ASN1GeneralizedTime.class, new ASN1GeneralizedTime(new Date()));
        doFullGetInstanceTest(ASN1UTCTime.class, new ASN1UTCTime(new Date()));
        doFullGetInstanceTest(ASN1Enumerated.class, new ASN1Enumerated(1));

        final CMPCertificate cmpCert = new CMPCertificate(Certificate.getInstance(cert1));
        final CertificateList crl = CertificateList.getInstance(v2CertList);
        final AttributeCertificate attributeCert = AttributeCertificate.getInstance(attrCert);

        doFullGetInstanceTest(CAKeyUpdAnnContent.class, new CAKeyUpdAnnContent(cmpCert, cmpCert, cmpCert));

        CertConfirmContent.getInstance(null);
        CertifiedKeyPair.getInstance(null);
        CertOrEncCert.getInstance(null);
        CertRepMessage.getInstance(null);
        doFullGetInstanceTest(CertResponse.class, new CertResponse(new ASN1Integer(1), new PKIStatusInfo(PKIStatus.granted)));
        doFullGetInstanceTest(com.github.gv2011.bcasn.asn1.cmp.CertStatus.class, new com.github.gv2011.bcasn.asn1.cmp.CertStatus(new byte[10], BigInteger.valueOf(1), new PKIStatusInfo(PKIStatus.granted)));
        doFullGetInstanceTest(Challenge.class, new Challenge(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE), new byte[10], new byte[10]));

        doFullGetInstanceTest(CMPCertificate.class, cmpCert);
        doFullGetInstanceTest(CRLAnnContent.class, new CRLAnnContent(crl));
        doFullGetInstanceTest(ErrorMsgContent.class, new ErrorMsgContent(new PKIStatusInfo(PKIStatus.granted), new ASN1Integer(1), new PKIFreeText("fred")));
        GenMsgContent.getInstance(null);
        GenRepContent.getInstance(null);
        InfoTypeAndValue.getInstance(null);
        KeyRecRepContent.getInstance(null);
        OOBCertHash.getInstance(null);
        PBMParameter.getInstance(null);
        PKIBody.getInstance(null);
        PKIConfirmContent.getInstance(null);
        PKIFreeText.getInstance(null);
        doFullGetInstanceTest(PKIFreeText.class, new PKIFreeText("hello world"));
        doFullGetInstanceTest(PKIFreeText.class, new PKIFreeText(new String[]{"hello", "world"}));
        doFullGetInstanceTest(PKIFreeText.class, new PKIFreeText(new DERUTF8String[]{new DERUTF8String("hello"), new DERUTF8String("world")}));
        PKIHeader.getInstance(null);
        PKIMessage.getInstance(null);
        PKIMessages.getInstance(null);
        doFullGetInstanceTest(PKIStatusInfo.class, new PKIStatusInfo(PKIStatus.rejection, new PKIFreeText("hello world"), new PKIFailureInfo(PKIFailureInfo.badAlg)));
        doFullGetInstanceTest(PKIStatusInfo.class, new PKIStatusInfo(PKIStatus.granted, new PKIFreeText("hello world")));
        PKIStatus.getInstance(null);
        PollRepContent.getInstance(null);
        PollReqContent.getInstance(null);
        POPODecKeyChallContent.getInstance(null);
        POPODecKeyRespContent.getInstance(null);
        ProtectedPart.getInstance(null);
        RevAnnContent.getInstance(null);
        RevDetails.getInstance(null);
        RevRepContent.getInstance(null);
        RevReqContent.getInstance(null);
        Attribute.getInstance(null);
        Attributes.getInstance(null);
        AuthenticatedData.getInstance(null);
        AuthenticatedData.getInstance(null);
        AuthEnvelopedData.getInstance(null);
        AuthEnvelopedData.getInstance(null);
        CompressedData.getInstance(null);
        CompressedData.getInstance(null);
        ContentInfo.getInstance(null);
        EncryptedContentInfo.getInstance(null);
        EncryptedData.getInstance(null);
        EnvelopedData.getInstance(null);
        EnvelopedData.getInstance(null);
        Evidence.getInstance(null);
        IssuerAndSerialNumber.getInstance(null);
        KEKIdentifier.getInstance(null);
        KEKIdentifier.getInstance(null);
        KEKRecipientInfo.getInstance(null);
        KEKRecipientInfo.getInstance(null);
        KeyAgreeRecipientIdentifier.getInstance(null);
        KeyAgreeRecipientIdentifier.getInstance(null);
        KeyAgreeRecipientInfo.getInstance(null);
        KeyAgreeRecipientInfo.getInstance(null);
        KeyTransRecipientInfo.getInstance(null);
        MetaData.getInstance(null);
        OriginatorIdentifierOrKey.getInstance(null);
        OriginatorIdentifierOrKey.getInstance(null);
        OriginatorInfo.getInstance(null);
        OriginatorInfo.getInstance(null);
        OriginatorPublicKey.getInstance(null);
        OriginatorPublicKey.getInstance(null);
        OtherKeyAttribute.getInstance(null);
        OtherRecipientInfo.getInstance(null);
        OtherRecipientInfo.getInstance(null);
        PasswordRecipientInfo.getInstance(null);
        PasswordRecipientInfo.getInstance(null);
        RecipientEncryptedKey.getInstance(null);
        RecipientIdentifier.getInstance(null);
        RecipientInfo.getInstance(null);
        RecipientKeyIdentifier.getInstance(null);
        RecipientKeyIdentifier.getInstance(null);
        SignedData.getInstance(null);
        SignerIdentifier.getInstance(null);
        SignerInfo.getInstance(null);
        Time.getInstance(null);
        Time.getInstance(null);
        TimeStampAndCRL.getInstance(null);
        TimeStampedData.getInstance(null);
        TimeStampTokenEvidence.getInstance(null);
        AttributeTypeAndValue.getInstance(null);

        doFullGetInstanceTest(CertId.class, new CertId(new GeneralName(new X500Name("CN=Test")), BigInteger.valueOf(1)));


        CertReqMessages.getInstance(null);
        CertReqMsg.getInstance(null);
        CertRequest.getInstance(null);
        CertTemplate.getInstance(null);
        Controls.getInstance(null);
        EncKeyWithID.getInstance(null);
        EncryptedKey.getInstance(null);
        EncryptedValue.getInstance(null);
        OptionalValidity.getInstance(null);
        PKIArchiveOptions.getInstance(null);
        PKIPublicationInfo.getInstance(null);
        PKMACValue.getInstance(null);
        PKMACValue.getInstance(null);
        POPOPrivKey.getInstance(null);
        POPOSigningKeyInput.getInstance(null);
        POPOSigningKey.getInstance(null);
        POPOSigningKey.getInstance(null);
        ProofOfPossession.getInstance(null);
        SinglePubInfo.getInstance(null);
        ECGOST3410ParamSetParameters.getInstance(null);
        ECGOST3410ParamSetParameters.getInstance(null);
        GOST28147Parameters.getInstance(null);
        GOST28147Parameters.getInstance(null);
        GOST3410ParamSetParameters.getInstance(null);
        GOST3410ParamSetParameters.getInstance(null);
        GOST3410PublicKeyAlgParameters.getInstance(null);
        GOST3410PublicKeyAlgParameters.getInstance(null);
        CertificateBody.getInstance(null);
        CVCertificate.getInstance(null);
        CVCertificateRequest.getInstance(null);
        PublicKeyDataObject.getInstance(null);
        UnsignedInteger.getInstance(null);
        CommitmentTypeIndication.getInstance(null);
        CommitmentTypeQualifier.getInstance(null);

        final OcspIdentifier ocspIdentifier = new OcspIdentifier(new ResponderID(new X500Name("CN=Test")), new ASN1GeneralizedTime(new Date()));
        final CrlListID crlListID = new CrlListID(new CrlValidatedID[]{new CrlValidatedID(new OtherHash(new byte[20]))});
        final OcspListID ocspListID = new OcspListID(new OcspResponsesID[] { new OcspResponsesID(ocspIdentifier) });
        final OtherRevRefs otherRevRefs = new OtherRevRefs(new ASN1ObjectIdentifier("1.2.1"), new DERSequence());
        final OtherRevVals otherRevVals = new OtherRevVals(new ASN1ObjectIdentifier("1.2.1"), new DERSequence());
        final CrlOcspRef crlOcspRef = new CrlOcspRef(crlListID, ocspListID, otherRevRefs);
        doFullGetInstanceTest(CompleteRevocationRefs.class, new CompleteRevocationRefs(new CrlOcspRef[]{crlOcspRef, crlOcspRef}));

        doFullGetInstanceTest(CrlIdentifier.class, new CrlIdentifier(new X500Name("CN=Test"), new ASN1UTCTime(new Date()), BigInteger.valueOf(1)));


        doFullGetInstanceTest(CrlListID.class, crlListID);
        doFullGetInstanceTest(CrlOcspRef.class, crlOcspRef);
        doFullGetInstanceTest(CrlValidatedID.class, new CrlValidatedID(new OtherHash(new byte[20])));
        doFullGetInstanceTest(OcspIdentifier.class, ocspIdentifier);
        doFullGetInstanceTest(OcspListID.class, ocspListID);
        doFullGetInstanceTest(OcspResponsesID.class, new OcspResponsesID(ocspIdentifier));

        final OtherHashAlgAndValue otherHashAlgAndValue = new OtherHashAlgAndValue(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE), new DEROctetString(new byte[10]));
        doFullGetInstanceTest(OtherHashAlgAndValue.class, otherHashAlgAndValue);
        OtherHash.getInstance(null);
        doFullGetInstanceTest(OtherRevRefs.class, otherRevRefs);
        doFullGetInstanceTest(OtherRevVals.class, otherRevVals);
        doFullGetInstanceTest(RevocationValues.class, new RevocationValues(new CertificateList[]{crl}, null, otherRevVals));

        final SignaturePolicyId signaturePolicyId = new SignaturePolicyId(new ASN1ObjectIdentifier("1.2.1"), otherHashAlgAndValue);
        doFullGetInstanceTest(SignaturePolicyIdentifier.class, new SignaturePolicyIdentifier());
        doFullGetInstanceTest(SignaturePolicyIdentifier.class, new SignaturePolicyIdentifier(signaturePolicyId));
        doFullGetInstanceTest(SignaturePolicyId.class, signaturePolicyId);
        doFullGetInstanceTest(SignerAttribute.class, new SignerAttribute(
          new com.github.gv2011.bcasn.asn1.x509.Attribute[]{
            new com.github.gv2011.bcasn.asn1.x509.Attribute(new ASN1ObjectIdentifier("1.2.1"), new DERSet())
          }
        ));
        doFullGetInstanceTest(SignerAttribute.class, new SignerAttribute(attributeCert));

        final ASN1EncodableVector postalAddr = new ASN1EncodableVector();

        postalAddr.add(new DERUTF8String("line 1"));
        postalAddr.add(new DERUTF8String("line 2"));

        doFullGetInstanceTest(SignerLocation.class, new SignerLocation(new DERUTF8String("AU"), new DERUTF8String("Melbourne"), new DERSequence(postalAddr)));
        doFullGetInstanceTest(SigPolicyQualifierInfo.class, new SigPolicyQualifierInfo(new ASN1ObjectIdentifier("1.2.1"), new DERSequence()));
        SigPolicyQualifiers.getInstance(null);
        SPuri.getInstance(null);
        final Vector v = new Vector();

        v.add(Integers.valueOf(1));
        v.add(BigInteger.valueOf(2));
        final NoticeReference noticeReference = new NoticeReference("BC", v);
        doFullGetInstanceTest(SPUserNotice.class, new SPUserNotice(noticeReference, new DisplayText("hello world")));
        ContentHints.getInstance(null);
        ContentIdentifier.getInstance(null);
        ESSCertID.getInstance(null);
        ESSCertIDv2.getInstance(null);
        OtherCertID.getInstance(null);
        OtherSigningCertificate.getInstance(null);
        SigningCertificate.getInstance(null);
        SigningCertificateV2.getInstance(null);
        CscaMasterList.getInstance(null);
        DataGroupHash.getInstance(null);
        LDSSecurityObject.getInstance(null);
        LDSVersionInfo.getInstance(null);
        CAST5CBCParameters.getInstance(null);
        IDEACBCPar.getInstance(null);
        PublicKeyAndChallenge.getInstance(null);
        BasicOCSPResponse.getInstance(null);
        BasicOCSPResponse.getInstance(null);

        doFullGetInstanceTest(CertID.class, new CertID(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE), new DEROctetString(new byte[1]), new DEROctetString(new byte[1]), new ASN1Integer(1)));

        CertStatus.getInstance(null);
        CertStatus.getInstance(null);
        CrlID.getInstance(null);
        OCSPRequest.getInstance(null);
        OCSPRequest.getInstance(null);
        OCSPResponse.getInstance(null);
        OCSPResponse.getInstance(null);
        OCSPResponseStatus.getInstance(null);
        Request.getInstance(null);
        Request.getInstance(null);
        ResponderID.getInstance(null);
        ResponderID.getInstance(null);
        ResponseBytes.getInstance(null);
        ResponseBytes.getInstance(null);
        ResponseData.getInstance(null);
        ResponseData.getInstance(null);
        RevokedInfo.getInstance(null);
        RevokedInfo.getInstance(null);
        Signature.getInstance(null);
        Signature.getInstance(null);
        SingleResponse.getInstance(null);
        SingleResponse.getInstance(null);
        TBSRequest.getInstance(null);
        TBSRequest.getInstance(null);
        Attribute.getInstance(null);
        AuthenticatedSafe.getInstance(null);
        CertificationRequestInfo.getInstance(null);
        CertificationRequest.getInstance(null);
        ContentInfo.getInstance(null);
        DHParameter.getInstance(null);
        EncryptedData.getInstance(null);
        EncryptedPrivateKeyInfo.getInstance(null);
        AlgorithmIdentifier.getInstance(null);
        IssuerAndSerialNumber.getInstance(null);
        MacData.getInstance(null);
        PBEParameter.getInstance(null);
        PBES2Parameters.getInstance(null);
        PBKDF2Params.getInstance(null);
        Pfx.getInstance(null);
        PKCS12PBEParams.getInstance(null);
        PrivateKeyInfo.getInstance(null);
        PrivateKeyInfo.getInstance(null);
        RC2CBCParameter.getInstance(null);
        RSAESOAEPparams.getInstance(null);
        RSAPrivateKey.getInstance(null);
        RSAPrivateKey.getInstance(null);
        RSAPublicKey.getInstance(null);
        RSAPublicKey.getInstance(null);
        RSASSAPSSparams.getInstance(null);
        SafeBag.getInstance(null);
        SignedData.getInstance(null);
        SignerInfo.getInstance(null);
        ECPrivateKey.getInstance(null);
        SMIMECapabilities.getInstance(null);
        SMIMECapability.getInstance(null);
        Accuracy.getInstance(null);
        MessageImprint.getInstance(null);
        TimeStampReq.getInstance(null);
        TimeStampResp.getInstance(null);
        TSTInfo.getInstance(null);
        AttributeTypeAndValue.getInstance(null);
        DirectoryString.getInstance(null);
        DirectoryString.getInstance(null);
        RDN.getInstance(null);
        X500Name.getInstance(null);
        X500Name.getInstance(null);
        AccessDescription.getInstance(null);
        AlgorithmIdentifier.getInstance(null);
        AlgorithmIdentifier.getInstance(null);
        AttCertIssuer.getInstance(null);
        AttCertIssuer.getInstance(null);
        AttCertValidityPeriod.getInstance(null);
        AttributeCertificateInfo.getInstance(null);
        AttributeCertificateInfo.getInstance(null);
        AttributeCertificate.getInstance(null);
        Attribute.getInstance(null);
        AuthorityInformationAccess.getInstance(null);
        AuthorityKeyIdentifier.getInstance(null);
        AuthorityKeyIdentifier.getInstance(null);
        BasicConstraints.getInstance(null);
        BasicConstraints.getInstance(null);
        Certificate.getInstance(null);
        Certificate.getInstance(null);
        CertificateList.getInstance(null);
        CertificateList.getInstance(null);
        CertificatePair.getInstance(null);
        CertificatePolicies.getInstance(null);
        CertificatePolicies.getInstance(null);
        CRLDistPoint.getInstance(null);
        CRLDistPoint.getInstance(null);
        CRLNumber.getInstance(null);
        CRLReason.getInstance(null);
        DigestInfo.getInstance(null);
        DigestInfo.getInstance(null);
        DisplayText.getInstance(null);
        DisplayText.getInstance(null);
        DistributionPoint.getInstance(null);
        DistributionPoint.getInstance(null);
        DistributionPointName.getInstance(null);
        DistributionPointName.getInstance(null);
        DSAParameter.getInstance(null);
        DSAParameter.getInstance(null);
        ExtendedKeyUsage.getInstance(null);
        ExtendedKeyUsage.getInstance(null);
        Extensions.getInstance(null);
        Extensions.getInstance(null);
        GeneralName.getInstance(null);
        GeneralName.getInstance(null);
        GeneralNames.getInstance(null);
        GeneralNames.getInstance(null);

        final GeneralSubtree generalSubtree = new GeneralSubtree(new GeneralName(new X500Name("CN=Test")));
        final ASN1ObjectIdentifier algOid = new ASN1ObjectIdentifier("1.2.1");
        final ObjectDigestInfo objectDigestInfo = new ObjectDigestInfo(ObjectDigestInfo.otherObjectDigest, algOid, new AlgorithmIdentifier(algOid), new byte[20]);

        doFullGetInstanceTest(GeneralSubtree.class, generalSubtree);
        doFullGetInstanceTest(Holder.class, new Holder(objectDigestInfo));
        IetfAttrSyntax.getInstance(null);
        IssuerSerial.getInstance(null);
        IssuerSerial.getInstance(null);
        IssuingDistributionPoint.getInstance(null);
        IssuingDistributionPoint.getInstance(null);
        DERBitString.getInstance(null);

        v.clear();
        v.add(generalSubtree);

        doFullGetInstanceTest(NameConstraints.class, new NameConstraints(null, null));
        doFullGetInstanceTest(NoticeReference.class, noticeReference);
        doFullGetInstanceTest(ObjectDigestInfo.class, objectDigestInfo);

        PolicyInformation.getInstance(null);
        PolicyMappings.getInstance(null);
        PolicyQualifierInfo.getInstance(null);
        PrivateKeyUsagePeriod.getInstance(null);
        doFullGetInstanceTest(RoleSyntax.class, new RoleSyntax(new GeneralNames(new GeneralName(new X500Name("CN=Test"))), new GeneralName(GeneralName.uniformResourceIdentifier, "http://bc")));
        RSAPublicKey.getInstance(null);
        SubjectDirectoryAttributes.getInstance(null);
        SubjectKeyIdentifier.getInstance(null);
        SubjectKeyIdentifier.getInstance(null);
        SubjectPublicKeyInfo.getInstance(null);
        SubjectPublicKeyInfo.getInstance(null);
        TargetInformation.getInstance(null);
        Target.getInstance(null);
        Targets.getInstance(null);
        TBSCertificate.getInstance(null);
        TBSCertificate.getInstance(null);
        TBSCertificateStructure.getInstance(null);
        TBSCertificateStructure.getInstance(null);
        TBSCertList.CRLEntry.getInstance(null);
        TBSCertList.getInstance(null);
        TBSCertList.getInstance(null);
        Time.getInstance(null);
        Time.getInstance(null);
        doFullGetInstanceTest(UserNotice.class, new UserNotice(noticeReference, "hello world"));
        V2Form.getInstance(null);
        V2Form.getInstance(null);
        X509CertificateStructure.getInstance(null);
        X509CertificateStructure.getInstance(null);
        X509Extensions.getInstance(null);
        X509Extensions.getInstance(null);
        X500Name.getInstance(null);
        X500Name.getInstance(null);
        DHDomainParameters.getInstance(null);
        DHDomainParameters.getInstance(null);
        DHPublicKey.getInstance(null);
        DHPublicKey.getInstance(null);
        DHValidationParms.getInstance(null);
        DHValidationParms.getInstance(null);
        X962Parameters.getInstance(null);
        X962Parameters.getInstance(null);
        X9ECParameters.getInstance(null);
        MQVuserKeyingMaterial.getInstance(null);
        MQVuserKeyingMaterial.getInstance(null);
        CertHash.getInstance(null);
        RequestedCertificate.getInstance(null);
        RequestedCertificate.getInstance(null);
        AdditionalInformationSyntax.getInstance(null);
        Admissions.getInstance(null);
        AdmissionSyntax.getInstance(null);
        DeclarationOfMajority.getInstance(null);
        MonetaryLimit.getInstance(null);
        NamingAuthority.getInstance(null);
        NamingAuthority.getInstance(null);
        ProcurationSyntax.getInstance(null);
        ProfessionInfo.getInstance(null);
        Restriction.getInstance(null);
        BiometricData.getInstance(null);
        Iso4217CurrencyCode.getInstance(null);
        MonetaryValue.getInstance(null);
        QCStatement.getInstance(null);
        SemanticsInformation.getInstance(null);
        TypeOfBiometricData.getInstance(null);
        NameOrPseudonym.getInstance(null);
        PersonalData.getInstance(null);
    }

    @Override
    public String getName()
    {
        return "GetInstanceNullTest";
    }
}
