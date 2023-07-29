#
# JDK 1.2 edits

ed org/bouncycastle/gpg/SExpression.java <<%
g/\.\.\. /s//[]/g
w
q
%


ed org/bouncycastle/asn1/ASN1Integer.java <<%
g/private final byte.. bytes;/s/final//
w
q
%


ed org/bouncycastle/cert/cmp/CMSProcessableCMPCertificate.java <<%
g/private final .*/s/final//
w
q
%

(
cd  org/bouncycastle/asn1/; 
for i in *.java
do
ed $i <<%%
g/final .* contents/s/final//
g/final .* start/s/final//
w
q
%%
done

ed test/RegressionTest.java <<%%
g/new MiscTest()/s//\/\/ &/
w
q
%%
)

(
cd  org/bouncycastle/crypto 
for i in engines/*.java digests/*.java hpke/*.java params/*.java
do
echo $i
ed $i <<%%
g/final .* contents/s/final//
g/final .* start/s/final//
g/private final .*/s/final//
w
q
%%
done
)

ed org/bouncycastle/crypto/generators/ECKeyPairGenerator.java <<%
g/private final .*/s/final//
w
w
q
%

ed org/bouncycastle/asn1/x509/AltSignatureAlgorithm.java <<%
g/private final .*/s/final//
w
w
q
%

ed org/bouncycastle/asn1/cms/CMSORIforKEMOtherInfo.java <<%
g/private final .*/s/final//
w
w
q
%

ed org/bouncycastle/asn1/ASN1TaggedObject.java <<%
g/final .* explicitness;/s/final//
g/final .* obj;/s/final//
g/final .* tagClass;/s/final//
g/final .* tagNo;/s/final//
w
q
%

ed org/bouncycastle/asn1/ASN1ObjectIdentifier.java <<%
g/private final String identifier;/s/final//
w
q
%

ed org/bouncycastle/asn1/DERBitString.java <<%
g/protected final byte...*data;/s/final//
g/protected final int.*padBits;/s/final//
g/final .* elements;/s/final//
g/final .* segmentLimit;/s/final//
w
q
%

ed org/bouncycastle/asn1/BERBitString.java <<%
g/protected final byte...*data;/s/final//
g/protected final int.*padBits;/s/final//
g/final .* elements;/s/final//
g/final .* segmentLimit;/s/final//
w
q
%

ed org/bouncycastle/asn1/BEROctetString.java <<%
g/private final ASN1OctetString/s/final//
g/private final int/s/final//
w
q
%

ed org/bouncycastle/asn1/DERIA5String.java <<%
g/private final byte.. *string;/s/final//
w
q
%

ed org/bouncycastle/asn1/DERNumericString.java <<%
g/private final byte.. *string;/s/final//
w
q
%

ed org/bouncycastle/asn1/DERPrintableString.java <<%
g/private final byte.. *string;/s/final//
w
q
%

ed org/bouncycastle/asn1/DERT61String.java <<%
g/private final byte.. *string;/s/final//
w
q
%

ed org/bouncycastle/asn1/crmf/DhSigStatic.java <<%
g/private final /s/final//
w
q
%

for f in  org/bouncycastle/crypto/digests/*.java
do
ed $f <<%%
g/private final CryptoServicePurpose purpose/s/final//
g/protected final CryptoServicePurpose purpose/s/final//
g/private final byte.. buffer/s/final//
g/private final byte.. diff/s/final//
w
q
%%
done

for f in  org/bouncycastle/crypto/macs/*.java
do
ed $f <<%%
g/private final CryptoServicePurpose purpose/s/final//
g/protected final CryptoServicePurpose purpose/s/final//
g/private final byte.. buffer/s/final//
g/private final byte.. diff/s/final//
w
q
%%
done

for f in org/bouncycastle/pqc/crypto/*/*.java org/bouncycastle/pqc/crypto/*/*/*.java
do
ed $f <<%%
g/ final /s/final//
w
q
%%
done

for f in  org/bouncycastle/crypto/constraints/*.java
do
ed $f <<%%
g/private final /s/final//
w
q
%%
done

ed org/bouncycastle/crypto/kems/SecretWithEncapsulationImpl.java <<%
g/private final /s/final//
w
q
%

ed org/bouncycastle/asn1/tsp/ArchiveTimeStamp.java <<%
g/private final /s/final//
w
q
%

ed org/bouncycastle/asn1/tsp/PartialHashtree.java <<%
g/private final /s/final//
w
q
%

ed org/bouncycastle/asn1/pkcs/PBKDF2Params.java <<%
g/private final ASN1OctetString octStr;/s/final//
g/private final ASN1Integer iterationCount;/s/final//
g/private final ASN1Integer keyLength;/s/final//
g/private final AlgorithmIdentifier prf;/s/final//
w
q
%
p

for i in org/bouncycastle/asn1/cmp/*.java org/bouncycastle/pqc/crypto/util/SecretWithEncapsulationImpl.java org/bouncycastle/jcajce/provider/asymmetric/ec/IESKEMCipher.java  org/bouncycastle/jcajce/ExternalPublicKey.java org/bouncycastle/jcajce/spec/*.java
do
ed $i <<%
g/private final/s/final//
w
q
%
done


ed org/bouncycastle/asn1/x9/X9ECPoint.java <<%
g/private final ASN1OctetString encoding;/s/final//
w
q
%

ed org/bouncycastle/asn1/x500/style/BCStyle.java <<%
g/protected final .*defaultLookUp;/s/final//
g/protected final .*defaultSymbols;/s/final//
w
q
%

ed org/bouncycastle/asn1/x500/style/RFC4519Style.java <<%
g/protected final .*defaultLookUp;/s/final//
g/protected final .*defaultSymbols;/s/final//
w
q
%

ed org/bouncycastle/crypto/agreement/kdf/GSKKDFParameters.java <<%
g/private final /s/final//
w
q
%

ed org/bouncycastle/crypto/signers/Ed448Signer.java <<%
g/private final/s/final//
w
q
%

ed org/bouncycastle/crypto/signers/Ed25519ctxSigner.java <<%
g/private final/s/final//
w
q
%

ed org/bouncycastle/crypto/signers/SM2Signer.java <<%
g/private final/s/final//
w
q
%

ed org/bouncycastle/crypto/signers/ISOTrailers.java <<%
g/private static final Map.* trailerMap;/s/final//
w
q
%

ed org/bouncycastle/jcajce/PKCS12Key.java <<%
g/private final char.* password;/s/final//
g/private final boolean.* useWrongZeroLengthConversion;/s/final//
w
q
%

ed org/bouncycastle/jcajce/spec/FPEParameterSpec.java <<%
g/private final .*;/s/final//
w
q
%

ed org/bouncycastle/jcajce/spec/MQVParameterSpec.java <<%
g/private final .*;/s/final//
w
q
%

ed org/bouncycastle/jcajce/spec/KTSParameterSpec.java <<%
g/private final .*algorithmName;/s/final//
w
q
%

ed org/bouncycastle/operator/jcajce/JceKTSKeyWrapper.java <<%
g/private final .*;/s/final//
w
q
%

ed org/bouncycastle/cms/CMSTypedStream.java <<%
g/private final .*;/s/final//
w
q
%

ed org/bouncycastle/cms/SignerInformation.java <<%
g/private final .*;/s/final//
g/protected final .*;/s/final//
w
q
%

ed org/bouncycastle/asn1/its/CertificateType.java <<%
g/private final .*;/s/final//
w
q
%

ed org/bouncycastle/asn1/ASN1InputStream.java <<%
g/private final .*;/s/final//
w
q
%

ed org/bouncycastle/asn1/ASN1StreamParser.java <<%
g/private final .*;/s/final//
w
q
%

ed org/bouncycastle/asn1/dvcs/DVCSTime.java <<%
g/private final .*;/s/final//
w
q
%

ed org/bouncycastle/asn1/x509/UserNotice.java <<%
g/private final .*;/s/final//
w
q
%

ed org/bouncycastle/asn1/cmc/BodyPartID.java <<%
g/private final .*;/s/final//
w
q
%

ed org/bouncycastle/asn1/cmc/CMCFailInfo.java <<%
g/private final .*;/s/final//
w
q
%

ed org/bouncycastle/asn1/cmc/CMCStatus.java <<%
g/private final .*;/s/final//
w
q
%

ed org/bouncycastle/asn1/cmc/CMCStatusInfo.java <<%
g/private final .*;/s/final//
w
q
%

ed org/bouncycastle/asn1/cmc/OtherStatusInfo.java <<%
g/private final .*;/s/final//
w
q
%

ed org/bouncycastle/asn1/cmc/TaggedRequest.java <<%
g/private final .*;/s/final//
w
q
%

for i in mceliece/McElieceCCA2Parameters.java sphincs/HashFunctions.java 
do
ed org/bouncycastle/pqc/crypto/$i <<%
g/private final .*;/s/final//
w
q
%
done

ed org/bouncycastle/cert/dane/TruncatingDigestCalculator.java <<%
g/private final .*;/s/final//
w
q
%

ed org/bouncycastle/crypto/signers/RSADigestSigner.java <<%
g/private final .*;/s/final//
w
q
%

ed org/bouncycastle/crypto/agreement/SM2KeyExchange.java <<%
g/private final .*;/s/final//
w
q
%

ed org/bouncycastle/crypto/engines/SM2Engine.java <<%
g/private final .*;/s/final//
w
q
%

ed org/bouncycastle/asn1/bc/ObjectStoreIntegrityCheck.java <<%
g/private final .*;/s/final//
w
q
%

ed org/bouncycastle/jcajce/spec/AEADParameterSpec.java <<%
g/private final .*;/s/final//
w
q
%

ed org/bouncycastle/jcajce/provider/asymmetric/dh/IESCipher.java <<%
g/private final .*;/s/final//
w
q
%

ed org/bouncycastle/jcajce/provider/keystore/bcfks/BcFKSKeyStoreSpi.java <<%
g/private final .*;/s/final//
w
q
%

ed org/bouncycastle/cert/dane/DANEEntry.java <<%
g/private final .*;/s/final//
w
q
%

ed org/bouncycastle/asn1/cryptopro/Gost2814789KeyWrapParameters.java <<%
g/private final .*;/s/final//
w
q
%

ed org/bouncycastle/asn1/cryptopro/Gost2814789EncryptedKey.java <<%
g/private final .*;/s/final//
w
q
%

ed org/bouncycastle/asn1/misc/ScryptParams.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/bouncycastle/asn1/bc/LinkedCertificate.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/bouncycastle/crypto/modes/G3413CFBBlockCipher.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/bouncycastle/crypto/modes/G3413CTRBlockCipher.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/bouncycastle/crypto/modes/KGCMBlockCipher.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/bouncycastle/jcajce/spec/DHUParameterSpec.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/bouncycastle/jcajce/spec/DHDomainParameterSpec.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/bouncycastle/jcajce/spec/GOST3410ParameterSpec.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/bouncycastle/crypto/params/ECGOST3410Parameters.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/bouncycastle/crypto/params/FPEParameters.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/bouncycastle/crypto/test/SP80038GTest.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/bouncycastle/jcajce/provider/asymmetric/dh/KeyAgreementSpi.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/bouncycastle/jcajce/provider/asymmetric/dh/KeyAgreementSpi.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/bouncycastle/crypto/util/JournalingSecureRandom.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/bouncycastle/util/Fingerprint.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/bouncycastle/openpgp/operator/jcajce/JcaPGPContentSignerBuilder.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/bouncycastle/openpgp/operator/jcajce/JcaKeyFingerprintCalculator.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/bouncycastle/asn1/ASN1Integer.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/bouncycastle/jcajce/provider/asymmetric/x509/PEMUtil <<%
g/private.*final.*;/s/final//
w
q
%

ed org/bouncycastle/crypto/generators/Argon2BytesGenerator.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/bouncycastle/crypto/generators/OpenSSLPBEParametersGenerator.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/bouncycastle/crypto/CryptoServicePurpose.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/bouncycastle/crypto/macs/Zuc128Mac.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/bouncycastle/pqc/crypto/test/TestSampler.java <<%
g/random.nextInt(10)/s//random.nextInt() \& 0xf/
w
q
%

ed org/bouncycastle/crypto/test/ZucTest.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/bouncycastle/crypto/macs/Zuc256Mac.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/bouncycastle/crypto/params/ECDomainParameters.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/bouncycastle/jcajce/provider/asymmetric/x509/PEMUtil.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/bouncycastle/jce/provider/test/ZucTest.java <<%
g/private.*final.*;/s/final//
g/(final /s/final//
w
q
%

ed org/bouncycastle/bcpg/Packet.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/bouncycastle/bcpg/SignatureSubpacketInputStream.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/bouncycastle/bcpg/sig/PreferredAEADCiphersuites.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/bouncycastle/jcajce/provider/symmetric/util/BCPBEKey.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/bouncycastle/pkix/PKIXIdentity.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/bouncycastle/pkix/jcajce/JcaPKIXIdentity.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/bouncycastle/jcajce/spec/CompositeAlgorithmSpec.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/bouncycastle/crypto/digests/ParallelHash.java <<%
g/private.*final.*;/s/final//
w
q
%

ed org/bouncycastle/crypto/digests/TupleHash.java <<%
g/private.*final.*;/s/final//
w
q
%

