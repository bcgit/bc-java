#
# JDK 1.2 edits

ed org/bouncycastle/asn1/ASN1Integer.java <<%
g/private final byte.. bytes;/s/final//
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

ed org/bouncycastle/asn1/pkcs/PBKDF2Params.java <<%
g/private final ASN1OctetString octStr;/s/final//
g/private final ASN1Integer iterationCount;/s/final//
g/private final ASN1Integer keyLength;/s/final//
g/private final AlgorithmIdentifier prf;/s/final//
w
q
%

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
