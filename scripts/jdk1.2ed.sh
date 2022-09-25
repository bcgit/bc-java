#
# JDK 1.2 edits

for i in org/bouncycastle/pqc/jcajce/provider/*/*.java  org/bouncycastle/pqc/*/*/*.java org/bouncycastle/pqc/*/*/*/*.java  org/bouncycastle/crypto/engines/*.java org/bouncycastle/openpgp/test/*.java
do
ed $i <<%%
g/.Override/d
w
q
%%
done

ed org/bouncycastle/crypto/util/DERMacData.java <<%
g/private final String enc;/s/final//
g/private final int ordinal;/s/final//
g/private final byte.. macData;/s/final//
g/private final DERSequence sequence;/s/final//
w
q
%

ed org/bouncycastle/crypto/util/DEROtherInfo.java <<%
g/private final DERSequence sequence;/s/final//
w
q
%

ed org/bouncycastle/jcajce/spec/KTSParameterSpec.java <<%
g/private final String wrappingKeyAlgorithm;/s/final//
g/private final int keySizeInBits;/s/final//
g/private final AlgorithmParameterSpec parameterSpec;/s/final//
g/private final AlgorithmIdentifier kdfAlgorithm;/s/final//
w
q
%

ed org/bouncycastle/util/test/FixedSecureRandom.java <<%
g/private static final boolean/s/final//
w
q
%

ed org/bouncycastle/asn1/cmc/CertificationRequest.java <<%
g/private final/s/final//
w
q
%

ed org/bouncycastle/crypto/util/PBKDF2Config.java <<%
g/private final/s/final//
w
q
%

ed org/bouncycastle/crypto/util/ScryptConfig.java <<%
g/private final/s/final//
w
q
%

ed org/bouncycastle/pqc/crypto/newhope/NHOtherInfoGenerator.java <<%
g/private final/s/final//
g/protected final/s/final//
g/(getPublicKey(/s//(NHOtherInfoGenerator.getPublicKey(/
g/return getEncod/s//return NHOtherInfoGenerator.getEncod/
w
q
%

ed org/bouncycastle/crypto/CryptoServicesRegistrar.java <<%
g/private final String/s/final//
g/private final Class/s/final//
w
q
%

ed org/bouncycastle/crypto/params/Argon2Parameters.java <<%
g/private final/s/final//
w
q
%

ed org/bouncycastle/cert/crmf/bc/BcCRMFEncryptorBuilder.java <<%
g/private final/s/final//
w
q
%

ed org/bouncycastle/crypto/modes/ChaCha20Poly1305.java <<%
g/private final/s/final//
w
q
%

ed org/bouncycastle/jcajce/provider/drbg/DRBG.java <<%
g/private final/s/final//
w
q
%

ed org/bouncycastle/pqc/crypto/test/TestSampler.java <<%
g/private final/s/final//
w
q
%

ed org/bouncycastle/cms/bc/BcCMSContentEncryptorBuilder.java <<%
g/private final/s/final//
w
q
%

ed org/bouncycastle/crypto/prng/SP800SecureRandomBuilder.java <<%
g/private final/s/final//
w
q
%

ed org/bouncycastle/crypto/modes/GCMSIVBlockCipher.java <<%
g/private final/s/final//
w
q
%

ed org/bouncycastle/cms/CMSSignedDataGenerator.java <<%
g/LinkedHashSet/s//HashSet/g
w
q
%

ed org/bouncycastle/cms/CMSAuthEnvelopedDataGenerator.java <<%
g/java.util.Collections/s//java.util.HashMap/
g/Collections.EMPTY_MAP/s//new HashMap()/
w
q
%

ed org/bouncycastle/cms/CMSAuthenticatedDataStreamGenerator.java <<%
g/java.util.Collections/s/$/ import java.util.HashMap;/
g/Collections.EMPTY_MAP/s//new HashMap()/
w
q
%

ed org/bouncycastle/cms/CMSAuthenticatedDataGenerator.java <<%
g/java.util.Collections/s/$/ import java.util.HashMap;/
g/Collections.EMPTY_MAP/s//new HashMap()/
w
q
%

ed org/bouncycastle/cms/CMSEnvelopedDataStreamGenerator.java <<%
g/java.util.Collections/s//java.util.HashMap/
g/Collections.EMPTY_MAP/s//new HashMap()/
w
q
%

ed org/bouncycastle/cms/CMSEnvelopedDataGenerator.java <<%
g/java.util.Collections/s//java.util.HashMap/
g/Collections.EMPTY_MAP/s//new HashMap()/
w
q
%

ed org/bouncycastle/cms/CMSEncryptedDataGenerator.java <<%
g/java.util.Collections/s//java.util.HashMap/
g/Collections.EMPTY_MAP/s//new HashMap()/
w
q
%

ed org/bouncycastle/openpgp/PGPExtendedKeyAttribute.java <<%
g/private final/s/final//
w
q
%

ed org/bouncycastle/gpg/SExpression.java <<%
g/\.\.\. /s//[]/g
w
q
%

ed org/bouncycastle/openpgp/operator/jcajce/JcePublicKeyDataDecryptorFactoryBuilder.java <<%
g/RSAKey/s//RSAPrivateKey/g
w
q
%

ed org/bouncycastle/openpgp/PGPCanonicalizedDataGenerator.java <<%
g/FileNotFoundException/s//IOException/
w
q
%
