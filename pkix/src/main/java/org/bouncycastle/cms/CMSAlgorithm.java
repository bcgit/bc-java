package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.bsi.BSIObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

public class CMSAlgorithm
{
    public static final ASN1ObjectIdentifier  DES_CBC         = OIWObjectIdentifiers.desCBC.intern();
    public static final ASN1ObjectIdentifier  DES_EDE3_CBC    = PKCSObjectIdentifiers.des_EDE3_CBC.intern();
    public static final ASN1ObjectIdentifier  RC2_CBC         = PKCSObjectIdentifiers.RC2_CBC.intern();
    public static final ASN1ObjectIdentifier  IDEA_CBC        = new ASN1ObjectIdentifier("1.3.6.1.4.1.188.7.1.1.2").intern();
    public static final ASN1ObjectIdentifier  CAST5_CBC       = new ASN1ObjectIdentifier("1.2.840.113533.7.66.10").intern();

    public static final ASN1ObjectIdentifier  AES128_CBC      = NISTObjectIdentifiers.id_aes128_CBC.intern();
    public static final ASN1ObjectIdentifier  AES192_CBC      = NISTObjectIdentifiers.id_aes192_CBC.intern();
    public static final ASN1ObjectIdentifier  AES256_CBC      = NISTObjectIdentifiers.id_aes256_CBC.intern();
    public static final ASN1ObjectIdentifier  AES128_CCM      = NISTObjectIdentifiers.id_aes128_CCM.intern();
    public static final ASN1ObjectIdentifier  AES192_CCM      = NISTObjectIdentifiers.id_aes192_CCM.intern();
    public static final ASN1ObjectIdentifier  AES256_CCM      = NISTObjectIdentifiers.id_aes256_CCM.intern();
    public static final ASN1ObjectIdentifier  AES128_GCM      = NISTObjectIdentifiers.id_aes128_GCM.intern();
    public static final ASN1ObjectIdentifier  AES192_GCM      = NISTObjectIdentifiers.id_aes192_GCM.intern();
    public static final ASN1ObjectIdentifier  AES256_GCM      = NISTObjectIdentifiers.id_aes256_GCM.intern();

//	public static final ASN1ObjectIdentifier  AES128_CBC_CMAC      = BSIObjectIdentifiers.id_aes128_CBC_CMAC;
//	public static final ASN1ObjectIdentifier  AES192_CBC_CMAC      = BSIObjectIdentifiers.id_aes192_CBC_CMAC;
//	public static final ASN1ObjectIdentifier  AES256_CBC_CMAC      = BSIObjectIdentifiers.id_aes256_CBC_CMAC;

    public static final ASN1ObjectIdentifier  CAMELLIA128_CBC = NTTObjectIdentifiers.id_camellia128_cbc.intern();
    public static final ASN1ObjectIdentifier  CAMELLIA192_CBC = NTTObjectIdentifiers.id_camellia192_cbc.intern();
    public static final ASN1ObjectIdentifier  CAMELLIA256_CBC = NTTObjectIdentifiers.id_camellia256_cbc.intern();
    public static final ASN1ObjectIdentifier  GOST28147_GCFB  = CryptoProObjectIdentifiers.gostR28147_gcfb.intern();
    public static final ASN1ObjectIdentifier  SEED_CBC        = KISAObjectIdentifiers.id_seedCBC.intern();

    public static final ASN1ObjectIdentifier  DES_EDE3_WRAP   = PKCSObjectIdentifiers.id_alg_CMS3DESwrap.intern();
    public static final ASN1ObjectIdentifier  AES128_WRAP     = NISTObjectIdentifiers.id_aes128_wrap.intern();
    public static final ASN1ObjectIdentifier  AES192_WRAP     = NISTObjectIdentifiers.id_aes192_wrap.intern();
    public static final ASN1ObjectIdentifier  AES256_WRAP     = NISTObjectIdentifiers.id_aes256_wrap.intern();
    public static final ASN1ObjectIdentifier  CAMELLIA128_WRAP = NTTObjectIdentifiers.id_camellia128_wrap.intern();
    public static final ASN1ObjectIdentifier  CAMELLIA192_WRAP = NTTObjectIdentifiers.id_camellia192_wrap.intern();
    public static final ASN1ObjectIdentifier  CAMELLIA256_WRAP = NTTObjectIdentifiers.id_camellia256_wrap.intern();
    public static final ASN1ObjectIdentifier  SEED_WRAP       = KISAObjectIdentifiers.id_npki_app_cmsSeed_wrap.intern();

    public static final ASN1ObjectIdentifier  GOST28147_WRAP  = CryptoProObjectIdentifiers.id_Gost28147_89_None_KeyWrap.intern();
    public static final ASN1ObjectIdentifier  GOST28147_CRYPTOPRO_WRAP  = CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_KeyWrap.intern();

    public static final ASN1ObjectIdentifier  ECDH_SHA1KDF    = X9ObjectIdentifiers.dhSinglePass_stdDH_sha1kdf_scheme.intern();
    public static final ASN1ObjectIdentifier  ECCDH_SHA1KDF    = X9ObjectIdentifiers.dhSinglePass_cofactorDH_sha1kdf_scheme.intern();
    public static final ASN1ObjectIdentifier  ECMQV_SHA1KDF   = X9ObjectIdentifiers.mqvSinglePass_sha1kdf_scheme.intern();

    public static final ASN1ObjectIdentifier  ECDH_SHA224KDF    = SECObjectIdentifiers.dhSinglePass_stdDH_sha224kdf_scheme.intern();
    public static final ASN1ObjectIdentifier  ECCDH_SHA224KDF    = SECObjectIdentifiers.dhSinglePass_cofactorDH_sha224kdf_scheme.intern();
    public static final ASN1ObjectIdentifier  ECMQV_SHA224KDF   = SECObjectIdentifiers.mqvSinglePass_sha224kdf_scheme.intern();

    public static final ASN1ObjectIdentifier  ECDH_SHA256KDF    = SECObjectIdentifiers.dhSinglePass_stdDH_sha256kdf_scheme.intern();
    public static final ASN1ObjectIdentifier  ECCDH_SHA256KDF    = SECObjectIdentifiers.dhSinglePass_cofactorDH_sha256kdf_scheme.intern();
    public static final ASN1ObjectIdentifier  ECMQV_SHA256KDF   = SECObjectIdentifiers.mqvSinglePass_sha256kdf_scheme.intern();

    public static final ASN1ObjectIdentifier  ECDH_SHA384KDF    = SECObjectIdentifiers.dhSinglePass_stdDH_sha384kdf_scheme.intern();
    public static final ASN1ObjectIdentifier  ECCDH_SHA384KDF    = SECObjectIdentifiers.dhSinglePass_cofactorDH_sha384kdf_scheme.intern();
    public static final ASN1ObjectIdentifier  ECMQV_SHA384KDF   = SECObjectIdentifiers.mqvSinglePass_sha384kdf_scheme.intern();

    public static final ASN1ObjectIdentifier  ECDH_SHA512KDF    = SECObjectIdentifiers.dhSinglePass_stdDH_sha512kdf_scheme.intern();
    public static final ASN1ObjectIdentifier  ECCDH_SHA512KDF    = SECObjectIdentifiers.dhSinglePass_cofactorDH_sha512kdf_scheme.intern();
    public static final ASN1ObjectIdentifier  ECMQV_SHA512KDF   = SECObjectIdentifiers.mqvSinglePass_sha512kdf_scheme.intern();

    public static final ASN1ObjectIdentifier  ECDHGOST3410_2001    = CryptoProObjectIdentifiers.gostR3410_2001.intern();
    public static final ASN1ObjectIdentifier  ECDHGOST3410_2012_256 = RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_256.intern();
    public static final ASN1ObjectIdentifier  ECDHGOST3410_2012_512 = RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_512.intern();

	public static final ASN1ObjectIdentifier  ECKA_EG_X963KDF  = BSIObjectIdentifiers.ecka_eg_X963kdf;
	public static final ASN1ObjectIdentifier  ECKA_EG_X963KDF_SHA256  = BSIObjectIdentifiers.ecka_eg_X963kdf_SHA256;
	public static final ASN1ObjectIdentifier  ECKA_EG_X963KDF_SHA384  = BSIObjectIdentifiers.ecka_eg_X963kdf_SHA384;
	public static final ASN1ObjectIdentifier  ECKA_EG_X963KDF_SHA512  = BSIObjectIdentifiers.ecka_eg_X963kdf_SHA512;

    public static final ASN1ObjectIdentifier  SHA1 = OIWObjectIdentifiers.idSHA1.intern();
    public static final ASN1ObjectIdentifier  SHA224 = NISTObjectIdentifiers.id_sha224.intern();
    public static final ASN1ObjectIdentifier  SHA256 = NISTObjectIdentifiers.id_sha256.intern();
    public static final ASN1ObjectIdentifier  SHA384 = NISTObjectIdentifiers.id_sha384.intern();
    public static final ASN1ObjectIdentifier  SHA512 = NISTObjectIdentifiers.id_sha512.intern();
    public static final ASN1ObjectIdentifier  MD5 = PKCSObjectIdentifiers.md5.intern();
    public static final ASN1ObjectIdentifier  GOST3411 = CryptoProObjectIdentifiers.gostR3411.intern();
    public static final ASN1ObjectIdentifier  GOST3411_2012_256 = RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256.intern();
    public static final ASN1ObjectIdentifier  GOST3411_2012_512 = RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512.intern();
    public static final ASN1ObjectIdentifier  RIPEMD128 = TeleTrusTObjectIdentifiers.ripemd128.intern();
    public static final ASN1ObjectIdentifier  RIPEMD160 = TeleTrusTObjectIdentifiers.ripemd160.intern();
    public static final ASN1ObjectIdentifier  RIPEMD256 = TeleTrusTObjectIdentifiers.ripemd256.intern();

}
