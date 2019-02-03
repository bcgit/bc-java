package org.bouncycastle.crypto.test;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class OAEPTest
    extends SimpleTest
{
    static byte[] pubKeyEnc1 =
        {
          (byte)0x30, (byte)0x5a, (byte)0x30, (byte)0x0d, (byte)0x06, (byte)0x09, (byte)0x2a, (byte)0x86,
          (byte)0x48, (byte)0x86, (byte)0xf7, (byte)0x0d, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x05,
          (byte)0x00, (byte)0x03, (byte)0x49, (byte)0x00, (byte)0x30, (byte)0x46, (byte)0x02, (byte)0x41,
          (byte)0x00, (byte)0xaa, (byte)0x36, (byte)0xab, (byte)0xce, (byte)0x88, (byte)0xac, (byte)0xfd,
          (byte)0xff, (byte)0x55, (byte)0x52, (byte)0x3c, (byte)0x7f, (byte)0xc4, (byte)0x52, (byte)0x3f,
          (byte)0x90, (byte)0xef, (byte)0xa0, (byte)0x0d, (byte)0xf3, (byte)0x77, (byte)0x4a, (byte)0x25,
          (byte)0x9f, (byte)0x2e, (byte)0x62, (byte)0xb4, (byte)0xc5, (byte)0xd9, (byte)0x9c, (byte)0xb5,
          (byte)0xad, (byte)0xb3, (byte)0x00, (byte)0xa0, (byte)0x28, (byte)0x5e, (byte)0x53, (byte)0x01,
          (byte)0x93, (byte)0x0e, (byte)0x0c, (byte)0x70, (byte)0xfb, (byte)0x68, (byte)0x76, (byte)0x93,
          (byte)0x9c, (byte)0xe6, (byte)0x16, (byte)0xce, (byte)0x62, (byte)0x4a, (byte)0x11, (byte)0xe0,
          (byte)0x08, (byte)0x6d, (byte)0x34, (byte)0x1e, (byte)0xbc, (byte)0xac, (byte)0xa0, (byte)0xa1,
          (byte)0xf5, (byte)0x02, (byte)0x01, (byte)0x11
        };

    static byte[] privKeyEnc1 =
        {
          (byte)0x30, (byte)0x82, (byte)0x01, (byte)0x52, (byte)0x02, (byte)0x01, (byte)0x00, (byte)0x30,
          (byte)0x0d, (byte)0x06, (byte)0x09, (byte)0x2a, (byte)0x86, (byte)0x48, (byte)0x86, (byte)0xf7,
          (byte)0x0d, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x05, (byte)0x00, (byte)0x04, (byte)0x82,
          (byte)0x01, (byte)0x3c, (byte)0x30, (byte)0x82, (byte)0x01, (byte)0x38, (byte)0x02, (byte)0x01,
          (byte)0x00, (byte)0x02, (byte)0x41, (byte)0x00, (byte)0xaa, (byte)0x36, (byte)0xab, (byte)0xce,
          (byte)0x88, (byte)0xac, (byte)0xfd, (byte)0xff, (byte)0x55, (byte)0x52, (byte)0x3c, (byte)0x7f,
          (byte)0xc4, (byte)0x52, (byte)0x3f, (byte)0x90, (byte)0xef, (byte)0xa0, (byte)0x0d, (byte)0xf3,
          (byte)0x77, (byte)0x4a, (byte)0x25, (byte)0x9f, (byte)0x2e, (byte)0x62, (byte)0xb4, (byte)0xc5,
          (byte)0xd9, (byte)0x9c, (byte)0xb5, (byte)0xad, (byte)0xb3, (byte)0x00, (byte)0xa0, (byte)0x28,
          (byte)0x5e, (byte)0x53, (byte)0x01, (byte)0x93, (byte)0x0e, (byte)0x0c, (byte)0x70, (byte)0xfb,
          (byte)0x68, (byte)0x76, (byte)0x93, (byte)0x9c, (byte)0xe6, (byte)0x16, (byte)0xce, (byte)0x62,
          (byte)0x4a, (byte)0x11, (byte)0xe0, (byte)0x08, (byte)0x6d, (byte)0x34, (byte)0x1e, (byte)0xbc,
          (byte)0xac, (byte)0xa0, (byte)0xa1, (byte)0xf5, (byte)0x02, (byte)0x01, (byte)0x11, (byte)0x02,
          (byte)0x40, (byte)0x0a, (byte)0x03, (byte)0x37, (byte)0x48, (byte)0x62, (byte)0x64, (byte)0x87,
          (byte)0x69, (byte)0x5f, (byte)0x5f, (byte)0x30, (byte)0xbc, (byte)0x38, (byte)0xb9, (byte)0x8b,
          (byte)0x44, (byte)0xc2, (byte)0xcd, (byte)0x2d, (byte)0xff, (byte)0x43, (byte)0x40, (byte)0x98,
          (byte)0xcd, (byte)0x20, (byte)0xd8, (byte)0xa1, (byte)0x38, (byte)0xd0, (byte)0x90, (byte)0xbf,
          (byte)0x64, (byte)0x79, (byte)0x7c, (byte)0x3f, (byte)0xa7, (byte)0xa2, (byte)0xcd, (byte)0xcb,
          (byte)0x3c, (byte)0xd1, (byte)0xe0, (byte)0xbd, (byte)0xba, (byte)0x26, (byte)0x54, (byte)0xb4,
          (byte)0xf9, (byte)0xdf, (byte)0x8e, (byte)0x8a, (byte)0xe5, (byte)0x9d, (byte)0x73, (byte)0x3d,
          (byte)0x9f, (byte)0x33, (byte)0xb3, (byte)0x01, (byte)0x62, (byte)0x4a, (byte)0xfd, (byte)0x1d,
          (byte)0x51, (byte)0x02, (byte)0x21, (byte)0x00, (byte)0xd8, (byte)0x40, (byte)0xb4, (byte)0x16,
          (byte)0x66, (byte)0xb4, (byte)0x2e, (byte)0x92, (byte)0xea, (byte)0x0d, (byte)0xa3, (byte)0xb4,
          (byte)0x32, (byte)0x04, (byte)0xb5, (byte)0xcf, (byte)0xce, (byte)0x33, (byte)0x52, (byte)0x52,
          (byte)0x4d, (byte)0x04, (byte)0x16, (byte)0xa5, (byte)0xa4, (byte)0x41, (byte)0xe7, (byte)0x00,
          (byte)0xaf, (byte)0x46, (byte)0x12, (byte)0x0d, (byte)0x02, (byte)0x21, (byte)0x00, (byte)0xc9,
          (byte)0x7f, (byte)0xb1, (byte)0xf0, (byte)0x27, (byte)0xf4, (byte)0x53, (byte)0xf6, (byte)0x34,
          (byte)0x12, (byte)0x33, (byte)0xea, (byte)0xaa, (byte)0xd1, (byte)0xd9, (byte)0x35, (byte)0x3f,
          (byte)0x6c, (byte)0x42, (byte)0xd0, (byte)0x88, (byte)0x66, (byte)0xb1, (byte)0xd0, (byte)0x5a,
          (byte)0x0f, (byte)0x20, (byte)0x35, (byte)0x02, (byte)0x8b, (byte)0x9d, (byte)0x89, (byte)0x02,
          (byte)0x20, (byte)0x59, (byte)0x0b, (byte)0x95, (byte)0x72, (byte)0xa2, (byte)0xc2, (byte)0xa9,
          (byte)0xc4, (byte)0x06, (byte)0x05, (byte)0x9d, (byte)0xc2, (byte)0xab, (byte)0x2f, (byte)0x1d,
          (byte)0xaf, (byte)0xeb, (byte)0x7e, (byte)0x8b, (byte)0x4f, (byte)0x10, (byte)0xa7, (byte)0x54,
          (byte)0x9e, (byte)0x8e, (byte)0xed, (byte)0xf5, (byte)0xb4, (byte)0xfc, (byte)0xe0, (byte)0x9e,
          (byte)0x05, (byte)0x02, (byte)0x21, (byte)0x00, (byte)0x8e, (byte)0x3c, (byte)0x05, (byte)0x21,
          (byte)0xfe, (byte)0x15, (byte)0xe0, (byte)0xea, (byte)0x06, (byte)0xa3, (byte)0x6f, (byte)0xf0,
          (byte)0xf1, (byte)0x0c, (byte)0x99, (byte)0x52, (byte)0xc3, (byte)0x5b, (byte)0x7a, (byte)0x75,
          (byte)0x14, (byte)0xfd, (byte)0x32, (byte)0x38, (byte)0xb8, (byte)0x0a, (byte)0xad, (byte)0x52,
          (byte)0x98, (byte)0x62, (byte)0x8d, (byte)0x51, (byte)0x02, (byte)0x20, (byte)0x36, (byte)0x3f,
          (byte)0xf7, (byte)0x18, (byte)0x9d, (byte)0xa8, (byte)0xe9, (byte)0x0b, (byte)0x1d, (byte)0x34,
          (byte)0x1f, (byte)0x71, (byte)0xd0, (byte)0x9b, (byte)0x76, (byte)0xa8, (byte)0xa9, (byte)0x43,
          (byte)0xe1, (byte)0x1d, (byte)0x10, (byte)0xb2, (byte)0x4d, (byte)0x24, (byte)0x9f, (byte)0x2d,
          (byte)0xea, (byte)0xfe, (byte)0xf8, (byte)0x0c, (byte)0x18, (byte)0x26
        };

    static byte[] output1 = 
    { 
        (byte)0x1b, (byte)0x8f, (byte)0x05, (byte)0xf9, (byte)0xca, (byte)0x1a, (byte)0x79, (byte)0x52,
        (byte)0x6e, (byte)0x53, (byte)0xf3, (byte)0xcc, (byte)0x51, (byte)0x4f, (byte)0xdb, (byte)0x89,
        (byte)0x2b, (byte)0xfb, (byte)0x91, (byte)0x93, (byte)0x23, (byte)0x1e, (byte)0x78, (byte)0xb9,
        (byte)0x92, (byte)0xe6, (byte)0x8d, (byte)0x50, (byte)0xa4, (byte)0x80, (byte)0xcb, (byte)0x52,
        (byte)0x33, (byte)0x89, (byte)0x5c, (byte)0x74, (byte)0x95, (byte)0x8d, (byte)0x5d, (byte)0x02,
        (byte)0xab, (byte)0x8c, (byte)0x0f, (byte)0xd0, (byte)0x40, (byte)0xeb, (byte)0x58, (byte)0x44,
        (byte)0xb0, (byte)0x05, (byte)0xc3, (byte)0x9e, (byte)0xd8, (byte)0x27, (byte)0x4a, (byte)0x9d,
        (byte)0xbf, (byte)0xa8, (byte)0x06, (byte)0x71, (byte)0x40, (byte)0x94, (byte)0x39, (byte)0xd2
    };

    static byte[] pubKeyEnc2 =
        {
        (byte)0x30, (byte)0x4c, (byte)0x30, (byte)0x0d, (byte)0x06, (byte)0x09, (byte)0x2a, (byte)0x86,
        (byte)0x48, (byte)0x86, (byte)0xf7, (byte)0x0d, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x05,
        (byte)0x00, (byte)0x03, (byte)0x3b, (byte)0x00, (byte)0x30, (byte)0x38, (byte)0x02, (byte)0x33,
        (byte)0x00, (byte)0xa3, (byte)0x07, (byte)0x9a, (byte)0x90, (byte)0xdf, (byte)0x0d, (byte)0xfd,
        (byte)0x72, (byte)0xac, (byte)0x09, (byte)0x0c, (byte)0xcc, (byte)0x2a, (byte)0x78, (byte)0xb8,
        (byte)0x74, (byte)0x13, (byte)0x13, (byte)0x3e, (byte)0x40, (byte)0x75, (byte)0x9c, (byte)0x98,
        (byte)0xfa, (byte)0xf8, (byte)0x20, (byte)0x4f, (byte)0x35, (byte)0x8a, (byte)0x0b, (byte)0x26,
        (byte)0x3c, (byte)0x67, (byte)0x70, (byte)0xe7, (byte)0x83, (byte)0xa9, (byte)0x3b, (byte)0x69,
        (byte)0x71, (byte)0xb7, (byte)0x37, (byte)0x79, (byte)0xd2, (byte)0x71, (byte)0x7b, (byte)0xe8,
        (byte)0x34, (byte)0x77, (byte)0xcf, (byte)0x02, (byte)0x01, (byte)0x03
        };

    static byte[] privKeyEnc2 =
        {
        (byte)0x30, (byte)0x82, (byte)0x01, (byte)0x13, (byte)0x02, (byte)0x01, (byte)0x00, (byte)0x30,
        (byte)0x0d, (byte)0x06, (byte)0x09, (byte)0x2a, (byte)0x86, (byte)0x48, (byte)0x86, (byte)0xf7,
        (byte)0x0d, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x05, (byte)0x00, (byte)0x04, (byte)0x81,
        (byte)0xfe, (byte)0x30, (byte)0x81, (byte)0xfb, (byte)0x02, (byte)0x01, (byte)0x00, (byte)0x02,
        (byte)0x33, (byte)0x00, (byte)0xa3, (byte)0x07, (byte)0x9a, (byte)0x90, (byte)0xdf, (byte)0x0d,
        (byte)0xfd, (byte)0x72, (byte)0xac, (byte)0x09, (byte)0x0c, (byte)0xcc, (byte)0x2a, (byte)0x78,
        (byte)0xb8, (byte)0x74, (byte)0x13, (byte)0x13, (byte)0x3e, (byte)0x40, (byte)0x75, (byte)0x9c,
        (byte)0x98, (byte)0xfa, (byte)0xf8, (byte)0x20, (byte)0x4f, (byte)0x35, (byte)0x8a, (byte)0x0b,
        (byte)0x26, (byte)0x3c, (byte)0x67, (byte)0x70, (byte)0xe7, (byte)0x83, (byte)0xa9, (byte)0x3b,
        (byte)0x69, (byte)0x71, (byte)0xb7, (byte)0x37, (byte)0x79, (byte)0xd2, (byte)0x71, (byte)0x7b,
        (byte)0xe8, (byte)0x34, (byte)0x77, (byte)0xcf, (byte)0x02, (byte)0x01, (byte)0x03, (byte)0x02,
        (byte)0x32, (byte)0x6c, (byte)0xaf, (byte)0xbc, (byte)0x60, (byte)0x94, (byte)0xb3, (byte)0xfe,
        (byte)0x4c, (byte)0x72, (byte)0xb0, (byte)0xb3, (byte)0x32, (byte)0xc6, (byte)0xfb, (byte)0x25,
        (byte)0xa2, (byte)0xb7, (byte)0x62, (byte)0x29, (byte)0x80, (byte)0x4e, (byte)0x68, (byte)0x65,
        (byte)0xfc, (byte)0xa4, (byte)0x5a, (byte)0x74, (byte)0xdf, (byte)0x0f, (byte)0x8f, (byte)0xb8,
        (byte)0x41, (byte)0x3b, (byte)0x52, (byte)0xc0, (byte)0xd0, (byte)0xe5, (byte)0x3d, (byte)0x9b,
        (byte)0x59, (byte)0x0f, (byte)0xf1, (byte)0x9b, (byte)0xe7, (byte)0x9f, (byte)0x49, (byte)0xdd,
        (byte)0x21, (byte)0xe5, (byte)0xeb, (byte)0x02, (byte)0x1a, (byte)0x00, (byte)0xcf, (byte)0x20,
        (byte)0x35, (byte)0x02, (byte)0x8b, (byte)0x9d, (byte)0x86, (byte)0x98, (byte)0x40, (byte)0xb4,
        (byte)0x16, (byte)0x66, (byte)0xb4, (byte)0x2e, (byte)0x92, (byte)0xea, (byte)0x0d, (byte)0xa3,
        (byte)0xb4, (byte)0x32, (byte)0x04, (byte)0xb5, (byte)0xcf, (byte)0xce, (byte)0x91, (byte)0x02,
        (byte)0x1a, (byte)0x00, (byte)0xc9, (byte)0x7f, (byte)0xb1, (byte)0xf0, (byte)0x27, (byte)0xf4,
        (byte)0x53, (byte)0xf6, (byte)0x34, (byte)0x12, (byte)0x33, (byte)0xea, (byte)0xaa, (byte)0xd1,
        (byte)0xd9, (byte)0x35, (byte)0x3f, (byte)0x6c, (byte)0x42, (byte)0xd0, (byte)0x88, (byte)0x66,
        (byte)0xb1, (byte)0xd0, (byte)0x5f, (byte)0x02, (byte)0x1a, (byte)0x00, (byte)0x8a, (byte)0x15,
        (byte)0x78, (byte)0xac, (byte)0x5d, (byte)0x13, (byte)0xaf, (byte)0x10, (byte)0x2b, (byte)0x22,
        (byte)0xb9, (byte)0x99, (byte)0xcd, (byte)0x74, (byte)0x61, (byte)0xf1, (byte)0x5e, (byte)0x6d,
        (byte)0x22, (byte)0xcc, (byte)0x03, (byte)0x23, (byte)0xdf, (byte)0xdf, (byte)0x0b, (byte)0x02,
        (byte)0x1a, (byte)0x00, (byte)0x86, (byte)0x55, (byte)0x21, (byte)0x4a, (byte)0xc5, (byte)0x4d,
        (byte)0x8d, (byte)0x4e, (byte)0xcd, (byte)0x61, (byte)0x77, (byte)0xf1, (byte)0xc7, (byte)0x36,
        (byte)0x90, (byte)0xce, (byte)0x2a, (byte)0x48, (byte)0x2c, (byte)0x8b, (byte)0x05, (byte)0x99,
        (byte)0xcb, (byte)0xe0, (byte)0x3f, (byte)0x02, (byte)0x1a, (byte)0x00, (byte)0x83, (byte)0xef,
        (byte)0xef, (byte)0xb8, (byte)0xa9, (byte)0xa4, (byte)0x0d, (byte)0x1d, (byte)0xb6, (byte)0xed,
        (byte)0x98, (byte)0xad, (byte)0x84, (byte)0xed, (byte)0x13, (byte)0x35, (byte)0xdc, (byte)0xc1,
        (byte)0x08, (byte)0xf3, (byte)0x22, (byte)0xd0, (byte)0x57, (byte)0xcf, (byte)0x8d
        };

    static byte[] output2 =
    {
          (byte)0x14, (byte)0xbd, (byte)0xdd, (byte)0x28, (byte)0xc9, (byte)0x83, (byte)0x35, (byte)0x19,
          (byte)0x23, (byte)0x80, (byte)0xe8, (byte)0xe5, (byte)0x49, (byte)0xb1, (byte)0x58, (byte)0x2a,
          (byte)0x8b, (byte)0x40, (byte)0xb4, (byte)0x48, (byte)0x6d, (byte)0x03, (byte)0xa6, (byte)0xa5,
          (byte)0x31, (byte)0x1f, (byte)0x1f, (byte)0xd5, (byte)0xf0, (byte)0xa1, (byte)0x80, (byte)0xe4,
          (byte)0x17, (byte)0x53, (byte)0x03, (byte)0x29, (byte)0xa9, (byte)0x34, (byte)0x90, (byte)0x74,
          (byte)0xb1, (byte)0x52, (byte)0x13, (byte)0x54, (byte)0x29, (byte)0x08, (byte)0x24, (byte)0x52,
          (byte)0x62, (byte)0x51
    };

    static byte[] pubKeyEnc3 =
    {
          (byte)0x30, (byte)0x81, (byte)0x9d, (byte)0x30, (byte)0x0d, (byte)0x06, (byte)0x09, (byte)0x2a,
          (byte)0x86, (byte)0x48, (byte)0x86, (byte)0xf7, (byte)0x0d, (byte)0x01, (byte)0x01, (byte)0x01,
          (byte)0x05, (byte)0x00, (byte)0x03, (byte)0x81, (byte)0x8b, (byte)0x00, (byte)0x30, (byte)0x81,
          (byte)0x87, (byte)0x02, (byte)0x81, (byte)0x81, (byte)0x00, (byte)0xbb, (byte)0xf8, (byte)0x2f,
          (byte)0x09, (byte)0x06, (byte)0x82, (byte)0xce, (byte)0x9c, (byte)0x23, (byte)0x38, (byte)0xac,
          (byte)0x2b, (byte)0x9d, (byte)0xa8, (byte)0x71, (byte)0xf7, (byte)0x36, (byte)0x8d, (byte)0x07,
          (byte)0xee, (byte)0xd4, (byte)0x10, (byte)0x43, (byte)0xa4, (byte)0x40, (byte)0xd6, (byte)0xb6,
          (byte)0xf0, (byte)0x74, (byte)0x54, (byte)0xf5, (byte)0x1f, (byte)0xb8, (byte)0xdf, (byte)0xba,
          (byte)0xaf, (byte)0x03, (byte)0x5c, (byte)0x02, (byte)0xab, (byte)0x61, (byte)0xea, (byte)0x48,
          (byte)0xce, (byte)0xeb, (byte)0x6f, (byte)0xcd, (byte)0x48, (byte)0x76, (byte)0xed, (byte)0x52,
          (byte)0x0d, (byte)0x60, (byte)0xe1, (byte)0xec, (byte)0x46, (byte)0x19, (byte)0x71, (byte)0x9d,
          (byte)0x8a, (byte)0x5b, (byte)0x8b, (byte)0x80, (byte)0x7f, (byte)0xaf, (byte)0xb8, (byte)0xe0,
          (byte)0xa3, (byte)0xdf, (byte)0xc7, (byte)0x37, (byte)0x72, (byte)0x3e, (byte)0xe6, (byte)0xb4,
          (byte)0xb7, (byte)0xd9, (byte)0x3a, (byte)0x25, (byte)0x84, (byte)0xee, (byte)0x6a, (byte)0x64,
          (byte)0x9d, (byte)0x06, (byte)0x09, (byte)0x53, (byte)0x74, (byte)0x88, (byte)0x34, (byte)0xb2,
          (byte)0x45, (byte)0x45, (byte)0x98, (byte)0x39, (byte)0x4e, (byte)0xe0, (byte)0xaa, (byte)0xb1,
          (byte)0x2d, (byte)0x7b, (byte)0x61, (byte)0xa5, (byte)0x1f, (byte)0x52, (byte)0x7a, (byte)0x9a,
          (byte)0x41, (byte)0xf6, (byte)0xc1, (byte)0x68, (byte)0x7f, (byte)0xe2, (byte)0x53, (byte)0x72,
          (byte)0x98, (byte)0xca, (byte)0x2a, (byte)0x8f, (byte)0x59, (byte)0x46, (byte)0xf8, (byte)0xe5,
          (byte)0xfd, (byte)0x09, (byte)0x1d, (byte)0xbd, (byte)0xcb, (byte)0x02, (byte)0x01, (byte)0x11
    };

    static byte[] privKeyEnc3 =
    {
        (byte)0x30, (byte)0x82, (byte)0x02, (byte)0x75, (byte)0x02, (byte)0x01, (byte)0x00, (byte)0x30,
        (byte)0x0d, (byte)0x06, (byte)0x09, (byte)0x2a, (byte)0x86, (byte)0x48, (byte)0x86, (byte)0xf7,
        (byte)0x0d, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x05, (byte)0x00, (byte)0x04, (byte)0x82,
        (byte)0x02, (byte)0x5f, (byte)0x30, (byte)0x82, (byte)0x02, (byte)0x5b, (byte)0x02, (byte)0x01,
        (byte)0x00, (byte)0x02, (byte)0x81, (byte)0x81, (byte)0x00, (byte)0xbb, (byte)0xf8, (byte)0x2f,
        (byte)0x09, (byte)0x06, (byte)0x82, (byte)0xce, (byte)0x9c, (byte)0x23, (byte)0x38, (byte)0xac,
        (byte)0x2b, (byte)0x9d, (byte)0xa8, (byte)0x71, (byte)0xf7, (byte)0x36, (byte)0x8d, (byte)0x07,
        (byte)0xee, (byte)0xd4, (byte)0x10, (byte)0x43, (byte)0xa4, (byte)0x40, (byte)0xd6, (byte)0xb6,
        (byte)0xf0, (byte)0x74, (byte)0x54, (byte)0xf5, (byte)0x1f, (byte)0xb8, (byte)0xdf, (byte)0xba,
        (byte)0xaf, (byte)0x03, (byte)0x5c, (byte)0x02, (byte)0xab, (byte)0x61, (byte)0xea, (byte)0x48,
        (byte)0xce, (byte)0xeb, (byte)0x6f, (byte)0xcd, (byte)0x48, (byte)0x76, (byte)0xed, (byte)0x52,
        (byte)0x0d, (byte)0x60, (byte)0xe1, (byte)0xec, (byte)0x46, (byte)0x19, (byte)0x71, (byte)0x9d,
        (byte)0x8a, (byte)0x5b, (byte)0x8b, (byte)0x80, (byte)0x7f, (byte)0xaf, (byte)0xb8, (byte)0xe0,
        (byte)0xa3, (byte)0xdf, (byte)0xc7, (byte)0x37, (byte)0x72, (byte)0x3e, (byte)0xe6, (byte)0xb4,
        (byte)0xb7, (byte)0xd9, (byte)0x3a, (byte)0x25, (byte)0x84, (byte)0xee, (byte)0x6a, (byte)0x64,
        (byte)0x9d, (byte)0x06, (byte)0x09, (byte)0x53, (byte)0x74, (byte)0x88, (byte)0x34, (byte)0xb2,
        (byte)0x45, (byte)0x45, (byte)0x98, (byte)0x39, (byte)0x4e, (byte)0xe0, (byte)0xaa, (byte)0xb1,
        (byte)0x2d, (byte)0x7b, (byte)0x61, (byte)0xa5, (byte)0x1f, (byte)0x52, (byte)0x7a, (byte)0x9a,
        (byte)0x41, (byte)0xf6, (byte)0xc1, (byte)0x68, (byte)0x7f, (byte)0xe2, (byte)0x53, (byte)0x72,
        (byte)0x98, (byte)0xca, (byte)0x2a, (byte)0x8f, (byte)0x59, (byte)0x46, (byte)0xf8, (byte)0xe5,
        (byte)0xfd, (byte)0x09, (byte)0x1d, (byte)0xbd, (byte)0xcb, (byte)0x02, (byte)0x01, (byte)0x11,
        (byte)0x02, (byte)0x81, (byte)0x81, (byte)0x00, (byte)0xa5, (byte)0xda, (byte)0xfc, (byte)0x53,
        (byte)0x41, (byte)0xfa, (byte)0xf2, (byte)0x89, (byte)0xc4, (byte)0xb9, (byte)0x88, (byte)0xdb,
        (byte)0x30, (byte)0xc1, (byte)0xcd, (byte)0xf8, (byte)0x3f, (byte)0x31, (byte)0x25, (byte)0x1e,
        (byte)0x06, (byte)0x68, (byte)0xb4, (byte)0x27, (byte)0x84, (byte)0x81, (byte)0x38, (byte)0x01,
        (byte)0x57, (byte)0x96, (byte)0x41, (byte)0xb2, (byte)0x94, (byte)0x10, (byte)0xb3, (byte)0xc7,
        (byte)0x99, (byte)0x8d, (byte)0x6b, (byte)0xc4, (byte)0x65, (byte)0x74, (byte)0x5e, (byte)0x5c,
        (byte)0x39, (byte)0x26, (byte)0x69, (byte)0xd6, (byte)0x87, (byte)0x0d, (byte)0xa2, (byte)0xc0,
        (byte)0x82, (byte)0xa9, (byte)0x39, (byte)0xe3, (byte)0x7f, (byte)0xdc, (byte)0xb8, (byte)0x2e,
        (byte)0xc9, (byte)0x3e, (byte)0xda, (byte)0xc9, (byte)0x7f, (byte)0xf3, (byte)0xad, (byte)0x59,
        (byte)0x50, (byte)0xac, (byte)0xcf, (byte)0xbc, (byte)0x11, (byte)0x1c, (byte)0x76, (byte)0xf1,
        (byte)0xa9, (byte)0x52, (byte)0x94, (byte)0x44, (byte)0xe5, (byte)0x6a, (byte)0xaf, (byte)0x68,
        (byte)0xc5, (byte)0x6c, (byte)0x09, (byte)0x2c, (byte)0xd3, (byte)0x8d, (byte)0xc3, (byte)0xbe,
        (byte)0xf5, (byte)0xd2, (byte)0x0a, (byte)0x93, (byte)0x99, (byte)0x26, (byte)0xed, (byte)0x4f,
        (byte)0x74, (byte)0xa1, (byte)0x3e, (byte)0xdd, (byte)0xfb, (byte)0xe1, (byte)0xa1, (byte)0xce,
        (byte)0xcc, (byte)0x48, (byte)0x94, (byte)0xaf, (byte)0x94, (byte)0x28, (byte)0xc2, (byte)0xb7,
        (byte)0xb8, (byte)0x88, (byte)0x3f, (byte)0xe4, (byte)0x46, (byte)0x3a, (byte)0x4b, (byte)0xc8,
        (byte)0x5b, (byte)0x1c, (byte)0xb3, (byte)0xc1, (byte)0x02, (byte)0x41, (byte)0x00, (byte)0xee,
        (byte)0xcf, (byte)0xae, (byte)0x81, (byte)0xb1, (byte)0xb9, (byte)0xb3, (byte)0xc9, (byte)0x08,
        (byte)0x81, (byte)0x0b, (byte)0x10, (byte)0xa1, (byte)0xb5, (byte)0x60, (byte)0x01, (byte)0x99,
        (byte)0xeb, (byte)0x9f, (byte)0x44, (byte)0xae, (byte)0xf4, (byte)0xfd, (byte)0xa4, (byte)0x93,
        (byte)0xb8, (byte)0x1a, (byte)0x9e, (byte)0x3d, (byte)0x84, (byte)0xf6, (byte)0x32, (byte)0x12,
        (byte)0x4e, (byte)0xf0, (byte)0x23, (byte)0x6e, (byte)0x5d, (byte)0x1e, (byte)0x3b, (byte)0x7e,
        (byte)0x28, (byte)0xfa, (byte)0xe7, (byte)0xaa, (byte)0x04, (byte)0x0a, (byte)0x2d, (byte)0x5b,
        (byte)0x25, (byte)0x21, (byte)0x76, (byte)0x45, (byte)0x9d, (byte)0x1f, (byte)0x39, (byte)0x75,
        (byte)0x41, (byte)0xba, (byte)0x2a, (byte)0x58, (byte)0xfb, (byte)0x65, (byte)0x99, (byte)0x02,
        (byte)0x41, (byte)0x00, (byte)0xc9, (byte)0x7f, (byte)0xb1, (byte)0xf0, (byte)0x27, (byte)0xf4,
        (byte)0x53, (byte)0xf6, (byte)0x34, (byte)0x12, (byte)0x33, (byte)0xea, (byte)0xaa, (byte)0xd1,
        (byte)0xd9, (byte)0x35, (byte)0x3f, (byte)0x6c, (byte)0x42, (byte)0xd0, (byte)0x88, (byte)0x66,
        (byte)0xb1, (byte)0xd0, (byte)0x5a, (byte)0x0f, (byte)0x20, (byte)0x35, (byte)0x02, (byte)0x8b,
        (byte)0x9d, (byte)0x86, (byte)0x98, (byte)0x40, (byte)0xb4, (byte)0x16, (byte)0x66, (byte)0xb4,
        (byte)0x2e, (byte)0x92, (byte)0xea, (byte)0x0d, (byte)0xa3, (byte)0xb4, (byte)0x32, (byte)0x04,
        (byte)0xb5, (byte)0xcf, (byte)0xce, (byte)0x33, (byte)0x52, (byte)0x52, (byte)0x4d, (byte)0x04,
        (byte)0x16, (byte)0xa5, (byte)0xa4, (byte)0x41, (byte)0xe7, (byte)0x00, (byte)0xaf, (byte)0x46,
        (byte)0x15, (byte)0x03, (byte)0x02, (byte)0x40, (byte)0x54, (byte)0x49, (byte)0x4c, (byte)0xa6,
        (byte)0x3e, (byte)0xba, (byte)0x03, (byte)0x37, (byte)0xe4, (byte)0xe2, (byte)0x40, (byte)0x23,
        (byte)0xfc, (byte)0xd6, (byte)0x9a, (byte)0x5a, (byte)0xeb, (byte)0x07, (byte)0xdd, (byte)0xdc,
        (byte)0x01, (byte)0x83, (byte)0xa4, (byte)0xd0, (byte)0xac, (byte)0x9b, (byte)0x54, (byte)0xb0,
        (byte)0x51, (byte)0xf2, (byte)0xb1, (byte)0x3e, (byte)0xd9, (byte)0x49, (byte)0x09, (byte)0x75,
        (byte)0xea, (byte)0xb7, (byte)0x74, (byte)0x14, (byte)0xff, (byte)0x59, (byte)0xc1, (byte)0xf7,
        (byte)0x69, (byte)0x2e, (byte)0x9a, (byte)0x2e, (byte)0x20, (byte)0x2b, (byte)0x38, (byte)0xfc,
        (byte)0x91, (byte)0x0a, (byte)0x47, (byte)0x41, (byte)0x74, (byte)0xad, (byte)0xc9, (byte)0x3c,
        (byte)0x1f, (byte)0x67, (byte)0xc9, (byte)0x81, (byte)0x02, (byte)0x40, (byte)0x47, (byte)0x1e,
        (byte)0x02, (byte)0x90, (byte)0xff, (byte)0x0a, (byte)0xf0, (byte)0x75, (byte)0x03, (byte)0x51,
        (byte)0xb7, (byte)0xf8, (byte)0x78, (byte)0x86, (byte)0x4c, (byte)0xa9, (byte)0x61, (byte)0xad,
        (byte)0xbd, (byte)0x3a, (byte)0x8a, (byte)0x7e, (byte)0x99, (byte)0x1c, (byte)0x5c, (byte)0x05,
        (byte)0x56, (byte)0xa9, (byte)0x4c, (byte)0x31, (byte)0x46, (byte)0xa7, (byte)0xf9, (byte)0x80,
        (byte)0x3f, (byte)0x8f, (byte)0x6f, (byte)0x8a, (byte)0xe3, (byte)0x42, (byte)0xe9, (byte)0x31,
        (byte)0xfd, (byte)0x8a, (byte)0xe4, (byte)0x7a, (byte)0x22, (byte)0x0d, (byte)0x1b, (byte)0x99,
        (byte)0xa4, (byte)0x95, (byte)0x84, (byte)0x98, (byte)0x07, (byte)0xfe, (byte)0x39, (byte)0xf9,
        (byte)0x24, (byte)0x5a, (byte)0x98, (byte)0x36, (byte)0xda, (byte)0x3d, (byte)0x02, (byte)0x41,
        (byte)0x00, (byte)0xb0, (byte)0x6c, (byte)0x4f, (byte)0xda, (byte)0xbb, (byte)0x63, (byte)0x01,
        (byte)0x19, (byte)0x8d, (byte)0x26, (byte)0x5b, (byte)0xdb, (byte)0xae, (byte)0x94, (byte)0x23,
        (byte)0xb3, (byte)0x80, (byte)0xf2, (byte)0x71, (byte)0xf7, (byte)0x34, (byte)0x53, (byte)0x88,
        (byte)0x50, (byte)0x93, (byte)0x07, (byte)0x7f, (byte)0xcd, (byte)0x39, (byte)0xe2, (byte)0x11,
        (byte)0x9f, (byte)0xc9, (byte)0x86, (byte)0x32, (byte)0x15, (byte)0x4f, (byte)0x58, (byte)0x83,
        (byte)0xb1, (byte)0x67, (byte)0xa9, (byte)0x67, (byte)0xbf, (byte)0x40, (byte)0x2b, (byte)0x4e,
        (byte)0x9e, (byte)0x2e, (byte)0x0f, (byte)0x96, (byte)0x56, (byte)0xe6, (byte)0x98, (byte)0xea,
        (byte)0x36, (byte)0x66, (byte)0xed, (byte)0xfb, (byte)0x25, (byte)0x79, (byte)0x80, (byte)0x39,
        (byte)0xf7
    };

    static byte[] output3 = Hex.decode(
        "b8246b56a6ed5881aeb585d9a25b2ad790c417e080681bf1ac2bc3deb69d8bce"
      + "f0c4366fec400af052a72e9b0effb5b3f2f192dbeaca03c12740057113bf1f06"
      + "69ac22e9f3a7852e3c15d913cab0b8863a95c99294ce8674214954610346f4d4"
      + "74b26f7c48b42ee68e1f572a1fc4026ac456b4f59f7b621ea1b9d88f64202fb1");

    byte[]  seed = {
                (byte)0xaa, (byte)0xfd, (byte)0x12, (byte)0xf6, (byte)0x59,
                (byte)0xca, (byte)0xe6, (byte)0x34, (byte)0x89, (byte)0xb4,
                (byte)0x79, (byte)0xe5, (byte)0x07, (byte)0x6d, (byte)0xde,
                (byte)0xc2, (byte)0xf0, (byte)0x6c, (byte)0xb5, (byte)0x8f
    };

    private class VecRand extends SecureRandom
    {
        byte[] seed;

        VecRand(byte[] seed)
        {
            this.seed = seed;
        }

        public void nextBytes(
            byte[]  bytes)
        {
            System.arraycopy(seed, 0, bytes, 0, bytes.length);
        }
    }

    private void baseOaepTest(
        int     id,
        byte[]  pubKeyEnc,
        byte[]  privKeyEnc,
        byte[]  output)
        throws Exception
    {
        ByteArrayInputStream    bIn = new ByteArrayInputStream(pubKeyEnc);
        ASN1InputStream         dIn = new ASN1InputStream(bIn);

        //
        // extract the public key info.
        //
        RSAPublicKey pubStruct;

        pubStruct = RSAPublicKey.getInstance(SubjectPublicKeyInfo.getInstance(dIn.readObject()).parsePublicKey());


        bIn = new ByteArrayInputStream(privKeyEnc);
        dIn = new ASN1InputStream(bIn);

        //
        // extract the private key info.
        //
        RSAPrivateKey privStruct;

        privStruct = RSAPrivateKey.getInstance(PrivateKeyInfo.getInstance(dIn.readObject()).parsePrivateKey());

        RSAKeyParameters    pubParameters = new RSAKeyParameters(
                                                    false,
                                                    pubStruct.getModulus(),
                                                    pubStruct.getPublicExponent());

        RSAKeyParameters    privParameters = new RSAPrivateCrtKeyParameters(
                                                    privStruct.getModulus(),
                                                    privStruct.getPublicExponent(),
                                                    privStruct.getPrivateExponent(),
                                                    privStruct.getPrime1(),
                                                    privStruct.getPrime2(),
                                                    privStruct.getExponent1(),
                                                    privStruct.getExponent2(),
                                                    privStruct.getCoefficient());

        byte[]  input = new byte[]
                    { (byte)0x54, (byte)0x85, (byte)0x9b, (byte)0x34, (byte)0x2c, (byte)0x49, (byte)0xea, (byte)0x2a };

        encDec("id(" + id + ")", pubParameters, privParameters, seed, input, output);

    }

    private void encDec(
        String label,
        RSAKeyParameters pubParameters,
        RSAKeyParameters privParameters,
        byte[] seed,
        byte[] input,
        byte[] output)
        throws InvalidCipherTextException
    {
        AsymmetricBlockCipher cipher = new OAEPEncoding(new RSAEngine());

        cipher.init(true, new ParametersWithRandom(pubParameters, new VecRand(seed)));

        byte[]  out;

        out = cipher.processBlock(input, 0, input.length);

        for (int i = 0; i != output.length; i++)
        {
            if (out[i] != output[i])
            {
                fail(label + " failed encryption");
            }
        }

        cipher.init(false, privParameters);

        out = cipher.processBlock(output, 0, output.length);

        for (int i = 0; i != input.length; i++)
        {
            if (out[i] != input[i])
            {
                fail(label + " failed decoding");
            }
        }
    }

    /*
     * RSA vector tests from PKCS#1 page
     */
    byte[] modulus_1024 = Hex.decode(
       "a8b3b284af8eb50b387034a860f146c4"
     + "919f318763cd6c5598c8ae4811a1e0ab"
     + "c4c7e0b082d693a5e7fced675cf46685"
     + "12772c0cbc64a742c6c630f533c8cc72"
     + "f62ae833c40bf25842e984bb78bdbf97"
     + "c0107d55bdb662f5c4e0fab9845cb514"
     + "8ef7392dd3aaff93ae1e6b667bb3d424"
     + "7616d4f5ba10d4cfd226de88d39f16fb");

    byte[] pubExp_1024 = Hex.decode(
       "010001");

    byte[] privExp_1024 = Hex.decode(
       "53339cfdb79fc8466a655c7316aca85c"
     + "55fd8f6dd898fdaf119517ef4f52e8fd"
     + "8e258df93fee180fa0e4ab29693cd83b"
     + "152a553d4ac4d1812b8b9fa5af0e7f55"
     + "fe7304df41570926f3311f15c4d65a73"
     + "2c483116ee3d3d2d0af3549ad9bf7cbf"
     + "b78ad884f84d5beb04724dc7369b31de"
     + "f37d0cf539e9cfcdd3de653729ead5d1");

    byte[] prime1_1024 = Hex.decode(
       "d32737e7267ffe1341b2d5c0d150a81b"
     + "586fb3132bed2f8d5262864a9cb9f30a"
     + "f38be448598d413a172efb802c21acf1"
     + "c11c520c2f26a471dcad212eac7ca39d");

    byte[] prime2_1024 = Hex.decode(
       "cc8853d1d54da630fac004f471f281c7"
     + "b8982d8224a490edbeb33d3e3d5cc93c"
     + "4765703d1dd791642f1f116a0dd852be"
     + "2419b2af72bfe9a030e860b0288b5d77");

    byte[] primeExp1_1024 = Hex.decode(
       "0e12bf1718e9cef5599ba1c3882fe804"
     + "6a90874eefce8f2ccc20e4f2741fb0a3"
     + "3a3848aec9c9305fbecbd2d76819967d"
     + "4671acc6431e4037968db37878e695c1");

    byte[] primeExp2_1024 = Hex.decode(
        "95297b0f95a2fa67d00707d609dfd4fc"
     +  "05c89dafc2ef6d6ea55bec771ea33373"
     +  "4d9251e79082ecda866efef13c459e1a"
     +  "631386b7e354c899f5f112ca85d71583");

    byte[] crtCoef_1024 = Hex.decode(
        "4f456c502493bdc0ed2ab756a3a6ed4d"
     +  "67352a697d4216e93212b127a63d5411"
     +  "ce6fa98d5dbefd73263e372814274381"
     +  "8166ed7dd63687dd2a8ca1d2f4fbd8e1");

    byte[] input_1024_1 = Hex.decode(
        "6628194e12073db03ba94cda9ef95323"
      + "97d50dba79b987004afefe34");

    byte[] seed_1024_1 = Hex.decode(
        "18b776ea21069d69776a33e96bad48e1"
      + "dda0a5ef");

    byte[] output_1024_1 = Hex.decode(
        "354fe67b4a126d5d35fe36c777791a3f"
      + "7ba13def484e2d3908aff722fad468fb"
      + "21696de95d0be911c2d3174f8afcc201"
      + "035f7b6d8e69402de5451618c21a535f"
      + "a9d7bfc5b8dd9fc243f8cf927db31322"
      + "d6e881eaa91a996170e657a05a266426"
      + "d98c88003f8477c1227094a0d9fa1e8c"
      + "4024309ce1ecccb5210035d47ac72e8a");

    byte[] input_1024_2 = Hex.decode(
        "750c4047f547e8e41411856523298ac9"
      +  "bae245efaf1397fbe56f9dd5");

    byte[] seed_1024_2 = Hex.decode(
        "0cc742ce4a9b7f32f951bcb251efd925"
      + "fe4fe35f");

    byte[] output_1024_2 = Hex.decode(
        "640db1acc58e0568fe5407e5f9b701df"
      + "f8c3c91e716c536fc7fcec6cb5b71c11"
      + "65988d4a279e1577d730fc7a29932e3f"
      + "00c81515236d8d8e31017a7a09df4352"
      + "d904cdeb79aa583adcc31ea698a4c052"
      + "83daba9089be5491f67c1a4ee48dc74b"
      + "bbe6643aef846679b4cb395a352d5ed1"
      + "15912df696ffe0702932946d71492b44");

    byte[] input_1024_3 = Hex.decode(
        "d94ae0832e6445ce42331cb06d531a82"
      + "b1db4baad30f746dc916df24d4e3c245"
      + "1fff59a6423eb0e1d02d4fe646cf699d"
      + "fd818c6e97b051");

    byte[] seed_1024_3 = Hex.decode(
        "2514df4695755a67b288eaf4905c36ee"
      + "c66fd2fd");

    byte[] output_1024_3 = Hex.decode(
        "423736ed035f6026af276c35c0b3741b"
      + "365e5f76ca091b4e8c29e2f0befee603"
      + "595aa8322d602d2e625e95eb81b2f1c9"
      + "724e822eca76db8618cf09c5343503a4"
      + "360835b5903bc637e3879fb05e0ef326"
      + "85d5aec5067cd7cc96fe4b2670b6eac3"
      + "066b1fcf5686b68589aafb7d629b02d8"
      + "f8625ca3833624d4800fb081b1cf94eb");

    byte[] input_1024_4 = Hex.decode(
        "52e650d98e7f2a048b4f86852153b97e"
      + "01dd316f346a19f67a85");

    byte[] seed_1024_4 = Hex.decode(
        "c4435a3e1a18a68b6820436290a37cef"
      + "b85db3fb");

    byte[] output_1024_4 = Hex.decode(
        "45ead4ca551e662c9800f1aca8283b05"
      + "25e6abae30be4b4aba762fa40fd3d38e"
      + "22abefc69794f6ebbbc05ddbb1121624"
      + "7d2f412fd0fba87c6e3acd888813646f"
      + "d0e48e785204f9c3f73d6d8239562722"
      + "dddd8771fec48b83a31ee6f592c4cfd4"
      + "bc88174f3b13a112aae3b9f7b80e0fc6"
      + "f7255ba880dc7d8021e22ad6a85f0755");

    byte[] input_1024_5 = Hex.decode(
        "8da89fd9e5f974a29feffb462b49180f"
      + "6cf9e802");

    byte[] seed_1024_5 = Hex.decode(
        "b318c42df3be0f83fea823f5a7b47ed5"
      + "e425a3b5");

    byte[] output_1024_5 = Hex.decode(
        "36f6e34d94a8d34daacba33a2139d00a"
      + "d85a9345a86051e73071620056b920e2"
      + "19005855a213a0f23897cdcd731b4525"
      + "7c777fe908202befdd0b58386b1244ea"
      + "0cf539a05d5d10329da44e13030fd760"
      + "dcd644cfef2094d1910d3f433e1c7c6d"
      + "d18bc1f2df7f643d662fb9dd37ead905"
      + "9190f4fa66ca39e869c4eb449cbdc439");

    byte[] input_1024_6 = Hex.decode(
        "26521050844271");

    byte[] seed_1024_6 = Hex.decode(
        "e4ec0982c2336f3a677f6a356174eb0c"
      + "e887abc2");

    byte[] output_1024_6 = Hex.decode(
        "42cee2617b1ecea4db3f4829386fbd61"
      + "dafbf038e180d837c96366df24c097b4"
      + "ab0fac6bdf590d821c9f10642e681ad0"
      + "5b8d78b378c0f46ce2fad63f74e0ad3d"
      + "f06b075d7eb5f5636f8d403b9059ca76"
      + "1b5c62bb52aa45002ea70baace08ded2"
      + "43b9d8cbd62a68ade265832b56564e43"
      + "a6fa42ed199a099769742df1539e8255");

    byte[] modulus_1027 = Hex.decode(
        "051240b6cc0004fa48d0134671c078c7"
      + "c8dec3b3e2f25bc2564467339db38853"
      + "d06b85eea5b2de353bff42ac2e46bc97"
      + "fae6ac9618da9537a5c8f553c1e35762"
      + "5991d6108dcd7885fb3a25413f53efca"
      + "d948cb35cd9b9ae9c1c67626d113d57d"
      + "de4c5bea76bb5bb7de96c00d07372e96"
      + "85a6d75cf9d239fa148d70931b5f3fb0"
      + "39");

    byte[] pubExp_1027 = Hex.decode(
        "010001");

    byte[] privExp_1027 = Hex.decode(
        "0411ffca3b7ca5e9e9be7fe38a85105e"
      + "353896db05c5796aecd2a725161eb365"
      + "1c8629a9b862b904d7b0c7b37f8cb5a1"
      + "c2b54001018a00a1eb2cafe4ee4e9492"
      + "c348bc2bedab4b9ebbf064e8eff322b9"
      + "009f8eec653905f40df88a3cdc49d456"
      + "7f75627d41aca624129b46a0b7c698e5"
      + "e65f2b7ba102c749a10135b6540d0401");

    byte[] prime1_1027 = Hex.decode(
        "027458c19ec1636919e736c9af25d609"
      + "a51b8f561d19c6bf6943dd1ee1ab8a4a"
      + "3f232100bd40b88decc6ba235548b6ef"
      + "792a11c9de823d0a7922c7095b6eba57"
      + "01");

    byte[] prime2_1027 = Hex.decode(
        "0210ee9b33ab61716e27d251bd465f4b"
      + "35a1a232e2da00901c294bf22350ce49"
      + "0d099f642b5375612db63ba1f2038649"
      + "2bf04d34b3c22bceb909d13441b53b51"
      + "39");

    byte[] primeExp1_1027 = Hex.decode(
        "39fa028b826e88c1121b750a8b242fa9"
      + "a35c5b66bdfd1fa637d3cc48a84a4f45"
      + "7a194e7727e49f7bcc6e5a5a412657fc"
      + "470c7322ebc37416ef458c307a8c0901");

    byte[] primeExp2_1027 = Hex.decode(
        "015d99a84195943979fa9e1be2c3c1b6"
      + "9f432f46fd03e47d5befbbbfd6b1d137"
      + "1d83efb330a3e020942b2fed115e5d02"
      + "be24fd92c9019d1cecd6dd4cf1e54cc8"
      + "99");

    byte[] crtCoef_1027 = Hex.decode(
        "01f0b7015170b3f5e42223ba30301c41"
      + "a6d87cbb70e30cb7d3c67d25473db1f6"
      + "cbf03e3f9126e3e97968279a865b2c2b"
      + "426524cfc52a683d31ed30eb984be412"
      + "ba");

    byte[] input_1027_1 = Hex.decode(
        "4a86609534ee434a6cbca3f7e962e76d"
      + "455e3264c19f605f6e5ff6137c65c56d"
      + "7fb344cd52bc93374f3d166c9f0c6f9c"
      + "506bad19330972d2");

    byte[] seed_1027_1 = Hex.decode(
        "1cac19ce993def55f98203f6852896c9"
      + "5ccca1f3");

    byte[] output_1027_1 = Hex.decode(
        "04cce19614845e094152a3fe18e54e33"
      + "30c44e5efbc64ae16886cb1869014cc5"
      + "781b1f8f9e045384d0112a135ca0d12e"
      + "9c88a8e4063416deaae3844f60d6e96f"
      + "e155145f4525b9a34431ca3766180f70"
      + "e15a5e5d8e8b1a516ff870609f13f896"
      + "935ced188279a58ed13d07114277d75c"
      + "6568607e0ab092fd803a223e4a8ee0b1"
      + "a8");

    byte[] input_1027_2 = Hex.decode(
        "b0adc4f3fe11da59ce992773d9059943"
      + "c03046497ee9d9f9a06df1166db46d98"
      + "f58d27ec074c02eee6cbe2449c8b9fc5"
      + "080c5c3f4433092512ec46aa793743c8");

    byte[] seed_1027_2 = Hex.decode(
        "f545d5897585e3db71aa0cb8da76c51d"
      + "032ae963");

    byte[] output_1027_2 = Hex.decode(
        "0097b698c6165645b303486fbf5a2a44"
      + "79c0ee85889b541a6f0b858d6b6597b1"
      + "3b854eb4f839af03399a80d79bda6578"
      + "c841f90d645715b280d37143992dd186"
      + "c80b949b775cae97370e4ec97443136c"
      + "6da484e970ffdb1323a20847821d3b18"
      + "381de13bb49aaea66530c4a4b8271f3e"
      + "ae172cd366e07e6636f1019d2a28aed1"
      + "5e");

    byte[] input_1027_3 = Hex.decode(
        "bf6d42e701707b1d0206b0c8b45a1c72"
      + "641ff12889219a82bdea965b5e79a96b"
      + "0d0163ed9d578ec9ada20f2fbcf1ea3c"
      + "4089d83419ba81b0c60f3606da99");

    byte[] seed_1027_3 = Hex.decode(
        "ad997feef730d6ea7be60d0dc52e72ea"
      + "cbfdd275");

    byte[] output_1027_3 = Hex.decode(
        "0301f935e9c47abcb48acbbe09895d9f"
      + "5971af14839da4ff95417ee453d1fd77"
      + "319072bb7297e1b55d7561cd9d1bb24c"
      + "1a9a37c619864308242804879d86ebd0"
      + "01dce5183975e1506989b70e5a834341"
      + "54d5cbfd6a24787e60eb0c658d2ac193"
      + "302d1192c6e622d4a12ad4b53923bca2"
      + "46df31c6395e37702c6a78ae081fb9d0"
      + "65");

    byte[] input_1027_4 = Hex.decode(
        "fb2ef112f5e766eb94019297934794f7"
      + "be2f6fc1c58e");

    byte[] seed_1027_4 = Hex.decode(
        "136454df5730f73c807a7e40d8c1a312"
      + "ac5b9dd3");

    byte[] output_1027_4 = Hex.decode(
        "02d110ad30afb727beb691dd0cf17d0a"
      + "f1a1e7fa0cc040ec1a4ba26a42c59d0a"
      + "796a2e22c8f357ccc98b6519aceb682e"
      + "945e62cb734614a529407cd452bee3e4"
      + "4fece8423cc19e55548b8b994b849c7e"
      + "cde4933e76037e1d0ce44275b08710c6"
      + "8e430130b929730ed77e09b015642c55"
      + "93f04e4ffb9410798102a8e96ffdfe11"
      + "e4");

    byte[] input_1027_5 = Hex.decode(
        "28ccd447bb9e85166dabb9e5b7d1adad"
      + "c4b9d39f204e96d5e440ce9ad928bc1c"
      + "2284");

    byte[] seed_1027_5 = Hex.decode(
        "bca8057f824b2ea257f2861407eef63d"
      + "33208681");

    byte[] output_1027_5 = Hex.decode(
        "00dbb8a7439d90efd919a377c54fae8f"
      + "e11ec58c3b858362e23ad1b8a4431079"
      + "9066b99347aa525691d2adc58d9b06e3"
      + "4f288c170390c5f0e11c0aa3645959f1"
      + "8ee79e8f2be8d7ac5c23d061f18dd74b"
      + "8c5f2a58fcb5eb0c54f99f01a8324756"
      + "8292536583340948d7a8c97c4acd1e98"
      + "d1e29dc320e97a260532a8aa7a758a1e"
      + "c2");

    byte[] input_1027_6 = Hex.decode(
        "f22242751ec6b1");

    byte[] seed_1027_6 = Hex.decode(
        "2e7e1e17f647b5ddd033e15472f90f68"
      + "12f3ac4e");

    byte[] output_1027_6 = Hex.decode(
        "00a5ffa4768c8bbecaee2db77e8f2eec"
      + "99595933545520835e5ba7db9493d3e1"
      + "7cddefe6a5f567624471908db4e2d83a"
      + "0fbee60608fc84049503b2234a07dc83"
      + "b27b22847ad8920ff42f674ef79b7628"
      + "0b00233d2b51b8cb2703a9d42bfbc825"
      + "0c96ec32c051e57f1b4ba528db89c37e"
      + "4c54e27e6e64ac69635ae887d9541619"
      + "a9");

    private void oaepVecTest(
        int keySize,
        int no,
        RSAKeyParameters pubParam,
        RSAKeyParameters privParam,
        byte[] seed,
        byte[] input,
        byte[] output)
        throws Exception
    {
        encDec(keySize + " " + no, pubParam, privParam, seed, input, output);
    }

    public OAEPTest()
    {
    }

    public String getName()
    {
        return "OAEP";
    }

    public void performTest() throws Exception
    {
        baseOaepTest(1, pubKeyEnc1, privKeyEnc1, output1);
        baseOaepTest(2, pubKeyEnc2, privKeyEnc2, output2);
        baseOaepTest(3, pubKeyEnc3, privKeyEnc3, output3);

        RSAKeyParameters pubParam = new RSAKeyParameters(false, new BigInteger(1, modulus_1024), new BigInteger(1, pubExp_1024));
        RSAKeyParameters privParam = new RSAPrivateCrtKeyParameters(pubParam.getModulus(), pubParam.getExponent(), new BigInteger(1, privExp_1024), new BigInteger(1, prime1_1024), new BigInteger(1, prime2_1024), new BigInteger(1, primeExp1_1024), new BigInteger(1, primeExp2_1024), new BigInteger(1, crtCoef_1024));

        oaepVecTest(1024, 1, pubParam, privParam, seed_1024_1, input_1024_1, output_1024_1);
        oaepVecTest(1024, 2, pubParam, privParam, seed_1024_2, input_1024_2, output_1024_2);
        oaepVecTest(1024, 3, pubParam, privParam, seed_1024_3, input_1024_3, output_1024_3);
        oaepVecTest(1024, 4, pubParam, privParam, seed_1024_4, input_1024_4, output_1024_4);
        oaepVecTest(1024, 5, pubParam, privParam, seed_1024_5, input_1024_5, output_1024_5);
        oaepVecTest(1024, 6, pubParam, privParam, seed_1024_6, input_1024_6, output_1024_6);

        pubParam = new RSAKeyParameters(false, new BigInteger(1, modulus_1027), new BigInteger(1, pubExp_1027));
        privParam = new RSAPrivateCrtKeyParameters(pubParam.getModulus(), pubParam.getExponent(), new BigInteger(1, privExp_1027), new BigInteger(1, prime1_1027), new BigInteger(1, prime2_1027), new BigInteger(1, primeExp1_1027), new BigInteger(1, primeExp2_1027), new BigInteger(1, crtCoef_1027));

        oaepVecTest(1027, 1, pubParam, privParam, seed_1027_1, input_1027_1, output_1027_1);
        oaepVecTest(1027, 2, pubParam, privParam, seed_1027_2, input_1027_2, output_1027_2);
        oaepVecTest(1027, 3, pubParam, privParam, seed_1027_3, input_1027_3, output_1027_3);
        oaepVecTest(1027, 4, pubParam, privParam, seed_1027_4, input_1027_4, output_1027_4);
        oaepVecTest(1027, 5, pubParam, privParam, seed_1027_5, input_1027_5, output_1027_5);
        oaepVecTest(1027, 6, pubParam, privParam, seed_1027_6, input_1027_6, output_1027_6);

        testForHighByteError("invalidCiphertextOaepTest 1024", 1024);

        //
        // OAEP - public encrypt, private decrypt, differing hashes
        //
        AsymmetricBlockCipher cipher = new OAEPEncoding(new RSAEngine(), new SHA256Digest(), new SHA1Digest(), new byte[10]);

        cipher.init(true, new ParametersWithRandom(pubParam, new SecureRandom()));

        byte[] input = new byte[10];

        byte[] out = cipher.processBlock(input, 0, input.length);

        cipher.init(false, privParam);

        out = cipher.processBlock(out, 0, out.length);

        for (int i = 0; i != input.length; i++)
        {
            if (out[i] != input[i])
            {
                fail("mixed digest failed decoding");
            }
        }

        cipher = new OAEPEncoding(new RSAEngine(), new SHA1Digest(), new SHA256Digest(), new byte[10]);

        cipher.init(true, new ParametersWithRandom(pubParam, new SecureRandom()));

        out = cipher.processBlock(input, 0, input.length);

        cipher.init(false, privParam);

        out = cipher.processBlock(out, 0, out.length);

        for (int i = 0; i != input.length; i++)
        {
            if (out[i] != input[i])
            {
                fail("mixed digest failed decoding");
            }
        }
    }

    private void testForHighByteError(String label, int keySizeBits) throws Exception
    {
        // draw a key of the size asked
        BigInteger e = BigIntegers.ONE.shiftLeft(16).add(BigIntegers.ONE);

        AsymmetricCipherKeyPairGenerator kpGen = new RSAKeyPairGenerator();

        kpGen.init(new RSAKeyGenerationParameters(e, new SecureRandom(), keySizeBits, 100));

        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

        AsymmetricBlockCipher cipher = new OAEPEncoding(new RSAEngine());

        // obtain a known good ciphertext
        cipher.init(true, new ParametersWithRandom(kp.getPublic(), new VecRand(seed)));
        byte[] m = { 42 };
        byte[] c = cipher.processBlock(m, 0, m.length);
        int keySizeBytes = (keySizeBits+7)>>>3;
        if (c.length!=keySizeBytes)
        {
            fail(label + " failed ciphertext size");
        }

        BigInteger n  = ((RSAPrivateCrtKeyParameters)kp.getPrivate()).getModulus();

        // decipher
        cipher.init(false, kp.getPrivate());
        byte[] r = cipher.processBlock(c, 0, keySizeBytes);
        if (r.length!=1 || r[0]!=42)
        {
            fail(label + " failed first decryption of test message");
        }

        // decipher again
        r = cipher.processBlock(c, 0, keySizeBytes);
        if (r.length!=1 || r[0]!=42)
        {
            fail(label + " failed second decryption of test message");
        }

        // check hapazard incorrect ciphertexts
        for(int i=keySizeBytes*8; --i>=0;)
        {
            c[i>>>3] ^= 1<<(i&7);
            boolean ko = true;
            try
            {
                BigInteger cV = new BigInteger(1, c);

                // don't pass in c if it will be rejected trivially
                if (cV.compareTo(n) < 0)
                {
                    r = cipher.processBlock(c, 0, keySizeBytes);
                }
                else
                {
                    ko = false; // size errors are picked up at start
                }
            }
            catch (InvalidCipherTextException exception)
            {
                ko = false;
            }
            if (ko)
            {
                fail(label + " invalid ciphertext caused no exception");
            }
            c[i>>>3] ^= 1<<(i&7);
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new OAEPTest());
    }
}
