package org.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.signers.SHAKEPSSSigner;

public class SHAKEPSSSignatureSpi
    extends SignatureSpi {
  private RSAKeyParameters key;
  private SecureRandom random;

  private Signer signer;

  // care - this constructor is actually used by outside organisations
  protected SHAKEPSSSignatureSpi(int type, int size) {
      this.signer = new SHAKEPSSSigner(new RSABlindedEngine(), type, size);
  }

  protected void engineInitVerify(
      PublicKey publicKey)
      throws InvalidKeyException {
    if (!(publicKey instanceof RSAPublicKey)) {
      throw new InvalidKeyException("Supplied key is not a RSAPublicKey instance");
    }

    RSAPublicKey rsaPk = (RSAPublicKey) publicKey;
    key = new RSAKeyParameters(false, rsaPk.getModulus(), rsaPk.getPublicExponent());

    signer.init(false, key);
  }

  protected void engineInitSign(
      PrivateKey privateKey,
      SecureRandom random)
      throws InvalidKeyException {
    this.random = random;
    engineInitSign(privateKey);
  }

  protected void engineInitSign(
      PrivateKey privateKey)
      throws InvalidKeyException {
    if (!(privateKey instanceof RSAPrivateKey)) {
      throw new InvalidKeyException("Supplied key is not a RSAPrivateKey instance");
    }

    key = generatePrivateKeyParameter((RSAPrivateKey)privateKey);
    if (random != null) {
      signer.init(true, new ParametersWithRandom(key, random));
    } else {
      signer.init(true, key);
    }
  }

  private static RSAKeyParameters generatePrivateKeyParameter(
      RSAPrivateKey key) {
    if (key instanceof RSAPrivateCrtKey) {
      RSAPrivateCrtKey k = (RSAPrivateCrtKey)key;

      return new RSAPrivateCrtKeyParameters(k.getModulus(),
          k.getPublicExponent(), k.getPrivateExponent(),
          k.getPrimeP(), k.getPrimeQ(), k.getPrimeExponentP(),
          k.getPrimeExponentQ(), k.getCrtCoefficient());
    } else {
      return new RSAKeyParameters(true, key.getModulus(), key.getPrivateExponent());
    }
  }

  protected void engineUpdate(
      byte    b)
      throws SignatureException {
    signer.update(b);
  }

  protected void engineUpdate(
      byte[]  b,
      int     off,
      int     len)
      throws SignatureException {
    signer.update(b, off, len);
  }

  protected byte[] engineSign()
      throws SignatureException {
    try {
      return signer.generateSignature();
    } catch (CryptoException e) {
      throw new SignatureException(e.getMessage());
    }
  }

  protected boolean engineVerify(
      byte[]  sigBytes)
      throws SignatureException {
    return signer.verifySignature(sigBytes);
  }

  protected void engineSetParameter(
      AlgorithmParameterSpec params)
      throws InvalidAlgorithmParameterException {
    throw new UnsupportedOperationException("engineSetParameter unsupported");
  }

  protected AlgorithmParameters engineGetParameters() {
    return null;
  }

  /**
   * @deprecated replaced with
   * <a href="#engineSetParameter(java.security.spec.AlgorithmParameterSpec)">
   * engineSetParameter(java.security.spec.AlgorithmParameterSpec)</a>
   */
  protected void engineSetParameter(
      String param,
      Object value) {
    throw new UnsupportedOperationException("engineSetParameter unsupported");
  }

  protected Object engineGetParameter(
      String param) {
    throw new UnsupportedOperationException("engineGetParameter unsupported");
  }

  static public class SHAKE128WithRSAPSS extends SHAKEPSSSignatureSpi {
    public SHAKE128WithRSAPSS() {
      super(128, 256);
    }
  }

  static public class SHAKE256WithRSAPSS extends SHAKEPSSSignatureSpi {
    public SHAKE256WithRSAPSS() {
      super(256, 512);
    }
  }
}
