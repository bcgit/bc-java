package com.github.gv2011.asn1;

public class ASN1ParsingException extends IllegalStateException {

  private static final long serialVersionUID = -6152659036346724789L;

  private Throwable cause;

  public ASN1ParsingException(final String message) {
    super(message);
  }

  public ASN1ParsingException(final String message, final Throwable cause) {
    super(message);
    this.cause = cause;
  }

  @Override
  public Throwable getCause() {
    return cause;
  }
}
