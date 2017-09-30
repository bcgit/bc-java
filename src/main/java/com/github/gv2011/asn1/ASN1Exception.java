package com.github.gv2011.asn1;

public class ASN1Exception extends RuntimeException{

  private static final long serialVersionUID = -2721088745216034082L;

  private Throwable cause;

  ASN1Exception(final String message){
    super(message);
  }

  ASN1Exception(final String message, final Throwable cause){
    super(message);
    this.cause = cause;
  }

  public ASN1Exception() {}

  @Override
  public Throwable getCause(){
    return cause;
  }
}
