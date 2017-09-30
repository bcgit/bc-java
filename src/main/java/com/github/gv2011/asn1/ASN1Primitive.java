package com.github.gv2011.asn1;

import static com.github.gv2011.util.ex.Exceptions.call;

import java.io.IOException;

import com.github.gv2011.util.bytes.Bytes;

/**
 * Base class for ASN.1 primitive objects. These are the actual objects used to
 * generate byte encodings.
 */
public abstract class ASN1Primitive extends ASN1Object {

  ASN1Primitive() {}

  /**
   * Create a base ASN.1 object from a byte stream.
   *
   * @param data
   *          the byte stream to parse.
   * @return the base ASN.1 object represented by the byte stream.
   * @exception IOException
   *              if there is a problem parsing the data, or parsing the stream
   *              did not exhaust the available data.
   */
  public static ASN1Primitive fromByteArray(final Bytes data){

    @SuppressWarnings("resource")
    final ASN1InputStream aIn = new ASN1InputStream(data);

    try {
      final ASN1Primitive o = aIn.readObject();

      if (call(aIn::available) != 0) { throw new ASN1Exception("Extra data detected in stream"); }

      return o;
    } catch (final ClassCastException e) {
      throw new ASN1Exception("cannot recognise object in stream");
    }
  }

  @Override
  public final boolean equals(final Object o) {
    if (this == o) { return true; }

    return (o instanceof ASN1Encodable) && asn1Equals(((ASN1Encodable) o).toASN1Primitive());
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return this;
  }

  /**
   * Return the current object as one which encodes using Distinguished Encoding
   * Rules.
   *
   * @return a DER version of this.
   */
  ASN1Primitive toDERObject() {
    return this;
  }

  /**
   * Return the current object as one which encodes using Definite Length
   * encoding.
   *
   * @return a DL version of this.
   */
  ASN1Primitive toDLObject() {
    return this;
  }

  @Override
  public abstract int hashCode();

  abstract boolean isConstructed();

  abstract int encodedLength();

  abstract void encode(ASN1OutputStream out);

  abstract boolean asn1Equals(ASN1Primitive o);
}
