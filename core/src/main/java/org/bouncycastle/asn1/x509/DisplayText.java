
package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DERVisibleString;

/**
 * <code>DisplayText</code> class, used in
 * <code>CertificatePolicies</code> X509 V3 extensions (in policy qualifiers).
 *
 * <p>It stores a string in a chosen encoding. 
 * <pre>
 * DisplayText ::= CHOICE {
 *      ia5String        IA5String      (SIZE (1..200)),
 *      visibleString    VisibleString  (SIZE (1..200)),
 *      bmpString        BMPString      (SIZE (1..200)),
 *      utf8String       UTF8String     (SIZE (1..200)) }
 * </pre>
 * @see PolicyQualifierInfo
 * @see PolicyInformation
 */
public class DisplayText 
    extends ASN1Object
    implements ASN1Choice
{
   /**
    * Constant corresponding to ia5String encoding. 
    *
    */
   public static final int CONTENT_TYPE_IA5STRING = 0;
   /**
    * Constant corresponding to bmpString encoding. 
    *
    */
   public static final int CONTENT_TYPE_BMPSTRING = 1;
   /**
    * Constant corresponding to utf8String encoding. 
    *
    */
   public static final int CONTENT_TYPE_UTF8STRING = 2;
   /**
    * Constant corresponding to visibleString encoding. 
    *
    */
   public static final int CONTENT_TYPE_VISIBLESTRING = 3;

   /**
    * Describe constant <code>DISPLAY_TEXT_MAXIMUM_SIZE</code> here.
    *
    */
   public static final int DISPLAY_TEXT_MAXIMUM_SIZE = 200;
   
   int contentType;
   ASN1String contents;
   
   /**
    * Creates a new <code>DisplayText</code> instance.
    *
    * @param type the desired encoding type for the text. 
    * @param text the text to store. Strings longer than 200
    * characters are truncated. 
    */
   public DisplayText(int type, String text)
   {
      if (text.length() > DISPLAY_TEXT_MAXIMUM_SIZE)
      {
         // RFC3280 limits these strings to 200 chars
         // truncate the string
         text = text.substring (0, DISPLAY_TEXT_MAXIMUM_SIZE);
      }
     
      contentType = type;
      switch (type)
      {
         case CONTENT_TYPE_IA5STRING:
            contents = new DERIA5String(text);
            break;
         case CONTENT_TYPE_UTF8STRING:
            contents = new DERUTF8String(text);
            break;
         case CONTENT_TYPE_VISIBLESTRING:
            contents = new DERVisibleString(text);
            break;
         case CONTENT_TYPE_BMPSTRING:
            contents = new DERBMPString(text);
            break;
         default:
            contents = new DERUTF8String(text);
            break;
      }
   }
   
   /**
    * Creates a new <code>DisplayText</code> instance.
    *
    * @param text the text to encapsulate. Strings longer than 200
    * characters are truncated. 
    */
   public DisplayText(String text) 
   {
      // by default use UTF8String
      if (text.length() > DISPLAY_TEXT_MAXIMUM_SIZE)
      {
         text = text.substring(0, DISPLAY_TEXT_MAXIMUM_SIZE);
      }
      
      contentType = CONTENT_TYPE_UTF8STRING;
      contents = new DERUTF8String(text);
   }

   /**
    * Creates a new <code>DisplayText</code> instance.
    * <p>Useful when reading back a <code>DisplayText</code> class
    * from it's ASN1Encodable/DEREncodable form. 
    *
    * @param de a <code>DEREncodable</code> instance. 
    */
   private DisplayText(ASN1String de)
   {
      contents = de;
      if (de instanceof DERUTF8String)
      {
         contentType = CONTENT_TYPE_UTF8STRING;
      }
      else if (de instanceof DERBMPString)
      {
         contentType = CONTENT_TYPE_BMPSTRING;
      }
      else if (de instanceof DERIA5String)
      {
         contentType = CONTENT_TYPE_IA5STRING;
      }
      else if (de instanceof DERVisibleString)
      {
         contentType = CONTENT_TYPE_VISIBLESTRING;
      }
      else
      {
         throw new IllegalArgumentException("unknown STRING type in DisplayText");
      }
   }

   public static DisplayText getInstance(Object obj) 
   {
      if  (obj instanceof ASN1String)
      {
          return new DisplayText((ASN1String)obj);
      }
      else if (obj == null || obj instanceof DisplayText)
      {
          return (DisplayText)obj;
      }

      throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
   }

   public static DisplayText getInstance(
       ASN1TaggedObject obj,
       boolean          explicit)
   {
       return getInstance(obj.getObject()); // must be explicitly tagged
   }
   
   public ASN1Primitive toASN1Primitive()
   {
      return (ASN1Primitive)contents;
   }

   /**
    * Returns the stored <code>String</code> object. 
    *
    * @return the stored text as a <code>String</code>. 
    */
   public String getString() 
   {
      return contents.getString();
   }   
}
