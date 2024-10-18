package org.bouncycastle.crypto.split;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;

import org.bouncycastle.crypto.split.attribute.KMIPName;
import org.bouncycastle.crypto.split.attribute.KMIPUniqueIdentifier;
import org.bouncycastle.crypto.split.attribute.KMIPVendorAttribute;
import org.bouncycastle.crypto.split.enumeration.KMIPCryptographicAlgorithm;
import org.bouncycastle.crypto.split.enumeration.KMIPCryptographicUsageMask;
import org.bouncycastle.crypto.split.enumeration.KMIPEnumeration;
import org.bouncycastle.crypto.split.enumeration.KMIPNameType;
import org.bouncycastle.crypto.split.enumeration.KMIPObjectType;
import org.bouncycastle.crypto.split.enumeration.KMIPOperation;
import org.bouncycastle.crypto.split.enumeration.KMIPResultReason;
import org.bouncycastle.crypto.split.enumeration.KMIPResultStatus;
import org.bouncycastle.crypto.split.enumeration.KMIPSplitKeyMethod;
import org.bouncycastle.crypto.split.message.KMIPBatchItem;
import org.bouncycastle.crypto.split.message.KMIPMessage;
import org.bouncycastle.crypto.split.message.KMIPProtocolVersion;
import org.bouncycastle.crypto.split.message.KMIPRequestBatchItem;
import org.bouncycastle.crypto.split.message.KMIPRequestHeader;
import org.bouncycastle.crypto.split.message.KMIPRequestMessage;
import org.bouncycastle.crypto.split.message.KMIPRequestPayload;
import org.bouncycastle.crypto.split.message.KMIPRequestPayloadCreate;
import org.bouncycastle.crypto.split.message.KMIPRequestPayloadCreateSplitKey;
import org.bouncycastle.crypto.split.message.KMIPRequestPayloadDefault;
import org.bouncycastle.crypto.split.message.KMIPRequestPayloadGet;
import org.bouncycastle.crypto.split.message.KMIPRequestPayloadJoinSplitKey;
import org.bouncycastle.crypto.split.message.KMIPRequestPayloadRegister;
import org.bouncycastle.crypto.split.message.KMIPResponseBatchItem;
import org.bouncycastle.crypto.split.message.KMIPResponseHeader;
import org.bouncycastle.crypto.split.message.KMIPResponseMessage;
import org.bouncycastle.crypto.split.message.KMIPResponsePayload;
import org.bouncycastle.crypto.split.message.KMIPResponsePayloadCreate;
import org.bouncycastle.crypto.split.message.KMIPResponsePayloadCreateSplitKey;
import org.bouncycastle.crypto.split.message.KMIPResponsePayloadDefault;
import org.bouncycastle.crypto.split.message.KMIPResponsePayloadGet;
import org.bouncycastle.crypto.split.object.KMIPKeyBlock;
import org.bouncycastle.crypto.split.object.KMIPObject;
import org.bouncycastle.crypto.split.object.KMIPSplitKey;
import org.bouncycastle.crypto.split.object.KMIPSymmetricKey;
import org.bouncycastle.util.encoders.Hex;

public class KMIPInputStream
{
    private XMLEventReader eventReader;

    public KMIPInputStream(InputStream stream)
        throws XMLStreamException
    {
        this.eventReader = XMLInputFactory.newInstance().createXMLEventReader(stream);
    }

    public KMIPMessage[] parse()
        throws XMLStreamException, KMIPInputException
    {
        ArrayList<KMIPMessage> messages = new ArrayList<KMIPMessage>();
        // Get a list of elements
        try
        {
            while (eventReader.hasNext())
            {
                XMLEvent event = eventReader.nextEvent();
                if (event.isStartElement())
                {
                    StartElement startElement = event.asStartElement();
                    String name = startElement.getName().getLocalPart();
                    if (name.equals("RequestMessage") || name.equals("ResponseMessage"))
                    {
                        KMIPMessage message = parseMessage();
                        messages.add(message);
                    }
                }
            }
        }
        catch (XMLStreamException e)
        {
            System.err.println("Error processing XML: " + e.getMessage());
        }

        KMIPMessage[] rlt = new KMIPMessage[messages.size()];
        messages.toArray(rlt);
        return rlt;
    }


    public KMIPMessage parseMessage()
        throws KMIPInputException
    {
        KMIPRequestHeader requestHeader = null;
        KMIPResponseHeader responseHeader = null;
        boolean isRequest = true;
        ArrayList<KMIPBatchItem> batchItems = new ArrayList<KMIPBatchItem>();
        try
        {
            while (eventReader.hasNext())
            {
                XMLEvent event = eventReader.nextEvent();
                if (event.isStartElement())
                {
                    StartElement startElement = event.asStartElement();
                    String name = startElement.getName().getLocalPart();
                    if (name.equals("RequestHeader"))
                    {
                        requestHeader = parseRequestHeader();
                        isRequest = true;
                    }
                    else if (name.equals("ResponseHeader"))
                    {
                        responseHeader = parseResponseHeader();
                        isRequest = false;
                    }
                    else if (name.equals("BatchItem"))
                    {
                        if (isRequest)
                        {
                            KMIPRequestBatchItem batchItem = parseRequestBatchItem();
                            batchItems.add(batchItem);
                        }
                        else
                        {
                            KMIPResponseBatchItem batchItem = parseResponseBatchItem();
                            batchItems.add(batchItem);
                        }
                    }
                }

                if (event.isEndElement())
                {
                    assertEndElement(event, isRequest ? "RequestMessage" : "ResponseMessage",
                        "Error in processing the end of Message: ");
                    break;
                }

            }
        }
        catch (XMLStreamException e)
        {
            System.err.println("Error processing XML: " + e.getMessage());
        }
        if (isRequest)
        {
            KMIPRequestBatchItem[] items = new KMIPRequestBatchItem[batchItems.size()];
            batchItems.toArray(items);
            return new KMIPRequestMessage(requestHeader, items);
        }
        else
        {
            KMIPResponseBatchItem[] items = new KMIPResponseBatchItem[batchItems.size()];
            batchItems.toArray(items);
            return new KMIPResponseMessage(responseHeader, items);
        }
    }

    public KMIPRequestHeader parseRequestHeader()
        throws KMIPInputException
    {
        KMIPProtocolVersion protocolVersion = null;
        String clientCorrelationValue = null;
        int batchCount = -1;
        try
        {
            while (eventReader.hasNext())
            {
                XMLEvent event = eventReader.nextEvent();
                if (event.isStartElement())
                {
                    StartElement startElement = event.asStartElement();
                    String name = startElement.getName().getLocalPart();
                    if (name.equals("ProtocolVersion"))
                    {
                        protocolVersion = parseProtocolVersion();
                    }
                    else if (name.equals("ClientCorrelationValue"))
                    {
                        clientCorrelationValue = parseTextString(startElement, "ClientCorrelationValue");
                    }
                    else if (name.equals("BatchCount"))
                    {
                        batchCount = parseInteger(startElement, "BatchCount");
                    }
                    else
                    {
                        throw new KMIPInputException("Add more code to support parseRequestHeader");
                    }
                }
                if (event.isEndElement())
                {
                    assertEndElement(event, "RequestHeader", "Error in processing RequestHeader: ");
                    break;
                }
            }

            if (protocolVersion == null || batchCount == -1)
            {
                throw new KMIPInputException("Request Header should contain Protocol Version and Batch Count");
            }
            KMIPRequestHeader header = new KMIPRequestHeader(protocolVersion, batchCount);
            header.setClientCorrelationValue(clientCorrelationValue);
            return header;
        }
        catch (XMLStreamException e)
        {
            System.err.println("Error processing XML: " + e.getMessage());
        }
        return null;
    }

    public KMIPResponseHeader parseResponseHeader()
        throws KMIPInputException
    {
        KMIPProtocolVersion protocolVersion = null;
        Date timestamp = null;
        int batchCount = -1;
        try
        {
            while (eventReader.hasNext())
            {
                XMLEvent event = eventReader.nextEvent();
                if (event.isStartElement())
                {
                    StartElement startElement = event.asStartElement();
                    String name = startElement.getName().getLocalPart();
                    if (name.equals("ProtocolVersion"))
                    {
                        protocolVersion = parseProtocolVersion();
                    }
                    else if (name.equals("TimeStamp"))
                    {
                        timestamp = parseDateTime(startElement, "Error in parsing TimeStamp: ");
                        assertEndElement(event, "TimeStamp", "Error in processing TimeStamp: ");
                    }
                    else if (name.equals("BatchCount"))
                    {
                        batchCount = parseInteger(startElement, "BatchCount");
                    }
                    else
                    {
                        throw new KMIPInputException("Add more code to support parseRequestHeader");
                    }
                }
                if (event.isEndElement())
                {
                    assertEndElement(event, "ResponseHeader", "Error in processing RequestHeader: ");
                    break;
                }
            }

            if (protocolVersion == null || batchCount == -1)
            {
                throw new KMIPInputException("Response Header should contain Protocol Version and Batch Count");
            }
            KMIPResponseHeader header = new KMIPResponseHeader(protocolVersion, timestamp, batchCount);
            return header;
        }
        catch (XMLStreamException e)
        {
            System.err.println("Error processing XML: " + e.getMessage());
        }
        return null;
    }


    private KMIPRequestBatchItem parseRequestBatchItem()
        throws KMIPInputException
    {
        KMIPOperation operation = null;
        KMIPRequestPayload requestPayload = null;

        try
        {
            while (eventReader.hasNext())
            {
                XMLEvent event = eventReader.nextEvent();
                if (event.isStartElement())
                {
                    StartElement startElement = event.asStartElement();
                    String name = startElement.getName().getLocalPart();
                    if (name.equals("Operation"))
                    {
                        operation = parseEnum(startElement, KMIPOperation.class, "Operation");
                    }
                    else if (name.equals("RequestPayload"))
                    {
                        requestPayload = parseRequestPayload(operation);
                    }
                    else
                    {
                        throw new KMIPInputException("Add more code to support parseRequestBatchItem");
                    }
                }
                if (event.isEndElement())
                {
                    assertEndElement(event, "BatchItem", "Error in parsing batch item");
                    break;
                }
            }
            if (operation == null || requestPayload == null)
            {
                throw new KMIPInputException("Request Header should contain Protocol Version and Batch Count");
            }
            KMIPRequestBatchItem batchItem = new KMIPRequestBatchItem(operation, requestPayload);

            return batchItem;
        }
        catch (XMLStreamException e)
        {
            System.err.println("Error processing XML: " + e.getMessage());
        }
        return null;
    }


    //TODO:
    private KMIPResponseBatchItem parseResponseBatchItem()
        throws KMIPInputException
    {
        KMIPOperation operation = null;
        KMIPResultStatus resultStatus = null;
        KMIPResponsePayload requestPayload = null;
        KMIPResultReason resultReason = null;
        String resultMessage = null;
        try
        {
            while (eventReader.hasNext())
            {
                XMLEvent event = eventReader.nextEvent();
                if (event.isStartElement())
                {
                    StartElement startElement = event.asStartElement();
                    String name = startElement.getName().getLocalPart();
                    if (name.equals("Operation"))
                    {
                        operation = parseEnum(startElement, KMIPOperation.class, "Operation");
                    }
                    else if (name.equals("ResultStatus"))
                    {
                        resultStatus = parseEnum(startElement, KMIPResultStatus.class, "ResultStatus");
                    }
                    else if (name.equals("ResponsePayload"))
                    {
                        requestPayload = parseResponsePayload(operation);
                    }
                    else if (name.equals("ResultReason"))
                    {
                        resultReason = parseEnum(startElement, KMIPResultReason.class, "ResultReason");
                    }
                    else if (name.equals("ResultMessage"))
                    {
                        resultMessage = parseTextString(startElement, "ResultMessage");
                    }
                    else
                    {
                        throw new KMIPInputException("Add more code to support parseResponseBatchItem");
                    }
                }
                if (event.isEndElement())
                {
                    assertEndElement(event, "BatchItem", "Error in parsing batch item");
                    break;
                }
            }
            if (operation == null || (requestPayload == null && resultStatus != KMIPResultStatus.OperationFailed))
            {
                throw new KMIPInputException("Request Header should contain Protocol Version and Batch Count");
            }
            KMIPResponseBatchItem batchItem = new KMIPResponseBatchItem(operation, resultStatus, requestPayload);
            if (resultReason == null)
            {
                if (resultStatus == KMIPResultStatus.OperationFailed)
                {
                    throw new KMIPInputException("Result Reason is REQUIRED if Result Status is Failure");
                }
            }
            else
            {
                batchItem.setResultReason(resultReason);
            }
            if (resultMessage != null)
            {
                batchItem.setResultMessage(resultMessage);
            }
            return batchItem;
        }
        catch (XMLStreamException e)
        {
            System.err.println("Error processing XML: " + e.getMessage());
        }
        return null;
    }

    private KMIPRequestPayload parseRequestPayload(KMIPOperation operation)
        throws KMIPInputException
    {
        KMIPObjectType objectType = null;
        Map<String, Object> attributes = null;
        XMLEvent event = null;
        KMIPUniqueIdentifier uniqueIdentifier = null;
        ArrayList<KMIPUniqueIdentifier> uniqueIdentifiers = new ArrayList<KMIPUniqueIdentifier>();
        int splitKeyParts = 0, splitKeyThreshold = 0;
        KMIPSplitKeyMethod splitKeyMethod = null;
        KMIPObject object = null;
        try
        {
            while (eventReader.hasNext())
            {
                event = eventReader.nextEvent();
                if (event.isStartElement())
                {
                    StartElement startElement = event.asStartElement();
                    String name = startElement.getName().getLocalPart();
                    if (name.equals("ObjectType"))
                    {
                        objectType = parseEnum(startElement, KMIPObjectType.class, "ObjectType");
                    }
                    else if (name.equals("Attributes"))
                    {
                        attributes = parseAttributes();
                    }
                    else if (name.equals("UniqueIdentifier"))
                    {
                        uniqueIdentifier = parseUniqueIdentifier(startElement, "Error in parsing Unique Identifier");
                        uniqueIdentifiers.add(uniqueIdentifier);
                    }
                    else if (name.equals("SplitKeyParts"))
                    {
                        splitKeyParts = parseInteger(startElement, "SplitKeyParts");
                    }
                    else if (name.equals("SplitKeyThreshold"))
                    {
                        splitKeyThreshold = parseInteger(startElement, "SplitKeyThreshold");
                    }
                    else if (name.equals("SplitKeyMethod"))
                    {
                        splitKeyMethod = parseEnum(startElement, KMIPSplitKeyMethod.class, "SplitKeyMethod");
                    }
                    else if (name.equals("SymmetricKey"))
                    {
                        assertStartElement("KeyBlock");
                        KMIPKeyBlock keyBlock = parseKeyBlock();

                        object = new KMIPSymmetricKey(keyBlock);
                        assertEndElement(event, "SymmetricKey", "Error in parsing SymmetricKey: ");
                    }
                    else if (name.equals("SplitKey"))
                    {
                        object = parseSplitKey(event);
                    }
                    else
                    {
                        throw new KMIPInputException("Add more code to support parseRequestPayload");
                    }
                }

                if (event.isEndElement())
                {
                    assertEndElement(event, "RequestPayload", "Error in parsing RequestPayload: ");
                    break;
                }
            }

            switch (operation)
            {
            case Create:
                return new KMIPRequestPayloadCreate(objectType, attributes);
            case CreateSplitKey:
                KMIPRequestPayloadCreateSplitKey splitkey = new KMIPRequestPayloadCreateSplitKey(objectType, splitKeyParts,
                    splitKeyThreshold, splitKeyMethod, attributes);
                if (uniqueIdentifier != null)
                {
                    splitkey.setUniqueIdentifier(uniqueIdentifier);
                }
                return splitkey;
            case JoinSplitKey:
                KMIPUniqueIdentifier[] kmipUniqueIdentifiers = new KMIPUniqueIdentifier[uniqueIdentifiers.size()];
                uniqueIdentifiers.toArray(kmipUniqueIdentifiers);
                KMIPRequestPayloadJoinSplitKey joinSplitKey = new KMIPRequestPayloadJoinSplitKey(objectType, kmipUniqueIdentifiers);
                if (attributes != null)
                {
                    joinSplitKey.setAttributes(attributes);
                }
                return joinSplitKey;
            case Destroy:
                KMIPRequestPayloadDefault destroy = new KMIPRequestPayloadDefault();
                if (uniqueIdentifier != null)
                {
                    destroy.setUniqueIdentifier(uniqueIdentifier);
                }
                return destroy;
            case Register:
                KMIPRequestPayloadRegister register = new KMIPRequestPayloadRegister(objectType, attributes, object);
                return register;
            case Get:
                KMIPRequestPayloadGet get = new KMIPRequestPayloadGet();
                if (uniqueIdentifier != null)
                {
                    get.setUniqueIdentifier(uniqueIdentifier);
                }
                return get;
            default:
                throw new KMIPInputException("add more support for parseRequestPayload");
            }
        }
        catch (XMLStreamException e)
        {
            System.err.println("Error processing XML: " + e.getMessage());
        }
        return null;
    }

    private KMIPResponsePayload parseResponsePayload(KMIPOperation operation)
        throws KMIPInputException
    {
        KMIPObjectType objectType = null;
        KMIPUniqueIdentifier uniqueIdentifier = null;
        ArrayList<KMIPUniqueIdentifier> uniqueIdentifiers = new ArrayList<KMIPUniqueIdentifier>();
        XMLEvent event = null;
        int splitKeyParts = 0, splitKeyThreshold = 0;
        KMIPSplitKeyMethod splitKeyMethod = null;
        KMIPObject object = null;
        try
        {
            while (eventReader.hasNext())
            {
                event = eventReader.nextEvent();
                if (event.isStartElement())
                {
                    StartElement startElement = event.asStartElement();
                    String name = startElement.getName().getLocalPart();
                    if (name.equals("ObjectType"))
                    {
                        objectType = parseEnum(startElement, KMIPObjectType.class, "ObjectType");
                    }
                    else if (name.equals("UniqueIdentifier"))
                    {
                        uniqueIdentifier = parseUniqueIdentifier(startElement, "Error in parsing Unique Identifier: ");
                        uniqueIdentifiers.add(uniqueIdentifier);
                    }
                    else if (name.equals("SplitKey"))
                    {
                        object = parseSplitKey(event);
                    }
                    else if (name.equals("SymmetricKey"))
                    {
                        assertStartElement("KeyBlock");
                        KMIPKeyBlock keyBlock = parseKeyBlock();

                        object = new KMIPSymmetricKey(keyBlock);
                        assertEndElement(event, "SymmetricKey", "Error in parsing SymmetricKey: ");
                    }
                    else
                    {
                        throw new KMIPInputException("Add more code to support parseRespondePayload");
                    }
                }

                if (event.isEndElement())
                {
                    assertEndElement(event, "ResponsePayload", "Error in parsing ResponsePayload: ");
                    break;
                }
            }

            switch (operation)
            {
            case Create:
                return new KMIPResponsePayloadCreate(objectType, uniqueIdentifier);
            case CreateSplitKey:
                KMIPUniqueIdentifier[] kmipUniqueIdentifiers = new KMIPUniqueIdentifier[uniqueIdentifiers.size()];
                uniqueIdentifiers.toArray(kmipUniqueIdentifiers);
                return new KMIPResponsePayloadCreateSplitKey(kmipUniqueIdentifiers);
            case JoinSplitKey:
            case Destroy:
            case Register:
                return new KMIPResponsePayloadDefault(uniqueIdentifier);
            case Get:
                return new KMIPResponsePayloadGet(objectType, uniqueIdentifier, object);
            default:
                throw new KMIPInputException("add more support for parseResponsePayload");
            }
        }
        catch (XMLStreamException e)
        {
            System.err.println("Error processing XML: " + e.getMessage());
        }
        return null;
    }

    private KMIPSplitKey parseSplitKey(XMLEvent event)
        throws XMLStreamException, KMIPInputException
    {
        StartElement startElement = assertStartElement("SplitKeyParts");
        int splitKeyParts = parseInteger(startElement, "SplitKeyParts");

        startElement = assertStartElement("KeyPartIdentifier");
        int keyPartIdentifier = parseInteger(startElement, "KeyPartIdentifier");

        startElement = assertStartElement("SplitKeyThreshold");
        int splitKeyThreshold = parseInteger(startElement, "SplitKeyThreshold");

        startElement = assertStartElement("SplitKeyMethod");
        KMIPSplitKeyMethod splitKeyMethod = parseEnum(startElement, KMIPSplitKeyMethod.class, "SplitKeyMethod");
        assertStartElement("KeyBlock");
        KMIPKeyBlock keyBlock = parseKeyBlock();
        assertEndElement(event, "SplitKey", "Error in parsing SplitKey: ");
        return new KMIPSplitKey(splitKeyParts, keyPartIdentifier, splitKeyThreshold, splitKeyMethod, null, keyBlock);
    }

    private Map<String, Object> parseAttributes()
        throws KMIPInputException
    {
        Map<String, Object> attributes = new HashMap<String, Object>();
        try
        {
            while (eventReader.hasNext())
            {
                XMLEvent event = eventReader.nextEvent();
                if (event.isStartElement())
                {
                    StartElement startElement = event.asStartElement();
                    String name = startElement.getName().getLocalPart();
                    if (name.equals("CryptographicAlgorithm"))
                    {
                        KMIPEnumeration cryptographicAlgorithm = parseEnum(startElement, KMIPCryptographicAlgorithm.class, "CryptographicAlgorithm");
                        attributes.put("CryptographicAlgorithm", cryptographicAlgorithm);
                    }
                    else if (name.equals("CryptographicLength"))
                    {
                        int cryptographicLength = parseInteger(startElement, "CryptographicLength");
                        attributes.put("CryptographicLength", cryptographicLength);
                    }
                    else if (name.equals("CryptographicUsageMask"))
                    {
                        int cryptographicUsageMask = parseInteger(startElement, KMIPCryptographicUsageMask.class, "Error in parsing CryptographicUsageMask: ");
                        attributes.put("CryptographicUsageMask", cryptographicUsageMask);
                        assertEndElement(event, "CryptographicUsageMask", "Error in parsing CryptographicUsageMask: ");
                    }
                    else if (name.equals("Name"))
                    {
                        startElement = assertStartElement("NameValue");
                        String nameValue = parseTextString(startElement, "NameValue");
                        startElement = assertStartElement("NameType");
                        KMIPNameType nameType = parseEnum(startElement, KMIPNameType.class, "NameType");

                        assertEndElement(event, "Name", "Error in processing Name: ");
                        KMIPName kmipName = new KMIPName(nameValue, nameType);
                        attributes.put("Name", kmipName);
                    }
                    else if (name.equals("Attribute"))
                    {
                        startElement = assertStartElement("VendorIdentification");
                        String vendorIdentification = parseTextString(startElement, "VendorIdentification");
                        startElement = assertStartElement("AttributeName");
                        String attributeName = parseTextString(startElement, "AttributeName");
                        startElement = assertStartElement("AttributeValue");
                        String attributeValue = parseTextString(startElement, "AttributeValue");
                        assertEndElement(event, "Attribute", "Error in processing Attribute: ");
                        KMIPVendorAttribute vendorAttribute = new KMIPVendorAttribute(vendorIdentification, attributeName, attributeValue);
                        attributes.put("VendorAttribute", vendorAttribute);
                    }
                    else
                    {
                        throw new KMIPInputException("Add more code to support parseAttributes");
                    }
                }

                if (event.isEndElement())
                {
                    assertEndElement(event, "Attributes", "Error in processing Name: ");
                    return attributes;
                }
            }
        }
        catch (XMLStreamException e)
        {
            System.err.println("Error processing XML: " + e.getMessage());
        }
        return null;
    }

    private KMIPKeyBlock parseKeyBlock()
        throws KMIPInputException
    {
        KMIPKeyFormatType keyFormatType = null;
        byte[] keyValue = null;
        KMIPCryptographicAlgorithm cryptographicAlgorithm = null;
        int cryptographicLength = 0;
        try
        {
            while (eventReader.hasNext())
            {
                XMLEvent event = eventReader.nextEvent();
                if (event.isStartElement())
                {
                    StartElement startElement = event.asStartElement();
                    String name = startElement.getName().getLocalPart();
                    if (name.equals("KeyFormatType"))
                    {
                        keyFormatType = parseEnum(startElement, KMIPKeyFormatType.class, "KeyFormatType");
                    }
                    else if (name.equals("KeyValue"))
                    {
                        startElement = assertStartElement("KeyMaterial");
                        keyValue = parseByteString(startElement, "Error in parsing KeyMaterial: ");
                        assertEndElement(event, "KeyMaterial", "Error in parsing KeyMaterial: ");
                        assertEndElement(event, "KeyValue", "Error in parsing KeyValue: ");
                    }
                    else if (name.equals("CryptographicAlgorithm"))
                    {
                        cryptographicAlgorithm = parseEnum(startElement, KMIPCryptographicAlgorithm.class, "CryptographicAlgorithm");
                    }
                    else if (name.equals("CryptographicLength"))
                    {
                        cryptographicLength = parseInteger(startElement, "CryptographicLength");
                    }
                    else
                    {
                        throw new KMIPInputException("Add more code to support parseKeyBlock");
                    }
                }

                if (event.isEndElement())
                {
                    assertEndElement(event, "KeyBlock", "Error in processing Name: ");
                    return new KMIPKeyBlock(keyFormatType, keyValue, cryptographicAlgorithm, cryptographicLength);
                }
            }
        }
        catch (XMLStreamException e)
        {
            System.err.println("Error processing XML: " + e.getMessage());
        }
        return null;
    }

    private static void assertException(Attribute attribute, String name, String value, String errorMessage)
        throws KMIPInputException
    {
        if (!attribute.getName().getLocalPart().equals(name) || !attribute.getValue().equals(value))
        {
            //parse error
            throw new KMIPInputException(errorMessage);
        }
    }

    private static void assertException(boolean condition, String errorMessage)
        throws KMIPInputException
    {
        if (condition)
        {
            throw new KMIPInputException(errorMessage);
        }
    }

    private StartElement assertStartElement(String name)
        throws KMIPInputException, XMLStreamException
    {
        while (eventReader.hasNext())
        {
            XMLEvent event = eventReader.nextEvent();
            if (event.isStartElement())
            {
                StartElement startElement = event.asStartElement();
                if (!startElement.getName().getLocalPart().equals(name))
                {
                    throw new KMIPInputException("Error in parsing" + name + ": Expected " + name + ", but got" + startElement.getName());
                }
                return startElement;
            }
        }
        throw new KMIPInputException("Error in parsing" + name + ": Expected Start Element for " + name);
    }

    private EndElement assertEndElement(XMLEvent event, String name, String errorMessage)
        throws KMIPInputException, XMLStreamException
    {
        do
        {
            if (event.isEndElement())
            {
                EndElement endElement = event.asEndElement();
                if (!endElement.getName().getLocalPart().equals(name))
                {
                    throw new KMIPInputException(errorMessage + "Expected " + name + "but got" + endElement.getName());
                }
                return endElement;
            }
            event = eventReader.nextEvent();
        }
        while (eventReader.hasNext());
        throw new KMIPInputException(errorMessage + "Expected End Element for " + name);
    }

    private int parseInteger(StartElement startElement, String className)
        throws KMIPInputException, XMLStreamException
    {
        int value;
        if (startElement.getAttributes() != null)
        {
            Iterator it = startElement.getAttributes();
            Attribute attribute = (Attribute)it.next();
            assertException(attribute, "type", "Integer", "Error in parsing " + className + ": type should be integer");
            attribute = (Attribute)it.next();
            value = Integer.parseInt(attribute.getValue());
            assertException(it.hasNext(), "Error in parsing " + className + ": There should be 2 attributes");
            assertEndElement(eventReader.nextEvent(), className, "Error in parsing " + className + ": ");
        }
        else
        {
            throw new KMIPInputException("Error in parsing " + className + ": there should be 2 attributes");
        }

        return value;
    }

    private String parseTextString(StartElement startElement, String className)
        throws KMIPInputException, XMLStreamException
    {
        String value;
        if (startElement.getAttributes() != null)
        {
            Iterator it = startElement.getAttributes();
            Attribute attribute = (Attribute)it.next();
            assertException(attribute, "type", "TextString", "Error in parsing " + className + ": type should be text string");
            attribute = (Attribute)it.next();
            value = attribute.getValue();
            assertException(it.hasNext(), "Error in parsing " + className + ": There should be 2 attributes");
            assertEndElement(eventReader.nextEvent(), className, "Error in parsing " + className + ": ");
        }
        else
        {
            throw new KMIPInputException("Error in parsing " + className + ": there should be 2 attributes");
        }
        return value;
    }

    private byte[] parseByteString(StartElement startElement, String errorMessage)
        throws KMIPInputException
    {
        String value;
        if (startElement.getAttributes() != null)
        {
            Iterator it = startElement.getAttributes();
            Attribute attribute = (Attribute)it.next();
            assertException(attribute, "type", "ByteString", errorMessage + " type should be text string");
            attribute = (Attribute)it.next();
            value = attribute.getValue();
            assertException(it.hasNext(), errorMessage + "There should be 2 attributes");
        }
        else
        {
            throw new KMIPInputException(errorMessage + " there should be 2 attributes");
        }
        return Hex.decode(value);
    }

    private KMIPUniqueIdentifier parseUniqueIdentifier(StartElement startElement, String errorMessage)
        throws KMIPInputException, XMLStreamException
    {
        //TODO: parse integer, enumeration
        String value;
        if (startElement.getAttributes() != null)
        {
            Iterator it = startElement.getAttributes();
            Attribute attribute = (Attribute)it.next();
            assertException(attribute, "type", "TextString", errorMessage + " type should be text string");
            attribute = (Attribute)it.next();
            value = attribute.getValue();
            assertException(it.hasNext(), errorMessage + "There should be 2 attributes");
        }
        else
        {
            throw new KMIPInputException(errorMessage + " there should be 2 attributes");
        }
        assertEndElement(eventReader.nextEvent(), "UniqueIdentifier", errorMessage);
        return new KMIPUniqueIdentifier(value);
    }

    private Date parseDateTime(StartElement startElement, String errorMessage)
        throws KMIPInputException
    {
        String value;
        if (startElement.getAttributes() != null)
        {
            Iterator it = startElement.getAttributes();
            Attribute attribute = (Attribute)it.next();
            assertException(attribute, "type", "DateTime", errorMessage + " type should be DateTime");
            attribute = (Attribute)it.next();
            value = attribute.getValue();
            assertException(it.hasNext(), errorMessage + "There should be 2 attributes");
        }
        else
        {
            throw new KMIPInputException(errorMessage + " there should be 2 attributes");
        }
        if (value.equals("$NOW"))
        {
            return new Date();
        }
        return new Date(value);
    }

    public <T extends Enum<T> & KMIPEnumeration> T parseEnum(StartElement startElement, Class<T> enumClass, String className)
        throws KMIPInputException, XMLStreamException
    {
        String value;
        if (startElement.getAttributes() != null)
        {
            Iterator it = startElement.getAttributes();
            Attribute attribute = (Attribute)it.next();
            assertException(attribute, "type", "Enumeration", "Error in parsing " + className + ": type should be enumeration");
            attribute = (Attribute)it.next();
            value = attribute.getValue();
            assertException(it.hasNext(), "Error in parsing " + className + ":There should be 2 attributes");
            assertEndElement(eventReader.nextEvent(), className, "Error in parsing " + className + ": ");
        }
        else
        {
            throw new KMIPInputException("Error in parsing " + className + ": there should be 2 attributes");
        }
        // Convert value string to corresponding enum constant
        try
        {
            return Enum.valueOf(enumClass, value.replace("-", "_"));
        }
        catch (IllegalArgumentException e)
        {
            throw new KMIPInputException("Error in parsing " + className + ": Invalid value for enum: " + value);
        }
    }

    private static <T extends Enum<T> & KMIPEnumeration> int parseInteger(StartElement startElement, Class<T> enumClass, String errorMessage)
        throws KMIPInputException
    {
        int result = 0;
        if (startElement.getAttributes() != null)
        {
            Iterator it = startElement.getAttributes();
            Attribute attribute = (Attribute)it.next();
            assertException(attribute, "type", "Integer", errorMessage + " type should be Integer");
            attribute = (Attribute)it.next();
            String[] values = attribute.getValue().split(" ");
            try
            {
                for (String value : values)
                {
                    T enumConstant = Enum.valueOf(enumClass, value.replace("-", "_"));
                    result |= enumConstant.getValue();
                }
            }
            catch (IllegalArgumentException e)
            {
                throw new KMIPInputException(errorMessage + " Invalid value for enum: " + attribute.getValue());
            }
            assertException(it.hasNext(), errorMessage + "There should be 2 attributes");
        }
        else
        {
            throw new KMIPInputException(errorMessage + " there should be 2 attributes");
        }
        return result;
    }

    public KMIPProtocolVersion parseProtocolVersion()
        throws KMIPInputException
    {
        int marjorVersion, minorVersion;
        try
        {
            XMLEvent event = eventReader.nextEvent();
            StartElement startElement = assertStartElement("ProtocolVersionMajor");
            marjorVersion = parseInteger(startElement, "ProtocolVersionMajor");

            startElement = assertStartElement("ProtocolVersionMinor");
            minorVersion = parseInteger(startElement, "ProtocolVersionMinor");

            assertEndElement(event, "ProtocolVersion", "Error in processing Protocol Version: ");
            return new KMIPProtocolVersion(marjorVersion, minorVersion);
        }
        catch (XMLStreamException e)
        {
            System.err.println("Error processing XML: " + e.getMessage());
        }
        return null;
    }
}
