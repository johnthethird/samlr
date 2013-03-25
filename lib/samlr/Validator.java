import javax.xml.crypto.*;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dom.*;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.*;
import java.io.FileInputStream;
import java.security.*;
import java.security.cert.*;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import java.io.StringReader;
import java.io.File;
import java.util.Scanner;
/**
 * Validating an XML Signature using the JSR 105 API. It assumes the key needed to
 * validate the signature is contained in a KeyInfo node.
 */
public class Validator {

    //
    // Synopsis: java Validator [document]
    //
    //    where "document" is the name of a file containing the XML document
    //    to be validated.
    //
    public static void main(String[] args) throws Exception {
        String samlResponse = new String(readFile(args[0]));
        System.out.println("Valid?: " + validate(samlResponse));
    }

    // Validator.validate(saml_response) returns boolean indicating if the doc has been validated
    public static boolean validate(String samlResponse) {
        boolean coreValidity = false;
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            Document doc = dbf.newDocumentBuilder().parse(new InputSource(new StringReader(samlResponse)));

            // Find Signature element
            NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
            if (nl.getLength() == 0) {
                throw new Exception("Cannot find Signature element");
            }

            // Create a DOM XMLSignatureFactory that will be used to unmarshal the
            // document containing the XMLSignature
            XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

            // Create a DOMValidateContext and specify a KeyValue KeySelector
            // and document context
            DOMValidateContext valContext = new DOMValidateContext(new RawX509KeySelector(), nl.item(0));

            XMLSignature signature = fac.unmarshalXMLSignature(valContext);

            // Validate the XMLSignature (generated above)
            coreValidity = signature.validate(valContext);
        } catch (Exception ex) {
            System.out.println("[SAML Validator] Exception:" + ex.getMessage());
            coreValidity = false;
        }
        // // Check core validation status
        // if (coreValidity == false) {
        //     System.err.println("Signature failed core validation");
        //     boolean sv = signature.getSignatureValue().validate(valContext);
        //     System.out.println("signature validation status: " + sv);
        //     // check the validation status of each Reference
        //     Iterator i = signature.getSignedInfo().getReferences().iterator();
        //     for (int j=0; i.hasNext(); j++) {
        //         boolean refValid =
        //             ((Reference) i.next()).validate(valContext);
        //         System.out.println("ref["+j+"] validity status: " + refValid);
        //     }
        // } else {
        //     System.out.println("Signature passed core validation");
        // }
        return coreValidity;
    }



    /**
     * KeySelector which would retrieve the X509Certificate out of the
     * KeyInfo element and return the public key.
     * NOTE: If there is an X509CRL in the KeyInfo element, then revoked
     * certificate will be ignored.
     */
    public static class RawX509KeySelector extends KeySelector {

        public KeySelectorResult select(KeyInfo keyInfo,
                                        KeySelector.Purpose purpose,
                                        AlgorithmMethod method,
                                        XMLCryptoContext context)
            throws KeySelectorException {
            if (keyInfo == null) {
                throw new KeySelectorException("Null KeyInfo object!");
            }
            // search for X509Data in keyinfo
            Iterator<?> iter = keyInfo.getContent().iterator();
            while (iter.hasNext()) {
                XMLStructure kiType = (XMLStructure) iter.next();
                if (kiType instanceof X509Data) {
                    X509Data xd = (X509Data) kiType;
                    Object[] entries = xd.getContent().toArray();
                    X509CRL crl = null;
                    // Looking for CRL before finding certificates
                    for (int i = 0; (i < entries.length && crl == null); i++) {
                        if (entries[i] instanceof X509CRL) {
                            crl = (X509CRL) entries[i];
                        }
                    }
                    Iterator<?> xi = xd.getContent().iterator();
                    while (xi.hasNext()) {
                        Object o = xi.next();
                        // skip non-X509Certificate entries
                        if (o instanceof X509Certificate) {
                            if ((purpose != KeySelector.Purpose.VERIFY) &&
                                (crl != null) &&
                                crl.isRevoked((X509Certificate)o)) {
                                continue;
                            } else {
                                return new SimpleKeySelectorResult
                                    (((X509Certificate)o).getPublicKey());
                            }
                        }
                    }
                }
            }
            throw new KeySelectorException("No X509Certificate found!");
        }
    }


    private static class SimpleKeySelectorResult implements KeySelectorResult {
        private PublicKey pk;
        SimpleKeySelectorResult(PublicKey pk) {
            this.pk = pk;
        }

        public Key getKey() { return pk; }
    }

    private static String readFile(String pathname) throws Exception {
        File file = new File(pathname);
        StringBuilder fileContents = new StringBuilder((int)file.length());
        Scanner scanner = new Scanner(file);
        String lineSeparator = System.getProperty("line.separator");

        try {
            while(scanner.hasNextLine()) {
                fileContents.append(scanner.nextLine() + lineSeparator);
            }
            return fileContents.toString();
        } finally {
            scanner.close();
        }
    }


}