package wrappedkey.service;

import org.bouncycastle.asn1.*;
import org.springframework.stereotype.Service;
import sun.security.provider.X509Factory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import java.util.Base64;

@Service
public class WrappedKeyService {

    /**
     * Constants copied from Android FW internals /frameworks/base/core/java/android/security/keymaster/KeymasterDefs.java
     */

    // Key formats
    public static final int KM_KEY_FORMAT_X509 = 0;
    public static final int KM_KEY_FORMAT_PKCS8 = 1;
    public static final int KM_KEY_FORMAT_RAW = 3;

    // Operation Purposes.
    public static final int KM_PURPOSE_ENCRYPT = 0;
    public static final int KM_PURPOSE_DECRYPT = 1;
    public static final int KM_PURPOSE_SIGN = 2;
    public static final int KM_PURPOSE_VERIFY = 3;
    public static final int KM_PURPOSE_WRAP = 5;

    // Algorithm values.
    public static final int KM_ALGORITHM_RSA = 1;
    public static final int KM_ALGORITHM_EC = 3;
    public static final int KM_ALGORITHM_AES = 32;
    public static final int KM_ALGORITHM_3DES = 33;
    public static final int KM_ALGORITHM_HMAC = 128;

    public static final int KM_INVALID = 0 << 28;
    public static final int KM_ENUM = 1 << 28;
    public static final int KM_ENUM_REP = 2 << 28;
    public static final int KM_UINT = 3 << 28;
    public static final int KM_UINT_REP = 4 << 28;
    public static final int KM_ULONG = 5 << 28;
    public static final int KM_DATE = 6 << 28;
    public static final int KM_BOOL = 7 << 28;
    public static final int KM_BIGNUM = 8 << 28;
    public static final int KM_BYTES = 9 << 28;
    public static final int KM_ULONG_REP = 10 << 28;

    // Block modes.
    public static final int KM_MODE_ECB = 1;
    public static final int KM_MODE_CBC = 2;
    public static final int KM_MODE_CTR = 3;
    public static final int KM_MODE_GCM = 32;

    // Padding modes.
    public static final int KM_PAD_NONE = 1;
    public static final int KM_PAD_RSA_OAEP = 2;
    public static final int KM_PAD_RSA_PSS = 3;
    public static final int KM_PAD_RSA_PKCS1_1_5_ENCRYPT = 4;
    public static final int KM_PAD_RSA_PKCS1_1_5_SIGN = 5;
    public static final int KM_PAD_PKCS7 = 64;

    /********************************************************************************************************************/

    private static final int AES_KEY_SIZE_IN_BYTES = 32;
    private static final int AES_KEY_SIZE_IN_BITS = AES_KEY_SIZE_IN_BYTES*8;
    private static final int WRAPPED_FORMAT_VERSION = 0;
    private static final int IV_SIZE = 12;
    private static final int AES_GCM_TAG_SIZE_IN_BYTES = 16;
    private static final int AES_GCM_TAG_SIZE_IN_BITS = AES_GCM_TAG_SIZE_IN_BYTES * 8;

    public static final int TAG_PURPOSE = 1;
    public static final int TAG_ALGORITHM = 2;
    public static final int TAG_KEY_SIZE = 3;
    public static final int TAG_BLOCK_MODE = 4;
    public static final int TAG_PADDINGS = 6;
    public static final int TAG_NO_AUTH = 503;

    private SecureRandom secureRandom;

    public WrappedKeyService() {
        secureRandom = new SecureRandom();
    }

    /**
     *
     * @param pemCertificate the public key of the certificate will be used to wrap the key
     * @return the WrappedKey in b64 format
     */
    public String generateB64WrappedKey(String pemCertificate) throws CertificateException {
        if (pemCertificate == null) {
            return "";
        }

        byte[] keyMaterial = new byte[AES_KEY_SIZE_IN_BYTES];
        secureRandom.nextBytes(keyMaterial);
        X509Certificate x509Certificate = generateX509CertFromPem(pemCertificate);
        byte[] wrappedKeyBYtes = generateAESWrappedKey(x509Certificate.getPublicKey(), keyMaterial);
        return Base64.getEncoder().encodeToString(wrappedKeyBYtes);
    }

    private X509Certificate generateX509CertFromPem(String pemCert) throws CertificateException {
        byte [] decoded = Base64.getDecoder().decode(
                pemCert.replaceAll(X509Factory.BEGIN_CERT, "")
                .replaceAll(X509Factory.END_CERT, "")
                .replaceAll("\n", ""));
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(decoded));
    }

    /**
     *
     * WrappedKey ASN1 format
     *
     *      KeyDescription ::= SEQUENCE(
     *          keyFormat INTEGER,                   # Values from KeyFormat enum.
     *          keyParams AuthorizationList,
     *      )
     *
     *      SecureKeyWrapper ::= SEQUENCE(
     *          version INTEGER,                     # Contains value 0
     *          encryptedTransportKey OCTET_STRING,
     *          initializationVector OCTET_STRING,
     *          keyDescription KeyDescription,
     *          encryptedKey OCTET_STRING,
     *          tag OCTET_STRING
     *      )
     *
     *     AuthorizationList ::= SEQUENCE {
     *          purpose  [1] EXPLICIT SET OF INTEGER OPTIONAL,
     *          algorithm  [2] EXPLICIT INTEGER OPTIONAL,
     *          keySize  [3] EXPLICIT INTEGER OPTIONAL,
     *          digest  [5] EXPLICIT SET OF INTEGER OPTIONAL,
     *          padding  [6] EXPLICIT SET OF INTEGER OPTIONAL,
     *          ecCurve  [10] EXPLICIT INTEGER OPTIONAL,
     *          rsaPublicExponent  [200] EXPLICIT INTEGER OPTIONAL,
     *          rollbackResistance  [303] EXPLICIT NULL OPTIONAL,
     *          activeDateTime  [400] EXPLICIT INTEGER OPTIONAL,
     *          originationExpireDateTime  [401] EXPLICIT INTEGER OPTIONAL,
     *          usageExpireDateTime  [402] EXPLICIT INTEGER OPTIONAL,
     *          noAuthRequired  [503] EXPLICIT NULL OPTIONAL,
     *          userAuthType  [504] EXPLICIT INTEGER OPTIONAL,
     *          authTimeout  [505] EXPLICIT INTEGER OPTIONAL,
     *          allowWhileOnBody  [506] EXPLICIT NULL OPTIONAL,
     *          trustedUserPresenceRequired  [507] EXPLICIT NULL OPTIONAL,
     *          trustedConfirmationRequired  [508] EXPLICIT NULL OPTIONAL,
     *          unlockedDeviceRequired  [509] EXPLICIT NULL OPTIONAL,
     *          allApplications  [600] EXPLICIT NULL OPTIONAL,
     *          applicationId  [601] EXPLICIT OCTET_STRING OPTIONAL,
     *          creationDateTime  [701] EXPLICIT INTEGER OPTIONAL,
     *          origin  [702] EXPLICIT INTEGER OPTIONAL,
     *          rootOfTrust  [704] EXPLICIT RootOfTrust OPTIONAL,
     *          osVersion  [705] EXPLICIT INTEGER OPTIONAL,
     *          osPatchLevel  [706] EXPLICIT INTEGER OPTIONAL,
     *          attestationApplicationId  [709] EXPLICIT OCTET_STRING OPTIONAL,
     *          attestationIdBrand  [710] EXPLICIT OCTET_STRING OPTIONAL,
     *          attestationIdDevice  [711] EXPLICIT OCTET_STRING OPTIONAL,
     *          attestationIdProduct  [712] EXPLICIT OCTET_STRING OPTIONAL,
     *          attestationIdSerial  [713] EXPLICIT OCTET_STRING OPTIONAL,
     *          attestationIdImei  [714] EXPLICIT OCTET_STRING OPTIONAL,
     *          attestationIdMeid  [715] EXPLICIT OCTET_STRING OPTIONAL,
     *          attestationIdManufacturer  [716] EXPLICIT OCTET_STRING OPTIONAL,
     *          attestationIdModel  [717] EXPLICIT OCTET_STRING OPTIONAL,
     *          vendorPatchLevel  [718] EXPLICIT INTEGER OPTIONAL,
     *          bootPatchLevel  [719] EXPLICIT INTEGER OPTIONAL,
     *      }
     */
    public byte[] generateAESWrappedKey(PublicKey publicKey, byte[] key) {

        try {
            ASN1EncodableVector keyDescriptionVector = new ASN1EncodableVector();
            keyDescriptionVector.add(new ASN1Integer(KM_KEY_FORMAT_RAW));
            keyDescriptionVector.add(generateAESAuthorizationList(AES_KEY_SIZE_IN_BITS));
            DERSequence keyDescriptionSequence = new DERSequence(keyDescriptionVector);

            ASN1EncodableVector secureKeyWrapperVector = new ASN1EncodableVector();

            byte[] iv = generateIV();
            // key encryption key, used to encrypt the key that is being wrapped
            byte[] transportKey = generateAESKey();
            byte[] encTransportKey = encryptTransportKey(transportKey, publicKey);

            byte[] encKeyAndTag = encryptKey(transportKey, key, iv, keyDescriptionSequence.getEncoded());
            byte[] encKey = getEncryptedTransportKey(encKeyAndTag);
            byte[] tag = getTag(encKeyAndTag);
            secureKeyWrapperVector.add(new ASN1Integer(WRAPPED_FORMAT_VERSION));
            secureKeyWrapperVector.add(new DEROctetString(encTransportKey));
            secureKeyWrapperVector.add(new DEROctetString(iv));
            secureKeyWrapperVector.add(keyDescriptionSequence);
            secureKeyWrapperVector.add(new DEROctetString(encKey));
            secureKeyWrapperVector.add(new DEROctetString(tag));

            DERSequence secureKeyWrapper = new DERSequence(secureKeyWrapperVector);
            return secureKeyWrapper.getEncoded(ASN1Encoding.DER);

        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private DERSequence generateAESAuthorizationList(int aesKeySizeInBits) {
        ASN1EncodableVector asn1EncodableVector = new ASN1EncodableVector();
        ASN1EncodableVector purposeVector = new ASN1EncodableVector();
        purposeVector.add(new ASN1Integer(KM_PURPOSE_DECRYPT));
        purposeVector.add(new ASN1Integer(KM_PURPOSE_ENCRYPT));
        DERTaggedObject purposeTagged = new DERTaggedObject(true, TAG_PURPOSE, new DERSet(purposeVector));
        asn1EncodableVector.add(purposeTagged);
        DERTaggedObject algorithmTagged = new DERTaggedObject(true, TAG_ALGORITHM, new ASN1Integer(KM_ALGORITHM_AES));
        asn1EncodableVector.add(algorithmTagged);
        DERTaggedObject keySizeTagged = new DERTaggedObject(true, TAG_KEY_SIZE, new ASN1Integer(aesKeySizeInBits));
        asn1EncodableVector.add(keySizeTagged);

        ASN1EncodableVector blockModesVector = new ASN1EncodableVector();
        blockModesVector.add(new ASN1Integer(KM_MODE_ECB));
        blockModesVector.add(new ASN1Integer(KM_MODE_CBC));
        DERSet blockModeSet = new DERSet(blockModesVector);
        DERTaggedObject blockModeTagged = new DERTaggedObject(true, TAG_BLOCK_MODE, blockModeSet);
        asn1EncodableVector.add(blockModeTagged);

        ASN1EncodableVector allPaddingsVector = new ASN1EncodableVector();
        allPaddingsVector.add(new ASN1Integer(KM_PAD_PKCS7));
        allPaddingsVector.add(new ASN1Integer(KM_PAD_NONE));
        DERSet paddingSet = new DERSet(allPaddingsVector);
        DERTaggedObject paddingTagged = new DERTaggedObject(true, TAG_PADDINGS, paddingSet);
        asn1EncodableVector.add(paddingTagged);

        DERTaggedObject noAuthRequiredTagged = new DERTaggedObject(true, TAG_NO_AUTH, DERNull.INSTANCE);
        asn1EncodableVector.add(noAuthRequiredTagged);
        return new DERSequence(asn1EncodableVector);
    }

    private byte[] encryptTransportKey(byte[] transportKey, PublicKey devicePublicKey) {
        try {
            OAEPParameterSpec spec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
            Cipher pkCipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
            pkCipher.init(Cipher.ENCRYPT_MODE, devicePublicKey, spec);
            return pkCipher.doFinal(transportKey);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }

    private byte[] encryptKey(byte[] transportKey, byte[] secretKey, byte[] iv, byte[] aad) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(transportKey, "AES");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(AES_GCM_TAG_SIZE_IN_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
            cipher.updateAAD(aad);
            return cipher.doFinal(secretKey);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }

    private byte[] generateIV() {
        byte[] iv = new byte[IV_SIZE];
        secureRandom.nextBytes(iv);
        return iv;
    }

    private byte[] generateAESKey() {
        byte[] key = new byte[AES_KEY_SIZE_IN_BYTES];
        secureRandom.nextBytes(key);
        return key;
    }

    private byte[] getTag(byte[] aesGcmOutput) {
        return Arrays.copyOfRange(aesGcmOutput, aesGcmOutput.length - AES_GCM_TAG_SIZE_IN_BYTES, aesGcmOutput.length);
    }

    private byte[] getEncryptedTransportKey(byte[] aesGcmOutput) {
        return Arrays.copyOfRange(aesGcmOutput, 0, aesGcmOutput.length - AES_GCM_TAG_SIZE_IN_BYTES);
    }

}
