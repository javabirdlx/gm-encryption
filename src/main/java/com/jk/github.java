//package com.jk;//package com.jk.sm2;
////
////import java.security.*;
////import java.security.spec.ECGenParameterSpec;
////import java.security.spec.PKCS8EncodedKeySpec;
////import java.security.spec.X509EncodedKeySpec;
////
/////**
//// * @Description :
//// * @Author : liuxiao
//// * @Date: 2020-05-21 17:15
//// */
////public class github {
////    public void testSM2()
////            throws Exception
////    {
////        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");
////
////        kpGen.initialize(new ECGenParameterSpec("sm2p256v1"));
////
////        KeyPair kp = kpGen.generateKeyPair();
////
////        doBasicTest("EC", kpGen.generateKeyPair());
////
////        byte[] encPub = Base64.decode("MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAELAtcshndZO6GOXfZxKR6TEu+eyRa4G2gH3iN0YPInldPfyGR18/FI/jHhObqZ1o3mh/c/wAJnNfqC6xnJ8kfYQ==");
////        byte[] encPriv = Base64.decode("MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgyv+YdWo5OtAv7E0znvq978yw2KdGKE4TsWw+yHqNtVKgCgYIKoEcz1UBgi2hRANCAAQsC1yyGd1k7oY5d9nEpHpMS757JFrgbaAfeI3Rg8ieV09/IZHXz8Uj+MeE5upnWjeaH9z/AAmc1+oLrGcnyR9h");
////
////        KeyFactory keyFact = KeyFactory.getInstance("EC", "BC");
////
////        PublicKey pub = keyFact.generatePublic(new X509EncodedKeySpec(encPub));
////        PrivateKey priv = keyFact.generatePrivate(new PKCS8EncodedKeySpec(encPriv));
////
////        assertTrue(pub.toString().startsWith("EC Public Key [38:20:5a:95:6f:1d:6f:10:74:42:a0:a7:ee:d4:b8:83:6d:32:2f:e6]"));
////        assertTrue(pub.toString().contains("    X: 2c0b5cb219dd64ee863977d9c4a47a4c4bbe7b245ae06da01f788dd183c89e57"));
////        assertTrue(pub.toString().contains("    Y: 4f7f2191d7cfc523f8c784e6ea675a379a1fdcff00099cd7ea0bac6727c91f61"));
////        assertTrue(priv.toString().startsWith("EC Private Key [38:20:5a:95:6f:1d:6f:10:74:42:a0:a7:ee:d4:b8:83:6d:32:2f:e6]"));
////        assertTrue(priv.toString().contains("    X: 2c0b5cb219dd64ee863977d9c4a47a4c4bbe7b245ae06da01f788dd183c89e57"));
////        assertTrue(priv.toString().contains("    Y: 4f7f2191d7cfc523f8c784e6ea675a379a1fdcff00099cd7ea0bac6727c91f61"));
////    }
////}
//
//
///**
// *
// */
//package com.doubleca.sample.pki.jce;
//
//import java.io.File;
//import java.io.FileInputStream;
//import java.io.FileOutputStream;
//import java.math.BigInteger;
//import java.security.InvalidKeyException;
//import java.security.Key;
//import java.security.KeyFactory;
//import java.security.KeyPair;
//import java.security.KeyPairGenerator;
//import java.security.KeyStore;
//import java.security.KeyStore.Entry;
//import java.security.MessageDigest;
//import java.security.NoSuchAlgorithmException;
//import java.security.PrivateKey;
//import java.security.PublicKey;
//import java.security.SecureRandom;
//import java.security.Security;
//import java.security.SignatureException;
//import java.security.cert.Certificate;
//import java.security.cert.CertificateFactory;
//import java.security.cert.X509Certificate;
//import java.security.spec.InvalidKeySpecException;
//import java.security.spec.PKCS8EncodedKeySpec;
//import java.security.spec.X509EncodedKeySpec;
//import java.util.Enumeration;
//
//import javax.crypto.Cipher;
//import javax.crypto.KeyGenerator;
//import javax.crypto.SecretKey;
//import javax.crypto.SecretKeyFactory;
//import javax.crypto.spec.IvParameterSpec;
//import javax.crypto.spec.SecretKeySpec;
//
//import com.doubleca.b146.c16.util.encoders.Base64;
//
//import doubleca.security.provider.DoubleCA;
//import doubleca.security.provider.jdk7.sm4.SM4KeySpec;
//
///**
// * @author
// *
// */
//public class Test
//{
//    private static final String SIGNATURE_KEY_ALGORITHM = "SM2";
//    private static final String SIGNATURE_ALGORITHM = "SM3withSM2";
//    private static final int SIGNATURE_KEY_SIZE = 256;
//    private static final String DIGEST_ALGORITHM = "SM3";
//    private static final String CIPHER_KEY_ALGORITHM = "SM4";
//    //	private static final String CIPHER_ALGORITHM = "SM4/ECB/PKCS5Padding";
//    private static final String CIPHER_ALGORITHM = "SM4/CBC/PKCS5Padding";
//    // private static final String CIPHER_ALGORITHM = "SM4/ECB/NOPadding";
//    // private static final String CIPHER_ALGORITHM = "SM4/CBC/NOPadding";
//
//    /**
//     * @param args
//     */
//    public static void main(String[] args)
//    {
//        // TODO Auto-generated method stub
//        /**
//         * 说明：JDK7版本及以上，JDK需要使用无限制的策略文件 UnlimitedJCEPolicy
//         * 否则，SM2密钥长度为256位，JCE无法调用成功
//         */
//        try
//        {
//            Security.addProvider(new DoubleCA());
//            System.out.println("");
//            System.out.println("TestSM2KeyPairGenerator");
//            KeyPair key = TestSM2KeyPairGenerator();
//            System.out.println("");
//            System.out.println("TestSM2KeyFactory");
//            TestSM2KeyFactory(key.getPublic().getEncoded(), key.getPrivate().getEncoded());
//            System.out.println("");
////			System.out.println("TestSM3Digest");
////			TestSM3Digest();
//            System.out.println("");
////			System.out.println("TestSM4Cipher");
////			SecretKey sm4key = TestSM4Cipher();
//            System.out.println("");
//            System.out.println("TestSM2AsymmetricCipher");
//            TestSM2AsymmetricCipher(key);
//            System.out.println("");
//            System.out.println("TestSM2Signature");
//            TestSM2Signature(key);
//            System.out.println("");
//            System.out.println("TestReadDCKS");
//            TestReadDCKS("resources/1E7A9FA952485DBD8452B1B7BDBB8DF4.dcks", "DoubleCA");
//            System.out.println("");
////			System.out.println("TestCreateDCKS");
////			TestCreateDCKS("resources/SM2SigningCert.dcks", "111111", key, sm4key);
//            System.out.println("");
//            System.out.println("TestReadDCKS");
//            TestReadDCKS("resources/SM2SigningCert.dcks", "111111");
//            System.out.println("");
//            System.out.println(" finish.");
//        }
//        catch (Exception ex)
//        {
//            ex.printStackTrace();
//        }
//    }
//
//    public static void TestSM2Signature(KeyPair key) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException
//    {
//        String content = "偶像：握奇数据王幼君总裁！";
//        System.out.println("原文：" + content);
//        java.security.Signature signature = java.security.Signature.getInstance(SIGNATURE_ALGORITHM);
//        signature.initSign(key.getPrivate());
//        signature.update(content.getBytes());
//        byte[] signValue = signature.sign();
//        System.out.println("签名值：" + new String(Base64.encode(signValue)));
//        signature.initVerify(key.getPublic());
//        signature.update(content.getBytes());
//        boolean result = signature.verify(signValue);
//        System.out.println("签名验证结果 ：" + result);
//    }
//
//    public static void TestSM2AsymmetricCipher(KeyPair key)
//    {
//        try
//        {
//            Cipher cipher = Cipher.getInstance("SM2/ECB/NOPadding");
//            cipher.init(Cipher.ENCRYPT_MODE, key.getPublic());
//            String plainText = "偶像：握奇数据王幼君总裁！";
//            System.out.println("原文：" + plainText);
//            cipher.update(plainText.getBytes());
//            byte[] cipherByte = cipher.doFinal();
//            System.out.println("密文：" + new String(Base64.encode(cipherByte)));
//            cipher.init(Cipher.DECRYPT_MODE, key.getPrivate());
//            byte[] plainByte = cipher.doFinal(cipherByte);
//            System.out.println("原文：" + new String(plainByte));
//        }
//        catch (Exception ex)
//        {
//            ex.printStackTrace();
//        }
//    }
//
//    public static KeyPair TestSM2KeyPairGenerator() throws Exception
//    {
//        // 生成密钥对
//        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(SIGNATURE_KEY_ALGORITHM);
//        keyGen.initialize(SIGNATURE_KEY_SIZE);
//        KeyPair key = keyGen.generateKeyPair();
//        PublicKey publicKey = key.getPublic();
//        BigInteger a = new BigInteger(1, key.getPrivate().getEncoded());
//        BigInteger b = new BigInteger(1, publicKey.getEncoded());
//        System.out.println(keyGen.getAlgorithm() + " KeyPairGenerator publickey : " + b.toString(16));
//        System.out.println(keyGen.getAlgorithm() + " KeyPairGenerator privatekey : " + a.toString(16));
//        return key;
//    }
//
//    public static void TestSM2KeyFactory(byte[] publicKeyByteArray, byte[] privateKeyByteArray)
//    {
//        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKeyByteArray);
//        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyByteArray);
//        try
//        {
//            KeyFactory factory = KeyFactory.getInstance(SIGNATURE_KEY_ALGORITHM);
//            PublicKey publicKey = factory.generatePublic(x509EncodedKeySpec);
//            PrivateKey privateKey = factory.generatePrivate(pkcs8EncodedKeySpec);
//            BigInteger b = new BigInteger(1, publicKey.getEncoded());
//            BigInteger a = new BigInteger(1, privateKey.getEncoded());
//            System.out.println(factory.getAlgorithm() + " KeyFactory public key : " + b.toString(16));
//            System.out.println(factory.getAlgorithm() + " KeyFactory private key : " + a.toString(16));
//        }
//        catch (NoSuchAlgorithmException | InvalidKeySpecException e)
//        {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//        }
//    }
//
//    public static void TestReadDCKS(String fileName, String password)
//    {
//        KeyStore ks = null;
//        File keyStoreFile = new File(fileName);
//        if (keyStoreFile.exists())
//        {
//            try
//            {
//                ks = KeyStore.getInstance("DCKS");
//                FileInputStream fis = new FileInputStream(keyStoreFile);
//                ks.load(fis, password.toCharArray());
//                Enumeration e = ks.aliases();
//                while (e.hasMoreElements())
//                {
//                    String alias = (String) e.nextElement();
//                    System.out.println("alias : " + alias);
//                    if (ks.isKeyEntry(alias))
//                    {
//                        // key
//                        Key key = ks.getKey(alias, password.toCharArray());
//                        System.out.println("Key Type : " + key.getFormat());
//                        System.out.println("Key Algorithm : " + key.getAlgorithm());
//                        if (key instanceof PrivateKey)
//                        {
//                            System.out.println("PrivateKey Value : " + new BigInteger(1, key.getEncoded()));
//                            Certificate cert = ks.getCertificate(alias);
//                            System.out.println("Certificate Value : " + cert);
//                        }
//                        else if (key instanceof SecretKey)
//                        {
//                            System.out.println("Key Value : " + new BigInteger(1, key.getEncoded()));
//                        }
//                        else
//                        {
//                            System.out.println("unknown key type...");
//                        }
//                    }
//                    else if (ks.isCertificateEntry(alias))
//                    {
//                        // cert
//                        System.out.println("CertificateEntry : " + ks.getCertificate(alias));
//                    }
//                    else
//                    {
//                        // trusted cert
//                        System.out.println("TrustedEntry : " + ks.getCertificate(alias));
//                    }
//                }
//            }
//            catch (Exception ex)
//            {
//                ex.printStackTrace();
//            }
//        }
//    }
//    public static void TestCreateDCKS(String fileName, String password, KeyPair sm2Key, SecretKey sm4key)
//    {
//        KeyStore ks = null;
//        File keyStoreFile = new File(fileName);
//        try
//        {
//            ks = KeyStore.getInstance("DCKS");
//            ks.load(null, password.toCharArray());
//            FileOutputStream fos = new FileOutputStream(keyStoreFile);
//            KeyStore.PasswordProtection p = new KeyStore.PasswordProtection(password.toCharArray());
//
//            if (sm2Key != null)
//            {
//                CertificateFactory cf = CertificateFactory.getInstance("X.509", DoubleCA.PROVIDER_NAME);
//                X509Certificate cert = (X509Certificate) cf.generateCertificate(new FileInputStream("resources/sm2cert.cer"));
//                X509Certificate[] serverChain = new X509Certificate[] {cert};
//                ks.setEntry("DoubleCA-SM2", new KeyStore.PrivateKeyEntry(sm2Key.getPrivate(), serverChain), p);
//            }
//            if (sm4key != null)
//            {
//                Entry entry = new KeyStore.SecretKeyEntry(sm4key);
//                ks.setEntry("DoubleCA-SM4", entry, p);
//            }
//            ks.store(fos, password.toCharArray());
//            fos.close();
//        }
//        catch (Exception ex)
//        {
//            ex.printStackTrace();
//        }
//    }
//}
//
