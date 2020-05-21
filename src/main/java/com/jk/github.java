package com.jk;//package com.jk.sm2;
//
//import java.security.*;
//import java.security.spec.ECGenParameterSpec;
//import java.security.spec.PKCS8EncodedKeySpec;
//import java.security.spec.X509EncodedKeySpec;
//
///**
// * @Description :
// * @Author : liuxiao
// * @Date: 2020-05-21 17:15
// */
//public class github {
//    public void testSM2()
//            throws Exception
//    {
//        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");
//
//        kpGen.initialize(new ECGenParameterSpec("sm2p256v1"));
//
//        KeyPair kp = kpGen.generateKeyPair();
//
//        doBasicTest("EC", kpGen.generateKeyPair());
//
//        byte[] encPub = Base64.decode("MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAELAtcshndZO6GOXfZxKR6TEu+eyRa4G2gH3iN0YPInldPfyGR18/FI/jHhObqZ1o3mh/c/wAJnNfqC6xnJ8kfYQ==");
//        byte[] encPriv = Base64.decode("MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgyv+YdWo5OtAv7E0znvq978yw2KdGKE4TsWw+yHqNtVKgCgYIKoEcz1UBgi2hRANCAAQsC1yyGd1k7oY5d9nEpHpMS757JFrgbaAfeI3Rg8ieV09/IZHXz8Uj+MeE5upnWjeaH9z/AAmc1+oLrGcnyR9h");
//
//        KeyFactory keyFact = KeyFactory.getInstance("EC", "BC");
//
//        PublicKey pub = keyFact.generatePublic(new X509EncodedKeySpec(encPub));
//        PrivateKey priv = keyFact.generatePrivate(new PKCS8EncodedKeySpec(encPriv));
//
//        assertTrue(pub.toString().startsWith("EC Public Key [38:20:5a:95:6f:1d:6f:10:74:42:a0:a7:ee:d4:b8:83:6d:32:2f:e6]"));
//        assertTrue(pub.toString().contains("    X: 2c0b5cb219dd64ee863977d9c4a47a4c4bbe7b245ae06da01f788dd183c89e57"));
//        assertTrue(pub.toString().contains("    Y: 4f7f2191d7cfc523f8c784e6ea675a379a1fdcff00099cd7ea0bac6727c91f61"));
//        assertTrue(priv.toString().startsWith("EC Private Key [38:20:5a:95:6f:1d:6f:10:74:42:a0:a7:ee:d4:b8:83:6d:32:2f:e6]"));
//        assertTrue(priv.toString().contains("    X: 2c0b5cb219dd64ee863977d9c4a47a4c4bbe7b245ae06da01f788dd183c89e57"));
//        assertTrue(priv.toString().contains("    Y: 4f7f2191d7cfc523f8c784e6ea675a379a1fdcff00099cd7ea0bac6727c91f61"));
//    }
//}
