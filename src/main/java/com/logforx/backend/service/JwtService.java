package com.logforx.backend.service;

import org.springframework.stereotype.Service;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

@Service
public class JwtService {

    private static final String SECRET = "cybersecurity-platform-super-secret-key-2026-wow-fest";
    
    public String generateToken(String email, String name, String badgeId) {
        try {
            String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
            long exp = System.currentTimeMillis() + 86400000; // 1 day expiration
            String payload = String.format(
                "{\"sub\":\"%s\",\"name\":\"%s\",\"badgeId\":\"%s\",\"role\":\"Investigator\",\"exp\":%d}",
                email, name, badgeId, exp
            );
            
            String encodedHeader = base64UrlEncode(header.getBytes(StandardCharsets.UTF_8));
            String encodedPayload = base64UrlEncode(payload.getBytes(StandardCharsets.UTF_8));
            
            String signatureInput = encodedHeader + "." + encodedPayload;
            String signature = calculateHmacSha256(signatureInput, SECRET);
            
            return signatureInput + "." + signature;
        } catch (Exception e) {
            throw new RuntimeException("Error generating token", e);
        }
    }
    
    public boolean validateToken(String token) {
        if (token == null || !token.contains(".")) return false;
        String[] parts = token.split("\\.");
        if (parts.length != 3) return false;
        
        try {
            String signatureInput = parts[0] + "." + parts[1];
            String expectedSignature = calculateHmacSha256(signatureInput, SECRET);
            
            // Check expiration
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            if (payload.contains("\"exp\":")) {
                int expIndex = payload.indexOf("\"exp\":") + 6;
                int endIndex = payload.indexOf("}", expIndex);
                if (endIndex == -1) endIndex = payload.indexOf(",", expIndex);
                if (endIndex != -1) {
                    String expStr = payload.substring(expIndex, endIndex).trim();
                    long expTime = Long.parseLong(expStr);
                    if (System.currentTimeMillis() > expTime) {
                        return false;
                    }
                }
            }
            
            return expectedSignature.equals(parts[2]);
        } catch (Exception e) {
            return false;
        }
    }

    private String base64UrlEncode(byte[] input) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(input);
    }
    
    private String calculateHmacSha256(String data, String secret) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] hash = secret.getBytes(StandardCharsets.UTF_8);
        Mac sha256 = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(hash, "HmacSHA256");
        sha256.init(secretKey);
        byte[] signedBytes = sha256.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return base64UrlEncode(signedBytes);
    }
}
