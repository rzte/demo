package com.demo.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.MacProvider;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class JwtBuilder {
    private static final Key secret = MacProvider.generateKey();

    /**
     * 生成过期时间 15分钟
     * @return
     */
    public static Date generateExpirationDate(){
        return new Date(System.currentTimeMillis() + (15 * 60 * 1000));
    }

    public static String generateToken(Map<String, Object> claims){
        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(generateExpirationDate())
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();
    }

    public static Claims getClaimsFromToken(String token){
        Claims claims = Jwts.parser()
                .setSigningKey(secret)
                .parseClaimsJws(token)
                .getBody();
        return claims;
    }

    public static void main(String[] args){
        Map<String, Object> claims = new HashMap<>();
        claims.put("username", "tom");
        claims.put("level", 1);

        String token = generateToken(claims);

        System.out.println(token);
        //eyJhbGciOiJIUzUxMiJ9.eyJsZXZlbCI6MSwiZXhwIjoxNTI5NjkwMjcwLCJ1c2VybmFtZSI6InRvbSJ9.PfXnWBKd7avOey1VeR1ABBeH_9UCijc7uxQJUbw639N-RYmsXO0cfXWhZPmKaTX6wZUcSs4znSZ1SK5F8p6Y5w

//        String token = "eyJhbGciOiJIUzUxMiJ9.eyJsZXZlbCI6MTAsInVzZXJuYW1lIjoidG9tIn0.2KVlLdsmD8JLSN90P1nMl2Bm1gutf5UAeDqAP_bNcCue-5thMGe6WdrzZ3C6WkTMnAJE6Ed-Sv7R9ZpxtPOKsg";
//
//        Claims claims = getClaimsFromToken(token);
//        System.out.println(claims);
    }
}
