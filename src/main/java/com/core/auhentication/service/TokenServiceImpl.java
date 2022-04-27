package com.core.auhentication.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

public class TokenServiceImpl implements TokenService {

    private final String secret;
    private final Long expiration;

    public TokenServiceImpl(@Value("${switch.jwt.secret}") String secret, @Value("${tantetobi.jwt.expiration}") Long expiration) {
        this.secret = secret;
        this.expiration = expiration;
    }

    @Override
    public String generateToken(Map<String, Object> claims, String subject) {
        return doGenerateToken(claims, subject);
    }

    @Override
    public Boolean isTokenValid(String token) {
        return isTokenExpired(token);
    }

    @Override
    public String refreshToken(String token) {
        final Date createdDate = new Date(System.currentTimeMillis());
        final Date expirationDate = new Date(createdDate.getTime() + expiration * 1000);

        final Claims claims = getAllClaimsFromToken(token);
        claims.setIssuedAt(createdDate);
        claims.setExpiration(expirationDate);

        return Jwts.builder()
                .setClaims(claims)
                .signWith(signTokenWith512Algorithm(), secret)
                .compact();
    }

    private String doGenerateToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(setExpirationDate())
                .signWith(signTokenWith512Algorithm(), secret)
                .compact();
    }

    private Date setExpirationDate() {
        return new Date(System.currentTimeMillis() + expiration * 1000);
    }

    private SignatureAlgorithm signTokenWith512Algorithm() {
        return SignatureAlgorithm.HS512;
    }

    private boolean isTokenExpired(String token) {
        Date tokenExpirationDate = getExpirationDateFromToken(token);
        return tokenExpirationDate.before(new Date());
    }

    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }
}
