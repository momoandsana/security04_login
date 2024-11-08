package com.web.mvc.jwt;

import com.web.mvc.domain.Member;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

/*
 JWT 정보 검증및 생성
 */
@Component
@Slf4j
public class JWTUtil {

    private SecretKey secretKey;//Decode한 secret key를 담는 객체
    
    //application.properties에 있는 미리 Base64로 Encode된 Secret key를 가져온다
    /*
    @Value 는 객체 주입이 아니라 primitive 형식 주입
    application.properties 에서 spring.jwt.secret 을 가지고 옴
    여기는 세팅을 하는 과정
     */
    public JWTUtil(@Value("${spring.jwt.secret}")String secret) {
   
        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }
    
    //검증 Username
    public String getUsername(String token) {
         log.info("getUsername(String token)  call");
        String re = Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
        log.info("getUsername(String token)  re = {}" ,re);
        return re;
    }
    //검증 Id
    public String getId(String token) {
        log.info("getId(String token)  call");
        String re = Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("id", String.class);
        log.info("getIds(String token)  re = {}" ,re);
        return re;
    }
    
    //검증 Role
    public String getRole(String token) {
        log.info("getRole(String token)  call");
        String re = Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
        log.info("getRole(String token)  re = {} " , re);
        return re;
    }
    
    //검증 Expired
    public Boolean isExpired(String token) {
        log.info("isExpired(String token)  call");
        boolean re = Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
        log.info("isExpired(String token)  re  = {}",re);
        return re;
    }
    //Bearer : JWT 혹은 Oauth에 대한 토큰을 사용
    //public String createJwt(String username, String role, Long expiredMs) {
    //claim은 payload에 해당하는 정보
    public String createJwt(Member member, String role, Long expiredMs) {
        log.info("createJwt  call");
        return Jwts.builder()
                .claim("username", member.getName()) //이름
                .claim("id", member.getId()) //아이디
                .claim("role", role) //Role
                .issuedAt(new Date(System.currentTimeMillis())) //현재로그인된 시간
                .expiration(new Date(System.currentTimeMillis() + expiredMs)) //만료시간
                .signWith(secretKey)
                .compact();
    }
}



