package com.web.mvc.config;


import com.web.mvc.jwt.JWTUtil;
import com.web.mvc.jwt.LoginFilter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@Slf4j
@RequiredArgsConstructor
public class SecurityConfig {

    //AuthenticationManager 가 인자로 받을 AuthenticationConfiguraion 객체 생성자 주입
    private final AuthenticationConfiguration authenticationConfiguration;
    private final JWTUtil jwtUtil;

    //AuthenticationManager Bean 등록
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {

        return configuration.getAuthenticationManager();
    }


    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        log.info("BCryptPasswordEncoder");
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        log.info("SecurityFilterChain");
        http
                .csrf((auth) -> auth.disable())
                /*
                csrf 공격은 주로 인증쿠키를 이용하는데 jwt 기반 인증에서는 authorization 헤더에
                jwt 토큰을 포함하여 요청하기 때문에 브라우저가 자동으로 쿠키를 첨부하지 않는다
                그래서 여기에서 disable 한다
                */
                .formLogin((auth) -> auth.disable())
                /*
                스프링이 제공하는 폼을 안 쓴다, UsernamePasswordAuthenticatorFilter 을 직접 커스텀해서
                사용해야 한다
                */
                .httpBasic((auth) -> auth.disable());
        /*
        http 기본 인증은 사용자 자격 증명을 매번 클라이언트에 보낼 때 암호화되지 않은 형태로
        보내게 되기 때문에 보안적인 문제가 있음
        그리고 어차피 나중에 jwt 사용할 예정이기 때문에 비활성화함
         */

        http.authorizeHttpRequests((auth) -> auth
                .requestMatchers("/index", "/members", "/members/**", "/boards").permitAll()
                .requestMatchers("/admin").hasRole("ADMIN")
                .anyRequest().authenticated());

        //필터 추가 LoginFilter()는 인자를 받음 (AuthenticationManager() 메소드에 authenticationConfiguration 객체를넣어야 함)
        //addFilterAt 은 UsernamePasswordAuthenticationFilter 의 자리에 LoginFilter 가 실행되도록 설정하는 것
        http.addFilterAt(new LoginFilter(
                this.authenticationManager(authenticationConfiguration) // AuthenticationManager
                        , jwtUtil), //JWTUtil
                UsernamePasswordAuthenticationFilter.class);

        return http.build();
        /*
        /members/* 는 하나의 세그먼트만 가능->/members/1 같이
        /members/** 는 하나 이상도 가능-> /members/1/details
         */

    }
}
