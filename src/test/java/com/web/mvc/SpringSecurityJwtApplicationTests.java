package com.web.mvc;

import com.web.mvc.domain.Member;
import com.web.mvc.repository.MemberRepository;
import jakarta.persistence.Column;
import org.hibernate.annotations.TypeRegistration;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.annotation.Commit;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest
@Transactional
@Commit
public class SpringSecurityJwtApplicationTests {
    @Autowired
    private MemberRepository memberRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    /*
    관리자 등록
     */
    @Test
    void memberInsert(){
        String ecnPwd=passwordEncoder.encode("1234");
        memberRepository.save(Member.builder()
                .id("admin")
                .pwd(ecnPwd)
                .role("ROLE_ADMIN")
                .address("오리역")
                .name("관리자")
                .build()
        );
    }
}
