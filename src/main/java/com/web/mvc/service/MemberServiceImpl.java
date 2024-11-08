package com.web.mvc.service;

import com.web.mvc.domain.Member;
import com.web.mvc.exception.ErrorCode;

import com.web.mvc.exception.MemberAuthenticationException;
import com.web.mvc.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.RequestMapping;

@Service
@RequiredArgsConstructor
@Slf4j
public class MemberServiceImpl implements MemberService {
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional(readOnly=true)
    @Override
    public String duplicateCheck(String id)
    {
        Member member = memberRepository.duplicateCheck(id);
        System.out.println("member = " + member);
        if(member==null)return "사용가능";
        else return "중복";
    }

    @Transactional
    @Override
    public void signUp(Member member) {
        if(memberRepository.existsById(member.getId()))
        {
            throw new MemberAuthenticationException(ErrorCode.DUPLICATED);
        }
        member.setPwd(passwordEncoder.encode(member.getPwd()));
        member.setRole("ROLE_USER");

        Member m=memberRepository.save(member);
        log.info("m={}",m);
    }

}
