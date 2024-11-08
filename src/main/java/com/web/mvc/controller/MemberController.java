package com.web.mvc.controller;

import com.web.mvc.domain.Member;
import com.web.mvc.service.MemberService;
import jakarta.annotation.Resource;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

@RequiredArgsConstructor
@RestController
@Slf4j
public class MemberController {
    private final MemberService memberService;

    @GetMapping("/test")
    public String test(){
        log.info("test 요청됨");
        return "Spring security setting 완료";
    }

    /*
    아이디 중복체크
     */
    @GetMapping("/members/{id}")
    public String duplicateIdCheck(@PathVariable String id){
        log.info("id {}", id);
        return memberService.duplicateCheck(id);
        /*
        중복 or 사용가능 이 화면에 나옴
         */
    }

    /*
    회원 가입
     */
    @PostMapping("/members")
    public String signUp(@RequestBody Member member){
        memberService.signUp(member);
        return "ok";
    }
}
