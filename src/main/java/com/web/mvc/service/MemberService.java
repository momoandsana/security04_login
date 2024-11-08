package com.web.mvc.service;

import com.web.mvc.domain.Member;

public interface MemberService {
    String duplicateCheck(String id);

    /**
     * 가입
     */
    void signUp(Member member);
}
