package com.web.mvc.repository;

import com.web.mvc.domain.Member;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface MemberRepository extends JpaRepository<Member,Long> {

    @Query("select m from Member m where m.id=?1")
    Member duplicateCheck(String id);

    /*
    jpa 는 pk를 기반으로 기본 함수를 제공하기 때문에 함수를 따로 만든다
     */
    Boolean existsById(String id);// member 의 id는 pk가 아님

    Member findById(String id);
}
