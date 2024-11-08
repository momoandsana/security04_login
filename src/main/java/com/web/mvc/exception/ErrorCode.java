package com.web.mvc.exception;

import org.springframework.http.HttpStatus;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
/**
 * Enum(열거형)은 서로 관련된 상수들을 정의하여 편리하게 사용하기 위한 자료형이다. 
 * https://jddng.tistory.com/305
 * 
 * */
public enum ErrorCode { //enum은 'Enumeration' 의 약자로 열거, 목록 이라는 뜻

	DUPLICATED(HttpStatus.BAD_REQUEST , "Duplicate Id", " 아이디가 중복입니다."),
	WRONG_PASS( HttpStatus.BAD_REQUEST, "password wrong","비밀번호 오류입니다.."),

	NOTFOUND_NO(HttpStatus.NOT_FOUND, "Not Found Board SearchById","글번호를 확인하세요."),
    NOTFOUND_BOARD( HttpStatus.BAD_REQUEST, "Not Found Board All","전체 게시물을 조회 할수 없습니다."),

    UPDATE_FAILED( HttpStatus.BAD_REQUEST, "Update fail","수정할수 없습니다."),
    DELETE_FAILED( HttpStatus.BAD_REQUEST, "Delete fail","삭제할 수 없습니다.");

    private final HttpStatus httpStatus;
    private  final String title;
    private final String message;
}



