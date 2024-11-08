package com.web.mvc.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public class MemberAuthenticationException extends  RuntimeException{
    private final ErrorCode errorCode;
}
