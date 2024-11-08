package com.web.mvc.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public class DMLException extends  RuntimeException{
    private final ErrorCode errorCode;
}
