package com.web.mvc.exception;


import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;

@RestControllerAdvice
public class DefaultExceptionAdvice {
    @ExceptionHandler({MemberAuthenticationException.class})
    public ProblemDetail signInExceptionHandle(MemberAuthenticationException e){
        ProblemDetail problemDetail = ProblemDetail.forStatus(e.getErrorCode().getHttpStatus());

        problemDetail.setTitle(e.getErrorCode().getTitle());
        problemDetail.setDetail(e.getErrorCode().getMessage());
        problemDetail.setProperty("timestamp", LocalDateTime.now());

        return  problemDetail;
    }

}