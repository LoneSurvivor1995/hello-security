package com.fsk.hellosecurity.filter;

import cn.hutool.core.util.StrUtil;
import com.fsk.hellosecurity.config.LocalCache;
import com.fsk.hellosecurity.exception.ValidateCodeException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class SmsCodeFilter extends OncePerRequestFilter {

    @Autowired
    private AuthenticationFailureHandler authenticationFailureHandler;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if ("/login/phone".equals(request.getRequestURI()) && "post".equalsIgnoreCase(request.getMethod())) {
            try {
                validateCode(request);
            } catch (ValidateCodeException e) {
                authenticationFailureHandler.onAuthenticationFailure(request, response, e);
                return;
            }
        }
        filterChain.doFilter(request, response);
    }

    private void validateCode(HttpServletRequest request) {
        String phone = request.getParameter("phone");
        String smsCode = request.getParameter("smsCode");
        String localSmsCode = LocalCache.getCache().get(phone);
        if (StrUtil.isEmpty(smsCode.trim())) {
            throw new ValidateCodeException("验证码不能为空");
        }
        if (StrUtil.isEmpty(localSmsCode)) {
            throw new ValidateCodeException("验证码已过期");
        }
        if (!smsCode.equals(localSmsCode)) {
            throw new ValidateCodeException("验证码不正确");
        }
        LocalCache.getCache().remove(phone);
    }
}
