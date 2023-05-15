package com.fsk.hellosecurity.controller;


import cn.hutool.captcha.CaptchaUtil;
import cn.hutool.captcha.CircleCaptcha;
import cn.hutool.captcha.GifCaptcha;
import cn.hutool.core.util.RandomUtil;
import cn.hutool.core.util.StrUtil;
import com.fsk.hellosecurity.config.LocalCache;
import com.fsk.hellosecurity.domain.ImageCode;
import com.fsk.hellosecurity.exception.ValidateCodeException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.Random;
import java.util.UUID;


@RestController
public class HelloController {

    @GetMapping("/hello")
    public String hello() {
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context.getAuthentication();
        String name = authentication.getName();
        return "hello! " + name;
    }

    @GetMapping("/code/image")
    public ImageCode createCode(String uuid) throws IOException {
        if (StrUtil.isNotEmpty(uuid)) {
            LocalCache.getCache().remove(uuid);
        }
        CircleCaptcha captcha = CaptchaUtil.createCircleCaptcha(100, 50, 4, 10);
        String newUuid = UUID.randomUUID().toString();
        LocalCache.getCache().put(newUuid, captcha.getCode());
        ImageCode imageCode = new ImageCode();
        imageCode.setImg("data:image/gif;base64," + captcha.getImageBase64());
        imageCode.setUuid(newUuid);
        return imageCode;
    }

    @GetMapping("/code/sms")
    public void createSmsCode(String phone) throws IOException {
        if (StrUtil.isEmpty(phone)){
            throw new ValidateCodeException("手机号不能为空");
        }
        String smsCode = RandomUtil.randomNumbers(4);
        LocalCache.getCache().put(phone, smsCode);
        System.out.println(StrUtil.format("向手机号{}发送验证码{}", phone, smsCode));
    }

    @GetMapping("/auth/admin")
    @PreAuthorize("hasAuthority('admin')")
    public String authAdmin() {
        return "您拥有admin权限，可以查看";
    }

    @GetMapping("/auth/test")
    @PreAuthorize("hasAuthority('test')")
    public String authTest() {
        return "您拥有test权限，可以查看";
    }
}
