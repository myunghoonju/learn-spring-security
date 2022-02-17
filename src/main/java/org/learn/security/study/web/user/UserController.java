package org.learn.security.study.web.user;

import lombok.RequiredArgsConstructor;
import org.learn.security.study.domain.service.UserService;
import org.learn.security.study.web.user.dto.AccountDto;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@RequiredArgsConstructor
@Controller
public class UserController {

    private final UserService service;

    @GetMapping(value="/mypage")
    public String myPage() {

        return "user/mypage";
    }

    @GetMapping("/users")
    public String createUser() {
        return "user/login/register";
    }

    @PostMapping("/users")
    public String createUser(AccountDto dto) {
        service.createUser(dto);

        return "redirect:/";
    }
}
