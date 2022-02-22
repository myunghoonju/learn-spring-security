package org.learn.security.study.web.user;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class MessageController {

    @GetMapping(value="/messages")
    public String mypage() {
        return "user/messages";
    }

    @ResponseBody
    @GetMapping(value="/api/messages")
    public String apiMessage() {
        return HttpStatus.OK.toString();
    }
}
