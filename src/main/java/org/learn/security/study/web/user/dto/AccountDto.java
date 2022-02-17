package org.learn.security.study.web.user.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.learn.security.study.domain.entity.Account;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Getter
@Setter
@NoArgsConstructor
public class AccountDto {

    private String username;
    private String password;
    private String email;
    private int age;
    private String role;

    public Account toEntity() {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        String encodedPassword = encoder.encode(this.password);

        return Account.builder()
                .username(this.username)
                .password(encodedPassword)
                .email(this.email)
                .age(this.age)
                .role(this.role)
                .build();
    }
}
