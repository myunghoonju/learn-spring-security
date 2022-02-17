package org.learn.security.study.domain.service;

import org.junit.jupiter.api.Test;
import org.learn.security.study.domain.entity.Account;
import org.learn.security.study.domain.repository.UserRepository;
import org.learn.security.study.web.user.dto.AccountDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class UserServiceTest {

    @Autowired
    UserRepository repository;

    @Test
    void saveTest() {
        AccountDto accountDto = new AccountDto();
        accountDto.setUsername("test");
        accountDto.setAge(1);
        accountDto.setPassword("1111");
        accountDto.setRole("ROLE_USER");
        accountDto.setEmail("email");
        Account account = accountDto.toEntity();

        repository.save(account);

        List<Account> result = repository.findAll();
        Account savedAccount = result.get(0);

        assertThat(savedAccount.getUsername()).isEqualTo(accountDto.getUsername());
    }
}