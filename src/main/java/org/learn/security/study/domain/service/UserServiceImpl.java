package org.learn.security.study.domain.service;

import lombok.RequiredArgsConstructor;
import org.learn.security.study.domain.entity.Account;
import org.learn.security.study.domain.repository.UserRepository;
import org.learn.security.study.web.user.dto.AccountDto;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@RequiredArgsConstructor
@Service
public class UserServiceImpl implements UserService {

    private final UserRepository repository;

    @Transactional
    @Override
    public Account createUser(AccountDto dto) {
        Account account = dto.toEntity();
        return repository.save(account);
    }
}
