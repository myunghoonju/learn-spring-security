package org.learn.security.study.domain.service;

import org.learn.security.study.domain.entity.Account;
import org.learn.security.study.web.user.dto.AccountDto;

public interface UserService {

    Account createUser(AccountDto accountDto);
}
