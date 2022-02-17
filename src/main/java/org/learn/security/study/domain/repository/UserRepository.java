package org.learn.security.study.domain.repository;

import org.learn.security.study.domain.entity.Account;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<Account, Long> {
}
