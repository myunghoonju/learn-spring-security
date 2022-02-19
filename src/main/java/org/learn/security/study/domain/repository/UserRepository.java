package org.learn.security.study.domain.repository;

import org.learn.security.study.domain.entity.Account;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface UserRepository extends JpaRepository<Account, Long> {

    @Query("SELECT a FROM Account as a WHERE a.username= :username")
    Account findByUsername(String username);
}
