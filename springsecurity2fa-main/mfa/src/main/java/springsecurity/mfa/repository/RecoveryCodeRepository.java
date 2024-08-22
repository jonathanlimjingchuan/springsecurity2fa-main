package springsecurity.mfa.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import springsecurity.mfa.model.RecoveryCode;
import springsecurity.mfa.model.User;

import java.util.Optional;
import java.util.Set;

@Repository
public interface RecoveryCodeRepository extends JpaRepository<RecoveryCode, Long> {

    Optional<RecoveryCode> findByCodeAndUser(String code, User user);

    Set<RecoveryCode> findByUser(User user);

    @Modifying
    @Query("DELETE FROM RecoveryCode rc WHERE rc.id = :id")
    void deleteById(Long id);
}
