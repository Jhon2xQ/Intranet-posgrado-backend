package com.posgrado.intranet.repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.posgrado.intranet.entities.TbResidentadoPasswordReset;

@Repository
public interface ResidentadoPasswordResetRepository extends JpaRepository<TbResidentadoPasswordReset, Long> {
  Optional<TbResidentadoPasswordReset> findByToken(String token);
}
