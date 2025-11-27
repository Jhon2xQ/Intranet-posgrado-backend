package com.posgrado.intranet.entities;

import java.io.Serial;
import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter

@Table(name = "tbResidentadoPasswordReset", schema = "Seguridad")
public class TbResidentadoPasswordReset {
  @Serial
  private static final long serialVersionUID = 1L;

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "id")
  private Long id;

  @Column(name = "token")
  private String token;

  @Column(name = "usuario")
  private String usuario;

  @Column(name = "expiracion")
  private LocalDateTime expiracion;

  @Column(name = "usado")
  private boolean usado = false;

  public boolean estaExpirado() {
    return LocalDateTime.now().isAfter(this.expiracion);
  }

  public void marcarComoUsado() {
    this.usado = true;
  }
}
