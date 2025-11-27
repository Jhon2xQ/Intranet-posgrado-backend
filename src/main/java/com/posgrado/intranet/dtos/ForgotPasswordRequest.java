package com.posgrado.intranet.dtos;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class ForgotPasswordRequest {
  @NotBlank(message = "Es necesario el codigo")
  private String codigo;
}
