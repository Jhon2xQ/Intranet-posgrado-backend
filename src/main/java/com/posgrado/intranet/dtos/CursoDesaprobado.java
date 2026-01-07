package com.posgrado.intranet.dtos;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class CursoDesaprobado {
  @NotBlank(message = "codigo de alumno es obligatorio")
  private String codigo;
}
