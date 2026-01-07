package com.posgrado.intranet.dtos;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CursoDesaprobadoRes {
  private String codigo;
  private String nombres;
  private String programa;
  private float monto;
}
