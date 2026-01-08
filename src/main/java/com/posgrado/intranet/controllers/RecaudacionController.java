package com.posgrado.intranet.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.posgrado.intranet.dtos.ApiResponse;
import com.posgrado.intranet.dtos.CursoDesaprobado;
import com.posgrado.intranet.dtos.CursoDesaprobadoRes;
import com.posgrado.intranet.externalService.RecaudacionService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
@RequestMapping("/recaudacion")
public class RecaudacionController {
  private final RecaudacionService recaudacionService;

  @PostMapping("/cursodesaprobado")
  public ResponseEntity<ApiResponse<CursoDesaprobadoRes>> getPagoCursoDesaprobado(
      @Valid @RequestBody CursoDesaprobado cursoDesDto) {
    try {
      CursoDesaprobadoRes pagoRes = recaudacionService.getPagoCursoDesaprobado(cursoDesDto.getCodigo());
      return ResponseEntity.ok(ApiResponse.success("Costo curso desaprobado encontrado satisfactoriamente", pagoRes));
    } catch (Exception e) {
      return ResponseEntity.status(404).body(ApiResponse.error("No se pudo obtener costo: " + e.getMessage()));
    }
  }
}
