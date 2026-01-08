package com.posgrado.intranet.externalService;

import org.springframework.stereotype.Service;

import com.posgrado.intranet.dtos.CursoDesaprobadoRes;
import com.posgrado.intranet.entities.TbAlumnoCarrera;
import com.posgrado.intranet.entities.TbCarrera;
import com.posgrado.intranet.entities.TbEspecialidad;
import com.posgrado.intranet.entities.TbPersona;
import com.posgrado.intranet.services.BaseService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class RecaudacionService {
  private final BaseService baseService;

  public CursoDesaprobadoRes getPagoCursoDesaprobado(String alumno) {
    TbAlumnoCarrera alumnoCa = baseService.getAlumnoCarrera(alumno);
    TbPersona persona = baseService.getPersona(alumno);
    TbCarrera carrera = baseService.getCarrera(alumnoCa.getCarrera());
    TbEspecialidad especialidad = baseService.getEspecialidad(alumnoCa.getCarrera(), alumnoCa.getEspecialidad());
    if (especialidad.getCostoCursoDes()==null) {
      throw new RuntimeException("El programa académico no tiene definido el costo de curso desaprobado");
    }
    CursoDesaprobadoRes cursoResponse = new CursoDesaprobadoRes();
    cursoResponse.setCodigo(alumno);
    cursoResponse
        .setNombres(persona.getNombres() + " " + persona.getApellidoPaterno() + " " + persona.getApellidoMaterno());
    cursoResponse.setPrograma(carrera.getNombre() + " " + especialidad.getDescripcion());
    cursoResponse.setMonto(especialidad.getCostoCursoDes());
    return cursoResponse;
  }
}
