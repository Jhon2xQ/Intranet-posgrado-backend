package com.posgrado.intranet.services;

import org.springframework.stereotype.Service;

import com.posgrado.intranet.entities.TbAlumno;
import com.posgrado.intranet.entities.TbAlumnoCarrera;
import com.posgrado.intranet.entities.TbCarrera;
import com.posgrado.intranet.entities.TbEspecialidad;
import com.posgrado.intranet.entities.TbPersona;
import com.posgrado.intranet.repositories.AlumnoCarreraRepository;
import com.posgrado.intranet.repositories.AlumnoRepository;
import com.posgrado.intranet.repositories.CarreraRepository;
import com.posgrado.intranet.repositories.EspecialidadRepository;
import com.posgrado.intranet.repositories.PersonaRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class BaseService {
  private final AlumnoRepository alumnoRepository;
  private final PersonaRepository personaRepository;
  private final CarreraRepository carreraRepository;
  private final EspecialidadRepository especialidadRepository;
  private final AlumnoCarreraRepository alumnoCarreraRepository;

  public TbAlumnoCarrera getAlumnoCarrera(String alumno) {
    return alumnoCarreraRepository.findByAlumnoAndEstadoAlumnoNot(alumno, 5)
        .orElseThrow(() -> new RuntimeException("codigo de alumno desactivado o no existe"));
  }

  @SuppressWarnings("null")
  public TbPersona getPersona(String alumnoId) {
    TbAlumno alumno = alumnoRepository.findById(alumnoId)
        .orElseThrow(() -> new RuntimeException("Alumno no encontrado"));
    return personaRepository.findById(alumno.getPersona())
        .orElseThrow(() -> new RuntimeException("Persona no encontrada"));
  }

  @SuppressWarnings("null")
  public TbCarrera getCarrera(String carreraId) {
    return carreraRepository.findById(carreraId).orElseThrow(() -> new RuntimeException("Carrera no encontrada"));
  }

  public TbEspecialidad getEspecialidad(String carreraId, String especialidadId) {
    return especialidadRepository.findByCarreraAndEspecialidad(carreraId, especialidadId)
        .orElseThrow(() -> new RuntimeException("Especialidad no encontrada"));
  }
}
