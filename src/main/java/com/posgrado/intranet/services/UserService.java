package com.posgrado.intranet.services;

import org.springframework.stereotype.Service;

import com.posgrado.intranet.dtos.AcademicoDto;
import com.posgrado.intranet.dtos.PersonalDto;
import com.posgrado.intranet.entities.TbCarrera;
import com.posgrado.intranet.entities.TbEspecialidad;
import com.posgrado.intranet.entities.TbPersona;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserService {

  private final BaseService baseService;

  public AcademicoDto getInformacionAcademica(String alumnoId, String carreraId, String especialidadId) {
    TbPersona tbPersona = baseService.getPersona(alumnoId);
    TbCarrera tbCarrera = baseService.getCarrera(carreraId);
    TbEspecialidad tbEspecialidad = baseService.getEspecialidad(carreraId, especialidadId);

    AcademicoDto academicoDto = new AcademicoDto();
    academicoDto.setAlumno(alumnoId);
    academicoDto.setNombres(tbPersona.getNombres());
    academicoDto.setApellidoPaterno(tbPersona.getApellidoPaterno());
    academicoDto.setApellidoMaterno(tbPersona.getApellidoMaterno());
    academicoDto.setCarrera(tbCarrera.getNombre());
    academicoDto.setEspecialidad(tbEspecialidad.getDescripcion());

    return academicoDto;
  }

  public PersonalDto getInformacionPersonal(String alumnoId) {
    TbPersona tbPersona = baseService.getPersona(alumnoId);

    PersonalDto personalDto = new PersonalDto();
    personalDto.setAlumno(alumnoId);
    personalDto.setNombres(tbPersona.getNombres());
    personalDto.setApellidoPaterno(tbPersona.getApellidoPaterno());
    personalDto.setApellidoMaterno(tbPersona.getApellidoMaterno());
    personalDto.setNroDocumento(tbPersona.getNroDocumento());
    personalDto.setEmail(tbPersona.getEmail());
    personalDto.setDireccion(tbPersona.getDireccion());
    personalDto.setTelefono(tbPersona.getTelefono());

    return personalDto;
  }
}
