package com.posgrado.intranet.entities;

import java.io.Serial;
import java.io.Serializable;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
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

@Table(name = "tbEspecialidad", schema = "Academico")
public class TbEspecialidad implements Serializable {

  @Serial
  private static final long serialVersionUID = 1L;

  @Id
  @Column(name = "especialidad")
  private String especialidad;

  @Column(name = "carrera")
  private String carrera;

  @Column(name = "descripcion")
  private String descripcion;

  @Column(name = "costo_cursodes")
  private float costoCursoDes;
}
