function isNumber(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function validatePoint(point, path, errors) {
  if (!isPlainObject(point) || !isNumber(point.x) || !isNumber(point.y)) {
    errors.push(`${path} must include numeric x and y values`);
  }
}

function validateArray(value, path, errors) {
  if (!Array.isArray(value)) {
    errors.push(`${path} must be an array`);
    return false;
  }
  return true;
}

function validateString(value, path, errors, required = false) {
  if (value == null && !required) return;
  if (typeof value !== 'string') {
    errors.push(`${path} must be a string`);
  }
}

export function validateElectricalProjectPayload(payload) {
  const errors = [];

  if (payload.projectName !== undefined) validateString(payload.projectName, 'projectName', errors);
  if (payload.projectScale !== undefined && !isNumber(payload.projectScale)) {
    errors.push('projectScale must be numeric');
  }

  if (payload.elements !== undefined && validateArray(payload.elements, 'elements', errors)) {
    payload.elements.forEach((element, index) => {
      if (!isPlainObject(element)) {
        errors.push(`elements[${index}] must be an object`);
        return;
      }
      validateString(element.symbolId, `elements[${index}].symbolId`, errors, true);
      if (!isNumber(element.x) || !isNumber(element.y)) {
        errors.push(`elements[${index}] must include numeric x and y`);
      }
    });
  }

  if (payload.wires !== undefined && validateArray(payload.wires, 'wires', errors)) {
    payload.wires.forEach((wire, index) => {
      if (!isPlainObject(wire)) {
        errors.push(`wires[${index}] must be an object`);
        return;
      }
      if (!Array.isArray(wire.points) || wire.points.length < 2) {
        errors.push(`wires[${index}].points must contain at least two points`);
      }
    });
  }

  if (payload.walls !== undefined && validateArray(payload.walls, 'walls', errors)) {
    payload.walls.forEach((wall, index) => {
      if (!isPlainObject(wall)) {
        errors.push(`walls[${index}] must be an object`);
        return;
      }
      ['x1', 'y1', 'x2', 'y2'].forEach((field) => {
        if (!isNumber(wall[field])) {
          errors.push(`walls[${index}].${field} must be numeric`);
        }
      });
    });
  }

  if (payload.circuits !== undefined && validateArray(payload.circuits, 'circuits', errors)) {
    payload.circuits.forEach((circuit, index) => {
      if (!isPlainObject(circuit)) {
        errors.push(`circuits[${index}] must be an object`);
        return;
      }
      validateString(circuit.id, `circuits[${index}].id`, errors, true);
      validateString(circuit.name, `circuits[${index}].name`, errors, true);
    });
  }

  return errors;
}

export function validateFloorplanPayload(payload) {
  const errors = [];

  validateString(payload.name, 'name', errors, true);
  if (payload.sourceFileName !== undefined) validateString(payload.sourceFileName, 'sourceFileName', errors);

  if (!isPlainObject(payload.bounds)) {
    errors.push('bounds must be an object');
  } else {
    ['minX', 'minY', 'maxX', 'maxY', 'width', 'height'].forEach((field) => {
      if (!isNumber(payload.bounds[field])) {
        errors.push(`bounds.${field} must be numeric`);
      }
    });
  }

  if (validateArray(payload.walls, 'walls', errors)) {
    payload.walls.forEach((wall, index) => {
      if (!isPlainObject(wall)) {
        errors.push(`walls[${index}] must be an object`);
        return;
      }
      validatePoint(wall.start, `walls[${index}].start`, errors);
      validatePoint(wall.end, `walls[${index}].end`, errors);
    });
  }

  if (payload.openings !== undefined && validateArray(payload.openings, 'openings', errors)) {
    payload.openings.forEach((opening, index) => {
      if (!isPlainObject(opening)) {
        errors.push(`openings[${index}] must be an object`);
        return;
      }
      validateString(opening.type, `openings[${index}].type`, errors, true);
      ['x', 'y', 'width', 'height'].forEach((field) => {
        if (!isNumber(opening[field])) {
          errors.push(`openings[${index}].${field} must be numeric`);
        }
      });
    });
  }

  if (payload.rooms !== undefined && validateArray(payload.rooms, 'rooms', errors)) {
    payload.rooms.forEach((room, index) => {
      if (!isPlainObject(room)) {
        errors.push(`rooms[${index}] must be an object`);
        return;
      }
      validateString(room.key, `rooms[${index}].key`, errors, true);
      ['x', 'y', 'width', 'height', 'area'].forEach((field) => {
        if (!isNumber(room[field])) {
          errors.push(`rooms[${index}].${field} must be numeric`);
        }
      });
    });
  }

  if (payload.arcs !== undefined && validateArray(payload.arcs, 'arcs', errors)) {
    payload.arcs.forEach((arc, index) => {
      if (!isPlainObject(arc)) {
        errors.push(`arcs[${index}] must be an object`);
        return;
      }
      validatePoint(arc.center, `arcs[${index}].center`, errors);
      ['radius', 'startAngle', 'endAngle'].forEach((field) => {
        if (!isNumber(arc[field])) {
          errors.push(`arcs[${index}].${field} must be numeric`);
        }
      });
    });
  }

  if (payload.roomTypeOverrides !== undefined && !isPlainObject(payload.roomTypeOverrides)) {
    errors.push('roomTypeOverrides must be an object');
  }

  return errors;
}
