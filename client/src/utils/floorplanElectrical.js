import { suggestRoomElectrical } from './electricalEngine';

const ROOM_TYPE_ORDER = [
  'entrance',
  'bathroom',
  'kitchen',
  'living_room',
  'office',
  'bedroom',
];

const ROOM_TYPE_LABELS = {
  entrance: 'כניסה',
  bathroom: 'חדר רחצה',
  kitchen: 'מטבח',
  living_room: 'סלון',
  office: 'משרד',
  bedroom: 'חדר שינה',
};

export function inferRoomType(room, index) {
  if (index === 0 && room.area <= 6) return 'entrance';
  if (room.area <= 4.5) return 'bathroom';
  if (room.area <= 8) return 'office';
  if (room.area <= 11) return index % 2 === 0 ? 'bedroom' : 'kitchen';
  if (room.area <= 16) return 'bedroom';
  return 'living_room';
}

function createPlacementGrid(room, count) {
  const points = [];
  const columns = Math.max(1, Math.ceil(Math.sqrt(count)));
  const rows = Math.max(1, Math.ceil(count / columns));
  const xStep = room.width / (columns + 1);
  const yStep = room.height / (rows + 1);

  for (let row = 1; row <= rows; row += 1) {
    for (let column = 1; column <= columns; column += 1) {
      points.push({
        x: room.x + column * xStep,
        y: room.y + row * yStep,
      });
    }
  }

  return points.slice(0, count);
}

function roomContains(room, opening) {
  return (
    opening.x >= room.x - 20 &&
    opening.x <= room.x + room.width + 20 &&
    opening.y >= room.y - 20 &&
    opening.y <= room.y + room.height + 20
  );
}

function nearestDoor(room, openings) {
  return openings.find((opening) => opening.type === 'door' && roomContains(room, opening)) || null;
}

export function buildElectricalSuggestions(model, roomTypeOverrides = {}) {
  const typedRooms = (model.rooms || []).map((room, index) => ({
    ...room,
    type: roomTypeOverrides[room.key] || inferRoomType(room, index),
    suggestion: suggestRoomElectrical(
      roomTypeOverrides[room.key] || inferRoomType(room, index),
      room.width / 100,
      room.height / 100
    ),
  }));

  const circuits = [];
  const elements = [];

  typedRooms.forEach((room, roomIndex) => {
    room.suggestion.circuits.forEach((circuit, circuitIndex) => {
      circuits.push({
        id: `auto_room_${roomIndex}_${circuitIndex}`,
        name: `${room.suggestion.name} - ${circuit.name}`,
        type: circuit.name,
        breaker: circuit.breaker,
        cable: circuit.cable,
        color: ['#FBBF24', '#34D399', '#38BDF8', '#F87171'][circuitIndex % 4],
        elements: [],
      });
    });

    const roomCenter = {
      x: room.x + room.width / 2,
      y: room.y + room.height / 2,
    };

    const firstLightingCircuit = circuits.find((circuit) => circuit.id.startsWith(`auto_room_${roomIndex}_`));
    elements.push({
      symbolId: 'ceiling_light',
      x: roomCenter.x,
      y: roomCenter.y,
      label: `${room.suggestion.name} תאורה`,
      wattage: 60,
      circuit: firstLightingCircuit?.id || null,
      layer: 'electrical',
    });

    const outletCount = Math.min(4, Math.max(2, Math.ceil(room.area / 6)));
    const outletPoints = createPlacementGrid(room, outletCount);
    outletPoints.forEach((point, outletIndex) => {
      elements.push({
        symbolId: room.type === 'kitchen' ? 'double_outlet' : 'single_outlet',
        x: point.x,
        y: point.y,
        label: `${room.suggestion.name} שקע ${outletIndex + 1}`,
        wattage: room.type === 'kitchen' ? 1800 : 2300,
        circuit: circuits.find((circuit) => circuit.id.startsWith(`auto_room_${roomIndex}_1`))?.id || firstLightingCircuit?.id || null,
        layer: 'electrical',
      });
    });

    const door = nearestDoor(room, model.openings || []);
    elements.push({
      symbolId: room.type === 'entrance' ? 'motion_switch' : 'single_switch',
      x: door ? door.x + 35 : room.x + 35,
      y: door ? door.y + 35 : room.y + room.height - 35,
      label: `${room.suggestion.name} מפסק`,
      wattage: 0,
      circuit: firstLightingCircuit?.id || null,
      layer: 'electrical',
    });

    if (room.type === 'living_room') {
      elements.push({
        symbolId: 'tv_outlet',
        x: room.x + room.width - 50,
        y: room.y + room.height / 2,
        label: `${room.suggestion.name} TV`,
        wattage: 120,
        circuit: circuits.find((circuit) => circuit.id.startsWith(`auto_room_${roomIndex}_1`))?.id || null,
        layer: 'electrical',
      });
    }

    if (room.type === 'entrance' && door) {
      elements.push({
        symbolId: 'doorbell',
        x: door.x - 25,
        y: door.y - 25,
        label: 'פעמון דלת',
        wattage: 5,
        circuit: firstLightingCircuit?.id || null,
        layer: 'electrical',
      });
    }
  });

  return {
    roomPlans: typedRooms.map((room) => ({
      name: room.suggestion.name,
      type: room.type,
      area: room.area,
      circuits: room.suggestion.circuits,
    })),
    circuits,
    elements,
  };
}

export function getRoomTypeLegend() {
  return ROOM_TYPE_ORDER;
}

export function getRoomTypeLabel(type) {
  return ROOM_TYPE_LABELS[type] || type;
}
