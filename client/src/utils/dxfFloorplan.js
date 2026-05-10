import DxfParser from 'dxf-parser';

const DEFAULT_WALL_HEIGHT = 280;
const DEFAULT_WALL_THICKNESS = 20;
const MIN_SEGMENT_LENGTH = 10;
const OPENING_PROXIMITY_THRESHOLD = 80;

const round = (value, precision = 2) => Number(value.toFixed(precision));

const distance = (a, b) => Math.hypot(b.x - a.x, b.y - a.y);

const pointToSegmentDistance = (point, segment) => {
  const ax = segment.start.x;
  const ay = segment.start.y;
  const bx = segment.end.x;
  const by = segment.end.y;
  const dx = bx - ax;
  const dy = by - ay;

  if (dx === 0 && dy === 0) {
    return distance(point, segment.start);
  }

  const t = Math.max(0, Math.min(1, ((point.x - ax) * dx + (point.y - ay) * dy) / (dx * dx + dy * dy)));
  const projection = { x: ax + t * dx, y: ay + t * dy };

  return distance(point, projection);
};

const normalizeLine = (start, end, entity) => {
  if (distance(start, end) < MIN_SEGMENT_LENGTH) return null;

  return {
    id: entity.handle || `${start.x}-${start.y}-${end.x}-${end.y}`,
    start: { x: round(start.x), y: round(start.y) },
    end: { x: round(end.x), y: round(end.y) },
    layer: entity.layer || '0',
    color: entity.colorNumber || null,
    type: entity.type,
    length: round(distance(start, end)),
  };
};

const lineEntityToSegment = (entity) =>
  normalizeLine(
    { x: entity.vertices?.[0]?.x ?? entity.start?.x, y: entity.vertices?.[0]?.y ?? entity.start?.y },
    { x: entity.vertices?.[1]?.x ?? entity.end?.x, y: entity.vertices?.[1]?.y ?? entity.end?.y },
    entity
  );

const polylineToSegments = (entity) => {
  const vertices = entity.vertices || [];
  const segments = [];

  for (let index = 0; index < vertices.length - 1; index += 1) {
    const segment = normalizeLine(vertices[index], vertices[index + 1], entity);
    if (segment) segments.push(segment);
  }

  if (entity.shape && vertices.length > 2) {
    const closingSegment = normalizeLine(vertices[vertices.length - 1], vertices[0], entity);
    if (closingSegment) segments.push(closingSegment);
  }

  return segments;
};

const arcEntityToArc = (entity) => {
  if (!entity.center || typeof entity.radius !== 'number') return null;

  return {
    id: entity.handle || `arc-${entity.center.x}-${entity.center.y}-${entity.radius}`,
    center: {
      x: round(entity.center.x),
      y: round(entity.center.y),
    },
    radius: round(entity.radius),
    startAngle: round(entity.startAngle || 0),
    endAngle: round(entity.endAngle || 0),
    layer: entity.layer || '0',
    type: entity.type,
  };
};

const openingKeywordMap = [
  { type: 'door', pattern: /(door|dr|dore|דלת|פתחים|opening-door)/i },
  { type: 'window', pattern: /(window|win|חלון|ויטרינה|opening-window)/i },
];

const inferOpeningType = (...candidates) => {
  const haystack = candidates.filter(Boolean).join(' ');
  const found = openingKeywordMap.find(({ pattern }) => pattern.test(haystack));
  return found?.type || null;
};

const normalizeOpeningEntity = (entity) => {
  const name = entity.name || entity.block || entity.blockName || '';
  const type = inferOpeningType(entity.layer, name, entity.text);
  if (!type) return null;

  const x = entity.position?.x ?? entity.x ?? entity.start?.x;
  const y = entity.position?.y ?? entity.y ?? entity.start?.y;
  if (typeof x !== 'number' || typeof y !== 'number') return null;

  const width = round(Math.max(entity.xScale || entity.width || 1, 1) * (type === 'door' ? 90 : 120));
  const height = type === 'door' ? 210 : 140;
  const sillHeight = type === 'door' ? 0 : 90;
  const rotation = round(entity.rotation || 0);

  return {
    id: entity.handle || `${type}-${x}-${y}`,
    type,
    x: round(x),
    y: round(y),
    width,
    height,
    sillHeight,
    rotation,
    layer: entity.layer || '0',
    sourceName: name || entity.layer || type,
  };
};

const attachOpeningsToWalls = (openings, walls) =>
  openings
    .map((opening) => {
      let bestWall = null;
      let bestDistance = Number.POSITIVE_INFINITY;

      walls.forEach((wall) => {
        const currentDistance = pointToSegmentDistance({ x: opening.x, y: opening.y }, wall);
        if (currentDistance < bestDistance) {
          bestDistance = currentDistance;
          bestWall = wall;
        }
      });

      if (!bestWall || bestDistance > OPENING_PROXIMITY_THRESHOLD) {
        return {
          ...opening,
          wallId: null,
          distanceToWall: round(bestDistance),
        };
      }

      return {
        ...opening,
        wallId: bestWall.id,
        distanceToWall: round(bestDistance),
      };
    })
    .filter(Boolean);

const computeBounds = (segments) => {
  if (!segments.length) {
    return {
      minX: 0,
      minY: 0,
      maxX: 0,
      maxY: 0,
      width: 0,
      height: 0,
    };
  }

  const xs = segments.flatMap((segment) => [segment.start.x, segment.end.x]);
  const ys = segments.flatMap((segment) => [segment.start.y, segment.end.y]);
  const minX = Math.min(...xs);
  const maxX = Math.max(...xs);
  const minY = Math.min(...ys);
  const maxY = Math.max(...ys);

  return {
    minX,
    minY,
    maxX,
    maxY,
    width: round(maxX - minX),
    height: round(maxY - minY),
  };
};

const detectRooms = (segments) => {
  const horizontal = segments.filter((segment) => Math.abs(segment.start.y - segment.end.y) < 1);
  const vertical = segments.filter((segment) => Math.abs(segment.start.x - segment.end.x) < 1);
  const rooms = [];

  horizontal.forEach((top) => {
    horizontal.forEach((bottom) => {
      if (bottom.start.y <= top.start.y + MIN_SEGMENT_LENGTH) return;

      const left = vertical.find(
        (segment) =>
          Math.abs(segment.start.x - top.start.x) < 1 &&
          Math.min(segment.start.y, segment.end.y) <= top.start.y &&
          Math.max(segment.start.y, segment.end.y) >= bottom.start.y
      );

      const right = vertical.find(
        (segment) =>
          Math.abs(segment.start.x - top.end.x) < 1 &&
          Math.min(segment.start.y, segment.end.y) <= top.start.y &&
          Math.max(segment.start.y, segment.end.y) >= bottom.start.y
      );

      if (!left || !right) return;

      const width = round(top.end.x - top.start.x);
      const height = round(bottom.start.y - top.start.y);

      if (width < 120 || height < 120) return;

      const key = `${round(top.start.x)}-${round(top.start.y)}-${width}-${height}`;
      if (rooms.some((room) => room.key === key)) return;

      rooms.push({
        key,
        x: round(top.start.x),
        y: round(top.start.y),
        width,
        height,
        area: round((width * height) / 10000),
      });
    });
  });

  return rooms;
};

export function parseDxfFloorplan(content) {
  const parser = new DxfParser();
  const parsed = parser.parseSync(content);
  const entities = parsed.entities || [];

  const segments = entities.flatMap((entity) => {
    if (entity.type === 'LINE') {
      const segment = lineEntityToSegment(entity);
      return segment ? [segment] : [];
    }

    if (entity.type === 'LWPOLYLINE' || entity.type === 'POLYLINE') {
      return polylineToSegments(entity);
    }

    return [];
  });
  const arcs = entities
    .filter((entity) => entity.type === 'ARC')
    .map(arcEntityToArc)
    .filter(Boolean);

  const layerStats = segments.reduce((accumulator, segment) => {
    accumulator[segment.layer] = (accumulator[segment.layer] || 0) + 1;
    return accumulator;
  }, {});

  const bounds = computeBounds(segments);
  const rooms = detectRooms(segments);
  const walls = segments.map((segment) => ({
    ...segment,
    height: DEFAULT_WALL_HEIGHT,
    thickness: DEFAULT_WALL_THICKNESS,
  }));
  const rawOpenings = entities
    .filter((entity) => ['INSERT', 'TEXT', 'MTEXT'].includes(entity.type))
    .map(normalizeOpeningEntity)
    .filter(Boolean);
  const openings = attachOpeningsToWalls(rawOpenings, walls);

  return {
    fileUnits: parsed.header?.$INSUNITS || null,
    wallHeight: DEFAULT_WALL_HEIGHT,
    wallThickness: DEFAULT_WALL_THICKNESS,
    bounds,
    walls,
    openings,
    arcs,
    rooms,
    layerStats,
    unsupportedEntities: entities.filter(
      (entity) => !['LINE', 'LWPOLYLINE', 'POLYLINE', 'INSERT', 'TEXT', 'MTEXT', 'ARC'].includes(entity.type)
    ).length,
    entityCount: entities.length,
  };
}
