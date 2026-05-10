import test from 'node:test';
import assert from 'node:assert/strict';

import { evaluateElectricalProject } from '../utils/electricalRules.js';
import { validateElectricalProjectPayload } from '../utils/validators.js';

test('validateElectricalProjectPayload accepts a minimal valid payload', () => {
  const errors = validateElectricalProjectPayload({
    projectName: 'Demo',
    projectScale: 50,
    elements: [{ symbolId: 'socket', x: 100, y: 120 }],
    wires: [{ points: [[0, 0], [100, 0]] }],
    walls: [{ x1: 0, y1: 0, x2: 200, y2: 0 }],
    circuits: [{ id: 'c1', name: 'Lighting', type: 'lighting', breaker: 10 }],
  });

  assert.deepEqual(errors, []);
});

test('evaluateElectricalProject blocks missing circuit references', () => {
  const findings = evaluateElectricalProject({
    circuits: [{ id: 'c1', name: 'Lighting', type: 'lighting', breaker: 10 }],
    elements: [{ symbolId: 'socket', x: 10, y: 20, circuit: 'missing', wattage: 100 }],
    wires: [],
  });

  assert.equal(findings.blocking.length, 1);
  assert.match(findings.blocking[0], /missing circuit/i);
});

test('evaluateElectricalProject blocks overloads and warns on near capacity', () => {
  const overloaded = evaluateElectricalProject({
    circuits: [{ id: 'c1', name: 'Lighting', type: 'lighting', breaker: 10 }],
    elements: [
      { symbolId: 'light-1', x: 0, y: 0, circuit: 'c1', wattage: 1000 },
      { symbolId: 'light-2', x: 10, y: 10, circuit: 'c1', wattage: 1000 },
    ],
  });

  assert.equal(overloaded.blocking.length, 1);
  assert.match(overloaded.blocking[0], /exceeds safe capacity/i);

  const nearCapacity = evaluateElectricalProject({
    circuits: [{ id: 'c1', name: 'Lighting', type: 'lighting', breaker: 10 }],
    elements: [
      { symbolId: 'light-1', x: 0, y: 0, circuit: 'c1', wattage: 1500 },
      { symbolId: 'light-2', x: 10, y: 10, circuit: 'c1', wattage: 200 },
    ],
  });

  assert.equal(nearCapacity.blocking.length, 0);
  assert.equal(nearCapacity.warnings.length, 1);
  assert.match(nearCapacity.warnings[0], /close to capacity/i);
});

test('evaluateElectricalProject warns on unassigned elements and odd breaker sizing', () => {
  const findings = evaluateElectricalProject({
    circuits: [{ id: 'c1', name: 'Sockets', type: 'outlets', breaker: 10 }],
    elements: [{ symbolId: 'socket', x: 20, y: 30, wattage: 120 }],
  });

  assert.equal(findings.blocking.length, 0);
  assert.equal(findings.warnings.length, 2);
});
