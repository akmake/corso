/**
 * Electrical CAD Store - Zustand
 * Manages the state of the electrical drawing editor.
 */
import { create } from 'zustand';
import { devtools, persist } from 'zustand/middleware';

export const ELECTRICAL_DRAFT_STORAGE_KEY = 'electrical-cad-draft';

const initialState = {
  // Project
  projectId: null,
  projectName: 'פרויקט חדש',
  projectScale: 50,
  lastSaved: null,
  isDirty: false,

  // Canvas state
  zoom: 1,
  panX: 0,
  panY: 0,
  gridSize: 20,
  gridVisible: true,
  snapToGrid: true,
  snapToSymbol: true,
  snapThreshold: 10,
  showMeasurements: true,
  showLabels: true,

  // Active tool
  activeTool: 'select',
  activeSymbolType: null,
  wireRoutingMode: 'L',

  // Layers
  layers: [
    { id: 'floorplan', name: 'תכנית קומה', visible: true, locked: false, opacity: 0.4, color: '#9CA3AF' },
    { id: 'walls', name: 'קירות', visible: true, locked: false, opacity: 1, color: '#1F2937' },
    { id: 'electrical', name: 'סמלי חשמל', visible: true, locked: false, opacity: 1, color: '#3B82F6' },
    { id: 'wiring', name: 'חיווט', visible: true, locked: false, opacity: 1, color: '#10B981' },
    { id: 'annotations', name: 'הערות', visible: true, locked: false, opacity: 1, color: '#F59E0B' },
  ],
  activeLayer: 'electrical',

  // Elements on canvas
  elements: [],
  wires: [],
  walls: [],

  // Circuits
  circuits: [
    { id: 'circuit_1', name: 'תאורה כללית', type: 'lighting', breaker: 10, cable: 1.5, color: '#FBBF24', elements: [] },
    { id: 'circuit_2', name: 'שקעים כלליים', type: 'outlets', breaker: 16, cable: 2.5, color: '#34D399', elements: [] },
    { id: 'circuit_3', name: 'מזגנים', type: 'ac', breaker: 20, cable: 4, color: '#38BDF8', elements: [] },
  ],
  activeCircuit: 'circuit_1',

  // Selection
  selectedElementIds: [],
  selectionBox: null,

  // Drawing state
  drawingPoints: [],
  isDrawing: false,

  // History
  history: [],
  historyIndex: -1,
  maxHistory: 50,

  // Floor plan image
  floorPlanImage: null,
  floorPlanOpacity: 0.4,
  floorPlanScale: 1,
  floorPlanX: 0,
  floorPlanY: 0,

  // UI state
  showSymbolPalette: true,
  showPropertiesPanel: true,
  showLayerPanel: true,
  showCircuitPanel: false,
  showCalculator: false,
  showAIPanel: false,

  // Hydration
  hasHydrated: false,
};

const createPersistedSnapshot = (state) => ({
  projectId: state.projectId,
  projectName: state.projectName,
  projectScale: state.projectScale,
  lastSaved: state.lastSaved,
  isDirty: state.isDirty,
  zoom: state.zoom,
  panX: state.panX,
  panY: state.panY,
  gridSize: state.gridSize,
  gridVisible: state.gridVisible,
  snapToGrid: state.snapToGrid,
  snapToSymbol: state.snapToSymbol,
  snapThreshold: state.snapThreshold,
  showMeasurements: state.showMeasurements,
  showLabels: state.showLabels,
  activeTool: state.activeTool,
  activeSymbolType: state.activeSymbolType,
  wireRoutingMode: state.wireRoutingMode,
  layers: state.layers,
  activeLayer: state.activeLayer,
  elements: state.elements,
  wires: state.wires,
  walls: state.walls,
  circuits: state.circuits,
  activeCircuit: state.activeCircuit,
  floorPlanImage: state.floorPlanImage,
  floorPlanOpacity: state.floorPlanOpacity,
  floorPlanScale: state.floorPlanScale,
  floorPlanX: state.floorPlanX,
  floorPlanY: state.floorPlanY,
  showSymbolPalette: state.showSymbolPalette,
  showPropertiesPanel: state.showPropertiesPanel,
  showLayerPanel: state.showLayerPanel,
  showCircuitPanel: state.showCircuitPanel,
  showCalculator: state.showCalculator,
  showAIPanel: state.showAIPanel,
});

export const hasElectricalDraft = () => {
  if (typeof window === 'undefined') return false;
  return Boolean(window.localStorage.getItem(ELECTRICAL_DRAFT_STORAGE_KEY));
};

const useElectricalStore = create(
  devtools(
    persist(
      (set, get) => ({
        ...initialState,

        setHasHydrated: (value) => set({ hasHydrated: value }),

        // Project actions
        setProjectName: (name) => set({ projectName: name, isDirty: true }),
        setProjectScale: (scale) => set({ projectScale: scale, isDirty: true }),

        loadProject: (data) => set({
          ...initialState,
          ...data,
          isDirty: false,
          history: [],
          historyIndex: -1,
          hasHydrated: true,
        }),

        resetProject: () => set({ ...initialState, hasHydrated: true }),

        markSaved: () => set({ lastSaved: new Date().toISOString(), isDirty: false }),

        clearDraft: () => {
          useElectricalStore.persist.clearStorage();
          set({ ...initialState, hasHydrated: true });
        },

        // Canvas actions
        setZoom: (zoom) => set({ zoom: Math.max(0.1, Math.min(5, zoom)) }),
        setPan: (x, y) => set({ panX: x, panY: y }),
        setGridSize: (size) => set({ gridSize: size }),
        toggleGrid: () => set((s) => ({ gridVisible: !s.gridVisible })),
        toggleSnap: () => set((s) => ({ snapToGrid: !s.snapToGrid })),
        toggleMeasurements: () => set((s) => ({ showMeasurements: !s.showMeasurements })),
        toggleLabels: () => set((s) => ({ showLabels: !s.showLabels })),

        // Tool actions
        setActiveTool: (tool) => set({
          activeTool: tool,
          isDrawing: false,
          drawingPoints: [],
          activeSymbolType: tool === 'symbol' ? get().activeSymbolType : null,
        }),

        setActiveSymbolType: (type) => set({
          activeSymbolType: type,
          activeTool: 'symbol',
        }),

        setWireRoutingMode: (mode) => set({ wireRoutingMode: mode }),

        // Element actions
        _pushHistory: () => {
          const state = get();
          const snapshot = {
            elements: JSON.parse(JSON.stringify(state.elements)),
            wires: JSON.parse(JSON.stringify(state.wires)),
            walls: JSON.parse(JSON.stringify(state.walls)),
          };
          const newHistory = state.history.slice(0, state.historyIndex + 1);
          newHistory.push(snapshot);
          if (newHistory.length > state.maxHistory) newHistory.shift();
          set({ history: newHistory, historyIndex: newHistory.length - 1 });
        },

        addElement: (element) => {
          get()._pushHistory();
          const id = `el_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
          const newElement = {
            ...element,
            id,
            layer: get().activeLayer,
            circuit: get().activeCircuit,
            rotation: element.rotation || 0,
            label: element.label || '',
            locked: false,
          };
          set((s) => ({
            elements: [...s.elements, newElement],
            isDirty: true,
          }));
          return id;
        },

        updateElement: (id, updates) => {
          get()._pushHistory();
          set((s) => ({
            elements: s.elements.map((el) => (el.id === id ? { ...el, ...updates } : el)),
            isDirty: true,
          }));
        },

        removeElements: (ids) => {
          get()._pushHistory();
          const idSet = new Set(ids);
          set((s) => ({
            elements: s.elements.filter((el) => !idSet.has(el.id)),
            wires: s.wires.filter((w) => !idSet.has(w.startElementId) && !idSet.has(w.endElementId)),
            selectedElementIds: [],
            isDirty: true,
          }));
        },

        duplicateElements: (ids) => {
          const state = get();
          const newElements = [];
          ids.forEach((id) => {
            const original = state.elements.find((el) => el.id === id);
            if (original) {
              newElements.push({
                ...original,
                id: `el_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
                x: original.x + 30,
                y: original.y + 30,
              });
            }
          });
          if (newElements.length > 0) {
            get()._pushHistory();
            set((s) => ({
              elements: [...s.elements, ...newElements],
              selectedElementIds: newElements.map((element) => element.id),
              isDirty: true,
            }));
          }
        },

        // Wire actions
        addWire: (wire) => {
          get()._pushHistory();
          const id = `wire_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
          set((s) => ({
            wires: [...s.wires, { ...wire, id, layer: 'wiring', circuit: s.activeCircuit }],
            isDirty: true,
          }));
          return id;
        },

        updateWire: (id, updates) => set((s) => ({
          wires: s.wires.map((wire) => (wire.id === id ? { ...wire, ...updates } : wire)),
          isDirty: true,
        })),

        removeWire: (id) => {
          get()._pushHistory();
          set((s) => ({
            wires: s.wires.filter((wire) => wire.id !== id),
            isDirty: true,
          }));
        },

        // Wall actions
        addWall: (wall) => {
          get()._pushHistory();
          const id = `wall_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
          set((s) => ({
            walls: [...s.walls, { ...wall, id, layer: 'walls', thickness: wall.thickness || 15 }],
            isDirty: true,
          }));
          return id;
        },

        removeWall: (id) => {
          get()._pushHistory();
          set((s) => ({
            walls: s.walls.filter((wall) => wall.id !== id),
            isDirty: true,
          }));
        },

        // Drawing state
        startDrawing: (point) => set({ isDrawing: true, drawingPoints: [point] }),
        addDrawingPoint: (point) => set((s) => ({ drawingPoints: [...s.drawingPoints, point] })),
        finishDrawing: () => set({ isDrawing: false, drawingPoints: [] }),
        cancelDrawing: () => set({ isDrawing: false, drawingPoints: [] }),

        // Selection
        selectElement: (id) => set({ selectedElementIds: [id] }),
        selectElements: (ids) => set({ selectedElementIds: ids }),
        addToSelection: (id) => set((s) => ({
          selectedElementIds: s.selectedElementIds.includes(id) ? s.selectedElementIds : [...s.selectedElementIds, id],
        })),
        clearSelection: () => set({ selectedElementIds: [] }),
        selectAll: () => set((s) => ({
          selectedElementIds: s.elements.filter((el) => !el.locked).map((el) => el.id),
        })),

        // Layers
        setActiveLayer: (layerId) => set({ activeLayer: layerId }),
        toggleLayerVisibility: (layerId) => set((s) => ({
          layers: s.layers.map((layer) => (layer.id === layerId ? { ...layer, visible: !layer.visible } : layer)),
        })),
        toggleLayerLock: (layerId) => set((s) => ({
          layers: s.layers.map((layer) => (layer.id === layerId ? { ...layer, locked: !layer.locked } : layer)),
        })),
        setLayerOpacity: (layerId, opacity) => set((s) => ({
          layers: s.layers.map((layer) => (layer.id === layerId ? { ...layer, opacity } : layer)),
        })),
        addLayer: (layer) => set((s) => ({
          layers: [...s.layers, { ...layer, id: `layer_${Date.now()}` }],
        })),
        removeLayer: (layerId) => set((s) => ({
          layers: s.layers.filter((layer) => layer.id !== layerId),
          elements: s.elements.filter((element) => element.layer !== layerId),
        })),

        // Circuits
        setActiveCircuit: (id) => set({ activeCircuit: id }),
        addCircuit: (circuit) => {
          const id = `circuit_${Date.now()}`;
          set((s) => ({
            circuits: [...s.circuits, { ...circuit, id, elements: [] }],
            isDirty: true,
          }));
          return id;
        },
        updateCircuit: (id, updates) => set((s) => ({
          circuits: s.circuits.map((circuit) => (circuit.id === id ? { ...circuit, ...updates } : circuit)),
          isDirty: true,
        })),
        removeCircuit: (id) => set((s) => ({
          circuits: s.circuits.filter((circuit) => circuit.id !== id),
          elements: s.elements.map((element) => (element.circuit === id ? { ...element, circuit: null } : element)),
          isDirty: true,
        })),
        assignToCircuit: (elementIds, circuitId) => set((s) => ({
          elements: s.elements.map((element) => (
            elementIds.includes(element.id) ? { ...element, circuit: circuitId } : element
          )),
          isDirty: true,
        })),

        // Floor plan
        setFloorPlan: (imageData) => set({
          floorPlanImage: imageData,
          isDirty: true,
        }),
        setFloorPlanTransform: (transform) => set((s) => ({
          floorPlanOpacity: transform.opacity ?? s.floorPlanOpacity,
          floorPlanScale: transform.scale ?? s.floorPlanScale,
          floorPlanX: transform.x ?? s.floorPlanX,
          floorPlanY: transform.y ?? s.floorPlanY,
        })),
        removeFloorPlan: () => set({
          floorPlanImage: null,
          isDirty: true,
        }),

        // Undo / redo
        undo: () => {
          const { history, historyIndex } = get();
          if (historyIndex < 0) return;

          if (historyIndex === history.length - 1) {
            const currentSnapshot = {
              elements: JSON.parse(JSON.stringify(get().elements)),
              wires: JSON.parse(JSON.stringify(get().wires)),
              walls: JSON.parse(JSON.stringify(get().walls)),
            };
            const newHistory = [...history, currentSnapshot];
            const snapshot = history[historyIndex];
            set({
              elements: snapshot.elements,
              wires: snapshot.wires,
              walls: snapshot.walls,
              history: newHistory,
              historyIndex: historyIndex - 1,
            });
            return;
          }

          const snapshot = history[historyIndex];
          set({
            elements: snapshot.elements,
            wires: snapshot.wires,
            walls: snapshot.walls,
            historyIndex: historyIndex - 1,
          });
        },

        redo: () => {
          const { history, historyIndex } = get();
          if (historyIndex >= history.length - 1) return;
          const snapshot = history[historyIndex + 1];
          set({
            elements: snapshot.elements,
            wires: snapshot.wires,
            walls: snapshot.walls,
            historyIndex: historyIndex + 1,
          });
        },

        // UI panels
        toggleSymbolPalette: () => set((s) => ({ showSymbolPalette: !s.showSymbolPalette })),
        togglePropertiesPanel: () => set((s) => ({ showPropertiesPanel: !s.showPropertiesPanel })),
        toggleLayerPanel: () => set((s) => ({ showLayerPanel: !s.showLayerPanel })),
        toggleCircuitPanel: () => set((s) => ({ showCircuitPanel: !s.showCircuitPanel })),
        toggleCalculator: () => set((s) => ({ showCalculator: !s.showCalculator })),
        toggleAIPanel: () => set((s) => ({ showAIPanel: !s.showAIPanel })),

        // Serialization
        getProjectData: () => {
          const state = get();
          return {
            projectName: state.projectName,
            projectScale: state.projectScale,
            elements: state.elements,
            wires: state.wires,
            walls: state.walls,
            circuits: state.circuits,
            layers: state.layers,
            floorPlanImage: state.floorPlanImage,
            floorPlanOpacity: state.floorPlanOpacity,
            floorPlanScale: state.floorPlanScale,
            floorPlanX: state.floorPlanX,
            floorPlanY: state.floorPlanY,
          };
        },
      }),
      {
        name: ELECTRICAL_DRAFT_STORAGE_KEY,
        partialize: createPersistedSnapshot,
        onRehydrateStorage: () => (state) => {
          state?.setHasHydrated(true);
        },
      }
    ),
    { name: 'electrical-cad-store' }
  )
);

export default useElectricalStore;
