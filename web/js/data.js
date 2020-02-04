const DATA_PATH = 'data'
const SYMBOLS_CATS = [
  {
    name: 'network',
    icon: 'fa-network-wired'
  },
  {
    name: 'file_system',
    icon: 'fa-folder-open'
  },
  {
    name: 'command_line',
    icon: 'fa-terminal'
  },
  {
    name: 'memory',
    icon: 'fa-database'
  },
  {
    name: 'unknown',
    icon: 'fa-asterisk'
  }
]
if (window.system == undefined) window.system = {}
system.data = (function() {
  const that = this
  this.binary = {
    entryFunction: null
  }
  this.symbTree = {
    rootNode: null
  }
  this.blocks = []
  this.blocksById = {}
  this.functions = []
  this.functionsById = {}
  this.functionsByName = {}
  this.nodes = []
  this.nodesById = {}
  this.leaves = []
  this.leavesById = {}
  this.symbols = []
  this.symbolsById = {}
  // Filters
  this.blockWhiteFilters = []
  this.blockBlackFilters = []
  this.blockWhiteFiltersById = {}
  this.blockBlackFiltersById = {}
  this.edgeWhiteFilters = []
  this.edgeBlackFilters = []
  this.edgeWhiteFiltersById = {}
  this.edgeBlackFiltersById = {}

  this.getBlockById = (id) => this.blocks[this.blocksById[id]]
  this.getBlockAddressById = (id) => this.blocks[this.blocksById[id]].address
  this.getFunctionById = (id) => this.functions[this.functionsById[id]]
  this.getFunctionByName = (id) => this.functions[this.functionsByName[id]]
  this.getNodeById = (id) => this.nodes[this.nodesById[id]]
  this.getLeafById = (id) => this.leaves[this.leavesById[id]]
  this.getLeafNodeById = (id) => this.getNodeById(id)
  this.getSymbolById = (id) => this.symbols[this.symbolsById[id]]
  this.getBlockWhiteFilterByBlockId = (id) => this.blockWhiteFilters[this.blockWhiteFiltersById[`${id}-white`]]
  this.getBlockBlackFilterByBlockId = (id) => this.blockBlackFilters[this.blockBlackFiltersById[`${id}-black`]]
  this.getEdgeWhiteFilterByBlocksId = (srcId, dstId) => this.edgeWhiteFilters[this.edgeWhiteFiltersById[`${srcId}-${dstId}-white`]]
  this.getEdgeBlackFilterByBlocksId = (srcId, dstId) => this.edgeBlackFilters[this.edgeBlackFiltersById[`${srcId}-${dstId}-black`]]


  this.init = (relPath) => {
    return new Promise((resolve, reject) => {
      this.readFile(relPath, 'cfg')
        .then(json => this.loadCfg(json))
        .then(() => this.readFile(relPath, 'symbolic_tree'))
        .then(json => this.loadSymbolicTree(json))
        .then(() => this.readFile(relPath, 'leaves'))
        .then(json => this.loadLeaves(json))
        .then(() => this.readFile(relPath, 'coverage_loss'))
        .then(json => this.loadCoverageLoss(json))
        .then(() => this.readFile(relPath, 'symbols'))
        .then(json => this.loadSymbols(json))
        .then(() => resolve(true))
    })
  }
  this.readFile = (relPath, file) => {
    return new Promise((resolve, reject) => {
      d3.json(`${DATA_PATH}/${relPath}/${file}.json`)
        .then(json => resolve(json))
        .catch(error => reject(error))
    })
  }
  this.loadCfg = (json) => {
    return new Promise((resolve, reject) => {
      this.binary.entryFunction = json.entry.toString()
      try {
        json.functions.forEach((functionJson, functionIndex) => {
          const f = new this.Function(functionJson)
          this.functionsById[f.id] = functionIndex
          this.functionsByName[f.name] = functionIndex
          this.functions.push(f)
          functionJson.blocks.forEach(blockJson => {
            const b = new this.Block(blockJson)
            this.blocksById[b.id] = this.blocks.length
            this.blocks.push(b)
          })
          resolve(true)
        })
      }
      catch (error) {
        reject(error)
      }
    })
  }
  this.resetCfg = () => {
    return new Promise((resolve, reject) => {
      try {
        this.binary.entryFunction = null
        this.functions = []
        this.functionsById = {}
        this.functionsByName = {}
        this.blocks = []
        this.blocksById = {}
        resolve(true)
      }
      catch (error) {
        reject(error)
      }
    })
  }
  this.loadSymbolicTree = (json) => {
    return new Promise((resolve, reject) => {
      try {
        json.forEach((nodeJson, nodeIndex) => {
          const n = new this.Node(nodeJson)
          if (n.fatherId === 'root') this.symbTree.rootNode = n.id
          this.nodesById[n.id] = nodeIndex
          this.nodes.push(n)
          nodeJson.blocks.forEach((blockId, blockIndex) => {
            const block = this.getBlockById(blockId)
            block.nodes.push(n.id)
            if (blockIndex === nodeJson.blocks.length - 1 && n.forkSymbols.length > 0) block.forkSymbolsByNodeId[n.id] = n.forkSymbols
          })
        })
        const computeDepth = (nodeId) => {
          const n = this.getNodeById(nodeId)
          n.depth = (n.fatherId === "root") ? 0 : this.getNodeById(n.fatherId).depth + 1
          n.children.forEach(computeDepth)
        }
        computeDepth(this.symbTree.rootNode)
        resolve(true)
      }
      catch (error) {
        reject(error)
      }
    })
  }
  this.resetSymbolicTree = () => {
    return new Promise((resolve, reject) => {
      try {
        this.symbTree.rootNode = null
        this.nodes = []
        this.nodesById = {}
        resolve(true)
      }
      catch (error) {
        reject(error)
      }
    })
  }
  this.loadLeaves = (json) => {
    return new Promise((resolve, reject) => {
      try {
        json.forEach((leafJson, leafIndex) => {
          const l = new this.Leaf(leafJson)
          this.leavesById[l.id] = leafIndex
          this.leaves.push(l)
        })
        resolve(true)
      }
      catch (error) {
        reject(error)
      }
    })
  }
  this.resetLeaves = () => {
    return new Promise((resolve, reject) => {
      try {
        this.leaves = []
        this.leavesById = {}
        resolve(true)
      }
      catch (error) {
        reject(error)
      }
    })
  }
  this.loadCoverageLoss = (json) => {
    return new Promise((resolve, reject) => {
      try {
        json.blocks.white.forEach((filterJson, filterIndex) => {
          const f = new this.BlockFilter(filterJson, 'white')
          this.blockWhiteFiltersById[f.id] = filterIndex
          this.blockWhiteFilters.push(f)
        })
        json.blocks.black.forEach((filterJson, filterIndex) => {
          const f = new this.BlockFilter(filterJson, 'black')
          this.blockBlackFiltersById[f.id] = filterIndex
          this.blockBlackFilters.push(f)
        })
        json.edges.white.forEach((filterJson, filterIndex) => {
          const f = new this.EdgeFilter(filterJson, 'white')
          this.edgeWhiteFiltersById[f.id] = filterIndex
          this.edgeWhiteFilters.push(f)
        })
        json.edges.black.forEach((filterJson, filterIndex) => {
          const f = new this.EdgeFilter(filterJson, 'black')
          this.edgeBlackFiltersById[f.id] = filterIndex
          this.edgeBlackFilters.push(f)
        })
        resolve(true)
      }
      catch (error) {
        reject(error)
      }
    })
  }
  this.resetCoverageLoss = () => {
    return new Promise((resolve, reject) => {
      try {
        this.blockWhiteFiltersById = {}
        this.blockWhiteFilters = []
        this.blockBlackFiltersById = {}
        this.blockBlackFilters = []
        this.edgeWhiteFiltersById = {}
        this.edgeWhiteFilters = []
        this.edgeBlackFiltersById = {}
        this.edgeBlackFilters = []
        resolve(true)
      }
      catch (error) {
        reject(error)
      }
    })
  }
  this.loadSymbols = (json) => {
    return new Promise((resolve, reject) => {
      try {
        json.forEach((symbolJson, symbolIndex) => {
          const s = new this.Symbol(symbolJson)
          this.symbolsById[s.id] = symbolIndex
          this.symbols.push(s)
          if (s.creationNode) {
            const node = this.getNodeById(s.creationNode)
            node.generatedSymbols.push(s.id)
            const block = this.getBlockById(s.creationBlock)
            if (block.generatedSymbolsByNodeId[node.id] === undefined) block.generatedSymbolsByNodeId[node.id] = []
            block.generatedSymbolsByNodeId[node.id].push(s.id)
          }
        })
        resolve(true)
      }
      catch (error) {
        reject(error)
      }
    })
  }
  this.resetSymbols = () => {
    return new Promise((resolve, reject) => {
      try {
        this.symbols = []
        this.symbolsById = {}
        resolve(true)
      }
      catch (error) {
        reject(error)
      }
    })
  }

  this.getGraph = (functionId, nodeId, filters) => {
    const func = this.getFunctionById(functionId)
    const node = this.getNodeById(nodeId)
    const verticesById = {}
    const edgesById = {}
    class Vertex {
      constructor(type, id, funcId = null) {
        this.type = type
        this.id = id
        this.functionId = funcId === null ? functionId : funcId
        switch (type) {
          case 'block':
            this.cfg = {
              in: 0,
              out: 0
            }
            this.backPath = {
              count: 0,
              countUnique: 0,
              in: 0,
              inUnique: 0,
              out: 0,
              outUnique: 0,
              nodes: [],
              forkNodes: [],
              forkSymbolsBySymbolId: {},
              generatedSymbols: []
            }
            this.backPathCallees = {
              in: 0,
              inUnique: 0,
              out: 0,
              outUnique: 0
            }
            this.backPathCallers = {
              in: 0,
              inUnique: 0,
              out: 0,
              outUnique: 0
            }
            this.nodePath = {
              count: 0,
              countUnique: 0,
              in: 0,
              inUnique: 0,
              out: 0,
              outUnique: 0,
              nodes: [],
              forkNodes: [],
              forkSymbolsBySymbolId: {},
              generatedSymbols: []
            }
            this.nodePathCallees = {
              in: 0,
              inUnique: 0,
              out: 0,
              outUnique: 0
            }
            this.nodePathCallers = {
              in: 0,
              inUnique: 0,
              out: 0,
              outUnique: 0
            }
            this.subPaths = {
              count: 0,
              countUnique: 0,
              in: 0,
              inUnique: 0,
              out: 0,
              outUnique: 0,
              nodes: [],
              forkNodes: [],
              forkSymbolsBySymbolId: {},
              generatedSymbols: []
            }
            this.subPathsCallees = {
              in: 0,
              inUnique: 0,
              out: 0,
              outUnique: 0
            }
            this.subPathsCallers = {
              in: 0,
              inUnique: 0,
              out: 0,
              outUnique: 0
            }
            break
          case 'callee':
            this.backPath = {
              in: 0,
              out: 0,
              inUnique: 0,
              outUnique: 0
            }
            this.nodePath = {
              in: 0,
              out: 0,
              inUnique: 0,
              outUnique: 0
            }
            this.subPaths = {
              in: 0,
              out: 0,
              inUnique: 0,
              outUnique: 0
            }
            break
          case 'caller':
            this.backPath = {
              out: 0,
              outUnique: 0
            }
            this.nodePath = {
              out: 0,
              outUnique: 0
            }
            this.subPaths = {
              out: 0,
              outUnique: 0
            }
            break
          case 'callre':
            this.backPath = {
              in: 0,
              inUnique: 0
            }
            this.nodePath = {
              in: 0,
              inUnique: 0
            }
            this.subPaths = {
              in: 0,
              inUnique: 0
            }
            break
          default:
            break
        }
      }
    }
    class Edge {
      constructor(type, sourceId, targetId) {
        this.type = type
        this.sourceId = sourceId
        this.targetId = targetId
        this.id = `${sourceId}-${targetId}`
        switch (type) {
          case 'blockBlock':
            this.cfg = 0
            this.backPath = 0
            this.backPathUnique = 0
            this.nodePath = 0
            this.nodePathUnique = 0
            this.subPaths = 0
            this.subPathsUnique = 0
            break
          case 'blockCallFunction':
            this.backPathCall = 0
            this.backPathCallUnique = 0
            this.backPathRet = 0
            this.backPathRetUnique = 0
            this.nodePathCall = 0
            this.nodePathCallUnique = 0
            this.nodePathRet = 0
            this.nodePathRetUnique = 0
            this.subPathsCall = 0
            this.subPathsCallUnique = 0
            this.subPathsRet = 0
            this.subPathsRetUnique = 0
            break
          case 'functionCallBlock':
            this.backPathCall = 0
            this.backPathCallUnique = 0
            this.nodePathCall = 0
            this.nodePathCallUnique = 0
            this.subPathsCall = 0
            this.subPathsCallUnique = 0
            break
          case 'blockRetFunction':
            this.backPathRet = 0
            this.backPathRetUnique = 0
            this.nodePathRet = 0
            this.nodePathRetUnique = 0
            this.subPathsRet = 0
            this.subPathsRetUnique = 0
            break
          default:
            break
        }
      }
    }
    const visitPath = (pathBlocks, prefix, prevPathBlocks = []) => {
      const calleeFunctions = []
      const callerFunctions = []
      const visitedBlocks = {}
      const visitedEdges = {}
      const callingBlocks = []
      let retBlockId
      // Find callee and caller functions in previous blocks
      for (let blockIndex = 0; blockIndex < prevPathBlocks.length - 1; blockIndex++) {
        let sourceBlock = that.getBlockById(prevPathBlocks[blockIndex])
        let targetBlock = that.getBlockById(prevPathBlocks[blockIndex+1])
        let sourceId = sourceBlock.id
        let targetId = targetBlock.id
        if (sourceBlock.functionId === functionId && targetBlock.functionId !== functionId) {
          targetId = targetBlock.functionId
          edgeId = `${sourceId}-${targetId}`
          if (callerFunctions.indexOf(targetId) < 0) {
            calleeFunctions.push(targetId)
            callingBlocks.push(sourceId)
          }
          else callerFunctions.splice(callerFunctions.indexOf(targetId), 1)
        }
        else if (sourceBlock.functionId !== functionId && targetBlock.functionId === functionId) {
          sourceId = sourceBlock.functionId
          edgeId = `${sourceId}-${targetId}`
          if (calleeFunctions.indexOf(sourceId) < 0) callerFunctions.push(sourceId)
          else {
            callingBlocks.splice(calleeFunctions.indexOf(sourceId), 1)
            calleeFunctions.splice(calleeFunctions.indexOf(sourceId), 1)
          }
        }
      }
      //
      for (let blockIndex = 0; blockIndex < pathBlocks.length - 1; blockIndex++) {
        let sourceBlock = that.getBlockById(pathBlocks[blockIndex])
        let targetBlock = that.getBlockById(pathBlocks[blockIndex + 1])
        let sourceId = sourceBlock.id
        let targetId = targetBlock.id
        let edgeId = `${sourceId}-${targetId}`
        let vertexId
        // Count source
        if (blockIndex === 0 && sourceBlock.functionId === functionId) {
          visitedBlocks[sourceId] = true
          verticesById[sourceId][`${prefix}`].count += 1
          verticesById[sourceId][`${prefix}`].countUnique += 1
        }
        // 
        if (sourceBlock.functionId === functionId && targetBlock.functionId === functionId) {
          if (edgesById[edgeId] === undefined) edgesById[edgeId] = new Edge('blockBlock', sourceId, targetId)
          //
          verticesById[sourceId][`${prefix}`].out += 1
          verticesById[targetId][`${prefix}`].in += 1
          edgesById[edgeId][`${prefix}`] += 1
          if (visitedEdges[edgeId] === undefined) {
            visitedEdges[edgeId] = true
            verticesById[sourceId][`${prefix}`].outUnique += 1
            verticesById[targetId][`${prefix}`].inUnique += 1
            edgesById[edgeId][`${prefix}Unique`] += 1
          }
          //
          verticesById[targetId][`${prefix}`].count += 1
          if (visitedBlocks[targetId] === undefined) {
            visitedBlocks[targetId] = true
            verticesById[targetId][`${prefix}`].countUnique += 1
          }
        }
        //
        else if (sourceBlock.functionId === functionId && targetBlock.functionId !== functionId) {
          targetId = targetBlock.functionId
          if (callerFunctions.indexOf(targetId) < 0) {
            callingBlocks.push(sourceId)
            calleeFunctions.push(targetId)
            vertexId = `${targetId}-callee-${sourceId}`
            if (verticesById[vertexId] === undefined) verticesById[vertexId] = new Vertex('callee', vertexId, funcId = targetId)
            edgeId = `${sourceId}-${targetId}-blockCallFunction`
            if (edgesById[edgeId] === undefined) edgesById[edgeId] = new Edge('blockCallFunction', sourceId, vertexId)
            verticesById[sourceId][`${prefix}Callees`].out += 1
            verticesById[vertexId][`${prefix}`].in += 1
            edgesById[edgeId][`${prefix}Call`] += 1
            if (visitedEdges[edgeId] === undefined) {
              visitedEdges[edgeId] = true
              verticesById[sourceId][`${prefix}Callees`].outUnique += 1
              verticesById[vertexId][`${prefix}`].inUnique += 1
              edgesById[edgeId][`${prefix}CallUnique`] += 1
            }
          }
          else {
            callerFunctions.splice(callerFunctions.indexOf(targetId), 1)
            vertexId = `${targetId}-callre-${sourceId}`
            if (verticesById[vertexId] === undefined) verticesById[vertexId] = new Vertex('callre', vertexId, funcId = targetId)
            edgeId = `${sourceId}-${targetId}-blockRetFunction`
            if (edgesById[edgeId] === undefined) edgesById[edgeId] = new Edge('blockRetFunction', sourceId, vertexId)
            verticesById[sourceId][`${prefix}Callers`].out += 1
            verticesById[vertexId][`${prefix}`].in += 1
            edgesById[edgeId][`${prefix}Ret`] += 1
            if (visitedEdges[edgeId] === undefined) {
              visitedEdges[edgeId] = true
              verticesById[sourceId][`${prefix}Callers`].outUnique += 1
              verticesById[vertexId][`${prefix}`].inUnique += 1
              edgesById[edgeId][`${prefix}RetUnique`] += 1
            }
          }
        }
        else if (sourceBlock.functionId !== functionId && targetBlock.functionId === functionId) {
          sourceId = sourceBlock.functionId
          if (calleeFunctions.indexOf(sourceId) < 0) {
            callerFunctions.push(sourceId)
            vertexId = `${sourceId}-caller-${targetId}`
            if (verticesById[vertexId] === undefined) verticesById[vertexId] = new Vertex('caller', vertexId, funcId = sourceId)
            edgeId = `${sourceId}-${targetId}-functionCallBlock`
            if (edgesById[edgeId] === undefined) edgesById[edgeId] = new Edge('functionCallBlock', vertexId, targetId)
            verticesById[targetId][`${prefix}Callers`].in += 1
            verticesById[vertexId][`${prefix}`].out += 1
            edgesById[edgeId][`${prefix}Call`] += 1
            if (visitedEdges[edgeId] === undefined) {
              visitedEdges[edgeId] = true
              verticesById[targetId][`${prefix}Callers`].inUnique += 1
              verticesById[vertexId][`${prefix}`].outUnique += 1
              edgesById[edgeId][`${prefix}CallUnique`] += 1
            }
            //
            verticesById[targetId][`${prefix}`].count += 1
            if (visitedBlocks[targetId] === undefined) {
              visitedBlocks[targetId] = true
              verticesById[targetId][`${prefix}`].countUnique += 1
            }
          }
          else {
            if (callingBlocks[calleeFunctions.indexOf(sourceId)] === targetId) {
              vertexId = `${sourceId}-callee-${targetId}`
              if (verticesById[vertexId] === undefined) verticesById[vertexId] = new Vertex('callee', vertexId, funcId = sourceId)
              edgeId = `${targetId}-${sourceId}-blockCallFunction`
              if (edgesById[edgeId] === undefined) edgesById[edgeId] = new Edge('blockCallFunction', targetId, vertexId)
              verticesById[targetId][`${prefix}Callees`].in += 1
              verticesById[vertexId][`${prefix}`].out += 1
              edgesById[edgeId][`${prefix}Ret`] += 1
              if (visitedEdges[edgeId] === undefined) {
                visitedEdges[edgeId] = true
                verticesById[targetId][`${prefix}Callees`].inUnique += 1
                verticesById[vertexId][`${prefix}`].outUnique += 1
                edgesById[edgeId][`${prefix}RetUnique`] += 1
              }
            }
            else {
              retBlockId = callingBlocks[calleeFunctions.indexOf(sourceId)]
              vertexId = `${sourceId}-callee-${retBlockId}`
              if (verticesById[vertexId] === undefined) verticesById[vertexId] = new Vertex('callee', vertexId, funcId = sourceId)
              edgeId = `${retBlockId}-${sourceId}-blockCallFunction`
              if (edgesById[edgeId] === undefined) edgesById[edgeId] = new Edge('blockCallFunction', retBlockId, vertexId)
              verticesById[retBlockId][`${prefix}Callees`].in += 1
              verticesById[vertexId][`${prefix}`].out += 1
              edgesById[edgeId][`${prefix}Ret`] += 1
              if (visitedEdges[edgeId] === undefined) {
                visitedEdges[edgeId] = true
                verticesById[retBlockId][`${prefix}Callees`].inUnique += 1
                verticesById[vertexId][`${prefix}`].outUnique += 1
                edgesById[edgeId][`${prefix}RetUnique`] += 1
              }
              // add fake edge
              edgeId = `${retBlockId}-${targetId}`
              verticesById[retBlockId][`${prefix}`].out += 1
              verticesById[targetId][`${prefix}`].in += 1
              edgesById[edgeId][`${prefix}`] += 1
              if (visitedEdges[edgeId] === undefined) {
                visitedEdges[edgeId] = true
                verticesById[retBlockId][`${prefix}`].outUnique += 1
                verticesById[targetId][`${prefix}`].inUnique += 1
                edgesById[edgeId][`${prefix}Unique`] += 1
              }
              //
              verticesById[targetId][`${prefix}`].count += 1
              if (visitedBlocks[targetId] === undefined) {
                visitedBlocks[targetId] = true
                verticesById[targetId][`${prefix}`].countUnique += 1
              }
            }
            callingBlocks.splice(calleeFunctions.indexOf(sourceId), 1)
            calleeFunctions.splice(calleeFunctions.indexOf(sourceId), 1)
          }
        }
      }
    }
    const visitPathNodes = (pathNodes, prefix) => {
      pathNodes.forEach((nodeId, nodeIndex) => {
        const node = that.getNodeById(nodeId)
        node.blocks.forEach((blockId, blockIndex) => {
          if (verticesById[blockId] !== undefined) {
            const block = that.getBlockById(blockId)
            if (block.generatedSymbolsByNodeId[nodeId] !== undefined) verticesById[blockId][`${prefix}`].generatedSymbols.push(...block.generatedSymbolsByNodeId[nodeId])
            if (verticesById[blockId][`${prefix}`].nodes.length === 0 || verticesById[blockId][`${prefix}`].nodes[verticesById[blockId][`${prefix}`].nodes.length - 1] !== nodeId) {
              verticesById[blockId][`${prefix}`].nodes.push(nodeId)
            }
            if (blockIndex === node.blocks.length - 1 && nodeIndex < pathNodes.length - 1) {
              verticesById[blockId][`${prefix}`].forkNodes.push(nodeId)
              node.forkSymbols.forEach(symbolId => {
                if (verticesById[blockId][`${prefix}`].forkSymbolsBySymbolId[symbolId] === undefined) verticesById[blockId][`${prefix}`].forkSymbolsBySymbolId[symbolId] = []
                verticesById[blockId][`${prefix}`].forkSymbolsBySymbolId[symbolId].push(nodeId)
              })
              //verticesById[blockId][`${prefix}`].forkSymbols.push(node.forkSymbols)
            }
          }
        })
      })
    }
    // Control flow graph
    const cfg = func.getCfg()
    cfg.vertices.forEach(v => {
      verticesById[v.id] = new Vertex('block', v.id)
      verticesById[v.id].cfg.in += v.in
      verticesById[v.id].cfg.out += v.out
    })
    cfg.edges.forEach(e => {
      edgesById[e.id] = new Edge('blockBlock', e.sourceId, e.targetId)
      edgesById[e.id].cfg += 1
    })
    // Path from root to selected node
    const backPathBlocks = node.getBackPathBlocks()
    const backPathNodes = node.getBackPathNodes()
    visitPath(backPathBlocks, 'backPath')
    visitPathNodes(backPathNodes, 'backPath')
    // Path of selected node
    const nodePathBlocks = node.blocks
    const nodePathNodes = [ node.id ]
    visitPath(nodePathBlocks, 'nodePath', prevPathBlocks = backPathBlocks)
    visitPathNodes(nodePathNodes, 'nodePath')
    // Sub paths from selected node
    let prevSubPathsBlocks = JSON.parse(JSON.stringify(backPathBlocks))
    prevSubPathsBlocks.pop()
    prevSubPathsBlocks = prevSubPathsBlocks.concat(nodePathBlocks)
    const subPathsBlocks = node.getSubPathsBlocks(filters)
    const subPathsNodes = node.getSubPathsNodes(filters)
    subPathsBlocks.forEach(pathBlocks => {
      visitPath(pathBlocks, 'subPaths', prevPathBlocks = prevSubPathsBlocks)
    })
    subPathsNodes.forEach(pathNodes => {
      visitPathNodes(pathNodes, 'subPaths')
    })
    return {
      functionId: functionId,
      nodeId: nodeId,
      vertices: Object.values(verticesById),
      edges: Object.values(edgesById),
      numSubPaths: subPathsBlocks.length
    }
  }
  this.getTree = (rootNodeId, filters, maxDepth=Infinity) => {
    let rootNode = system.data.getNodeById(rootNodeId)
    let realMaxDepth = maxDepth + rootNode.depth
    let filteredNodes = new Set()
    filteredNodes.add(rootNodeId)
    rootNode.getSubPathsNodes(filters).forEach(path => {
      path.forEach((nodeId, i) => { 
        if(i <= maxDepth) filteredNodes.add(nodeId)
      })
    })
    let elements = []

    rootNode.getSubTreeNodesForTree(realMaxDepth).forEach(id => {
      let n = system.data.getNodeById(id)
      let subtreeLastBlocksId = {}
      n.getSubTreeNodes(filters).forEach( (subNodeId) => {
        let subNode = system.data.getNodeById(subNodeId)
        let b = subNode.blocks[subNode.blocks.length - 1]
        if(subtreeLastBlocksId.hasOwnProperty(b)) subtreeLastBlocksId[b]++;
        else subtreeLastBlocksId[b] = 1
      })
      let treeNode = {
        id: n.id,
        parentId: (n.fatherId == "root" || n.id == rootNodeId) ? null : n.fatherId,
        filteredOut: !filteredNodes.has(n.id),
        node: n,
        type: (n.children.length == 0) ? "leaf" : "node",
        forkingBlocks: this.getForkingBlocks(n.id, filters).filter((b) => { return b.blockId == [n.blocks[n.blocks.length - 1]]}),
        forkingSymbols: this.getForkingSymbols(n.id, filters).filter((s) => { return n.forkSymbols.includes(s.symbolId) }),
      }
      elements.push(treeNode)
      if(n.depth == realMaxDepth && treeNode.type == "node"){
        elements.push({
          id: "subtree-" + n.id,
          parentId: n.id,
          filteredOut: !filteredNodes.has(n.id),
          node: n,
          type: "subtree",
          forkingBlocks: this.getForkingBlocks(n.id, filters),
          forkingSymbols: this.getForkingSymbols(n.id, filters)
        })
      } 
    })
    let tree = d3.stratify()(elements)
    console.log(elements)
    return tree
  }
  this.getForkingBlocks = (nodeId, filters = null) => {
    const rootNode = this.getNodeById(nodeId)
    const subTreeNodes = rootNode.getSubTreeNodes(filters)
    const blocksById = {}
    subTreeNodes.forEach(nodeId => {
      const node = this.getNodeById(nodeId)
      if (node.forkSymbols.length > 0) {
        const block = this.getBlockById(node.blocks[node.blocks.length - 1])
        if (blocksById[block.id] === undefined) {
          blocksById[block.id] = {
            blockId: block.id,
            count: 0,
            network: [],
            memory: [],
            file_system: [],
            command_line: [],
            unknown: []
          }
        }
        blocksById[block.id].count += 1
        node.forkSymbols.forEach(symbolId => {
          const symbol = this.getSymbolById(symbolId)
          blocksById[block.id][symbol.category].push(nodeId)
        })
      }
    })
    return Object.values(blocksById).sort((a, b) => b.count - a.count)
  }
  this.getForkingSymbols = (nodeId, filters = null) => {
    const rootNode = this.getNodeById(nodeId)
    const subTreeNodes = rootNode.getSubTreeNodes(filters)
    const symbolsById = {}
    subTreeNodes.forEach(nodeId => {
      const node = this.getNodeById(nodeId)
      node.forkSymbols.forEach(symbolId => {
        if (symbolsById[symbolId] === undefined) {
          const symbol = this.getSymbolById(symbolId)
          let creationNode = symbol.creationNode ? this.getNodeById(symbol.creationNode) : false
          symbolsById[symbolId] = {
            symbolId: symbolId,
            size: symbol.size,
            category: symbol.category,
            creationNode: creationNode ? creationNode.id : false,
            creationDepth: creationNode ? creationNode.depth : false,
            forkingNodes: []
          }
        }
        symbolsById[symbolId].forkingNodes.push(nodeId)
      })
    })
    return Object.values(symbolsById).sort((a, b) => b.forkingNodes.length - a.forkingNodes.length)
  }

  this.Block = class {
    constructor(json){
      this.id = json.id.toString()
      this.address = json.address.toString()
      this.functionId = json.function.toString()
      this.code = json.code.map(c => c.toString())
      this.functionRefs = json.func_refs.map(ref => ({
        codeIndex: ref.code_id,
        type: ref.type,
        function: ref.function
      }))
      this.successors = json.successors.map(s => s.toString())
      this.nodes = []
      this.generatedSymbolsByNodeId = {}
      this.forkSymbolsByNodeId = {}
    }
  }
  this.Function = class {
    constructor(json){
      this.id = json.id.toString()
      this.name = json.name.toString()
      this.address = json.address.toString()
      this.callees = json.callees.map(c => c.toString())
      this.blocks = json.blocks.map(b => b.id.toString())
    }
  
    getCfg() {
      const cfg = {
        functionId: this.id,
        vertices: this.blocks.map(b => (
          { 
            id: b,
            type: "block",
            in: 0,
            out: 0
          }
        )),
        edges: []
      }
      cfg.vertices.forEach(v => {
        let vertex = that.getBlockById(v.id)
        v.out += vertex.successors.length
        vertex.successors.forEach(succId => {
          cfg.edges.push({
            id: `${v.id}-${succId}`,
            sourceId: v.id,
            targetId: succId
          })
          cfg.vertices.find(w => w.id == succId).in += 1
        })
      })
      return cfg
    }
  }
  this.Node = class {
    constructor(json){
      this.id = json.id.toString()
      this.fatherId = json.father_id === 0 ? 'root' : json.father_id.toString()
      this.blocks = (json.blocks === undefined) ? [] : json.blocks.map(b => b.toString())
      this.children = (json.children === undefined) ? [] : json.children.map(c => c.toString())
      this.forkSymbols = (json.fork_symbols === undefined) ? [] : json.fork_symbols.map(s => s.toString())
      this.depth = null
      this.generatedSymbols = []
    }
  /*
  */
    getBackPathNodes() {
      const visitNode = (nodeId) => {
        const node = that.getNodeById(nodeId)
        if (node.fatherId === 'root') return [ nodeId ]
        return visitNode(node.fatherId).concat([ nodeId ])
      }
      if (this.fatherId === 'root') return []
      return visitNode(this.fatherId)
    }
    getBackPathBlocks() {
      const backPathNodes = this.getBackPathNodes()
      const backPathBlocks = []
      backPathNodes.forEach(nodeId => {
        const node = that.getNodeById(nodeId)
        backPathBlocks.push(...node.blocks)
      })
      return backPathBlocks.concat(this.blocks[0])
    }
    /*
    */
    getSubTreeNodes(filters = null, maxDepth = Infinity) {
      const subTreeNodes = []
      const visitSubtree = (nodeId) => {
        const node = that.getNodeById(nodeId)
        if (node.children.length === 0) {
          const leaf = that.getLeafById(nodeId)
          if (filters === null || leaf.checkFilters(filters)) {
            if (node.depth - this.depth <= maxDepth) subTreeNodes.push(nodeId)
            return true
          }
          return false
        }
        let visit = false
        node.children.forEach(childId => {
          if (visitSubtree(childId)) visit = true
        })
        if (visit) {
          if (node.depth - this.depth <= maxDepth) subTreeNodes.push(nodeId)
          return true
        }
        return false
      }
      visitSubtree(this.id)
      return subTreeNodes
    }
    getSubTreeBlocks(filters = null, maxDepth = Infinity) {
      const subTreeNodes = this.getSubTreeNodes(filters, maxDepth)
      const subTreeBlocks = []
      subTreeNodes.forEach(nodeId => {
        const node = that.getNodeById(nodeId)
        subTreeBlocks.push(...node.blocks)
      })
      return [...new Set(subTreeBlocks)]
    }
    getSubTreeNodesForTree(maxDepth = Infinity) {
      let node = this
      let subTree = [ this.id ]
      this.children.forEach(childId => {
        if(node.depth < maxDepth) subTree = subTree.concat(that.getNodeById(childId).getSubTreeNodesForTree(maxDepth))
      })
      return subTree
    }
    getSubTreeNodesEdges() {
      const subTreeNodesEdges = []
      const visitNode = (nodeId) => {
        const node = that.getNodeById(nodeId)
        if (node.fatherId !== 'root') subTreeNodesEdges.push([ node.fatherId, nodeId ])
        node.children.forEach(childId => visitNode(childId))
      }
      this.children.forEach(childId => visitNode(childId))
      return subTreeNodesEdges
    }
    getSubTreeBlocksEdges() {
      const subTreeNodesEdges = this.getSubTreeNodesEdges()
      const subTreeBlocksEdges = []
      subTreeNodesEdges.forEach(nodesEdge => {
        const sourceNode = that.getNodeById(nodesEdge[0])
        const targetNode = that.getNodeById(nodesEdge[1])
        subTreeBlocksEdges.push([ sourceNode.blocks[sourceNode.blocks.length - 1], targetNode.blocks[0] ])
        for (let blockIndex = 0; blockIndex < targetNode.blocks.length - 1; blockIndex++) {
          subTreeBlocksEdges.push([ targetNode.blocks[blockIndex], targetNode.blocks[blockIndex + 1] ])
        }
      })
      return subTreeBlocksEdges
    }
    getSubPathsNodes(filters = null) {
      const subPathsNodes = []
      const visitChild = (path, nodeId) => {
        const node = that.getNodeById(nodeId)
        if (node.children.length === 0) {
          const leaf = that.getLeafById(nodeId)
          if (filters === null || leaf.checkFilters(filters)) subPathsNodes.push(path.concat([ nodeId ]))
        }
        else {
          node.children.forEach(childId => {
            visitChild(path.concat([ nodeId ]), childId)
          })
        }
      }
      this.children.forEach(childId => {
        visitChild([ this.id ], childId)
      })
      return subPathsNodes
    }
    getSubPathsBlocks(filters = null) {
      const subPathsNodes = this.getSubPathsNodes(filters)
      const subPathsBlocks = subPathsNodes.map(pathNodes => {
        const pathBlocks = []
        pathNodes.forEach((nodeId, nodeIndex) => {
          const node = that.getNodeById(nodeId)
          if (nodeIndex === 0) pathBlocks.push(node.blocks[node.blocks.length - 1])
          else pathBlocks.push(...node.blocks)
        })
        return pathBlocks
      })
      return subPathsBlocks
    }
  }
  this.VirtualNode = class extends this.Node{
    constructor(fatherId){
      super({id:"virtualnode-" + fatherId, father_id: fatherId})
      this.virtualNode = true;
    }
  }
  this.Leaf = class {
    constructor(json) {
      this.id = json.id.toString()
      this.numBlocks = json.executed_basic_blocks
      this.numBlocksUnique = json.executed_basic_blocks_unique
      this.maxRepBlock = json.max_rep_basic_block
      this.numConstraints = json.num_constraints
      this.mappedPages = json.mapped_pages
      this.symbolicPages = json.symbolic_pages
      this.generatedSymbols = json.generated_symbols
      this.numMallocFree = json.num_malloc_free
    }
    checkFilters(filters) {
      let check = true
      Object.keys(filters).forEach(filterKey => {
        if (filters[filterKey] !== null) {
          if (this[filterKey] < filters[filterKey][0] || this[filterKey] > filters[filterKey][1]) check = false
        }
      })
      return check
    }
  }
  this.Symbol = class {
    constructor(json) {
      this.id = json.id.toString()
      this.creationInfo = json.creation_info.toString()
      this.creationNode = (json.creation_node_id === 0 || that.getNodeById(json.creation_node_id) === undefined) ? false : json.creation_node_id.toString()
      this.creationBlock = (json.creation_node_id === 0 || that.getNodeById(json.creation_node_id) === undefined) === 0 ? false : json.creation_block_id.toString()
      this.size = parseInt(json.size)
      this.category = json.category.toString().toLowerCase()
    }
  }
  this.BlockFilter = class {
    constructor(json, type) {
      this.el = "block"
      this.id = `${json.block_id.toString()}-${type}`
      this.blockId = json.block_id.toString()
      this.type = type
      this.coverageLoss = json.coverage_loss
      this.treeReduction = json.tree_reduction
    }
    elementStr() {
      return "Block <br>[" + that.getBlockAddressById(this.blockId) + "]"
    }
  }
  this.EdgeFilter = class {
    constructor(json, type) {
      this.el = "edge"
      this.id = `${json.src.toString()}-${json.dst.toString()}-${type}`
      this.srcBlockId = json.src.toString()
      this.dstBlockId = json.dst.toString()
      this.srcFunctionId = that.getBlockById(json.src).functionId
      this.dstFunctionId = that.getBlockById(json.dst).functionId
      this.type = type
      this.coverageLoss = json.coverage_loss,
      this.treeReduction = json.tree_reduction
    }
    elementStr() {
      return "Edge <br>[" + that.getBlockAddressById(this.srcBlockId) + ", " + that.getBlockAddressById(this.dstBlockId) + "]"
    }
  }
  return(this)
}).call({})
