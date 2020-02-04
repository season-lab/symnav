if (window.system == undefined) window.system = {}
system.state = (function() {
  const that = this
  const treeMaxDepth = 6
  this.currentFunctions = []
  this.currentFunctionsIndex = -1
  this.currentNode = null
  this.symbTreeFilters = []
  this.pathsFilters = {
    numBlocks: null,
    numBlocksUnique: null,
    maxRepBlock: null,
    numConstraints: null,
    mappedPages: null,
    symbolicPages: null
  }
  this.selectedForkingBlocks = []
  this.selectedForkingSymbols = []
  this.graphLayers = {
    node: true,
    path: true,
    subtree: true,
    callees: true,
    callers: true
  }
  /*
  */
  this.init = () => {
    this.setCurrentNode()
    system.paths.drawParCoords()
    system.filters.update()
  }
  /*
  */
  this.setCurrentNode = (nodeId = undefined, afterUpdate = true) => {
    if (nodeId == undefined || nodeId == null) {
      this.resetCurrentNode(false)
    }
    else {
      this.currentNode = nodeId
      const node = system.data.getNodeById(nodeId)
      const block = system.data.getBlockById(node.blocks[node.blocks.length - 1])
      const functionId = block.functionId
      this.currentFunctions = [ functionId ]
      this.currentFunctionsIndex = 0
    }
    if (afterUpdate) this.afterUpdate('currentGraph')
    if (afterUpdate) this.afterUpdate('currentNode')
  }
  this.resetCurrentNode = (afterUpdate = true) => {
    this.currentNode = null
    this.resetCurrentFunction(false)
    this.resetSelectedForkingBlocks(false)
    if (afterUpdate) this.afterUpdate('currentGraph')
    if (afterUpdate) this.afterUpdate('currentNode')
  }
  this.setCurrentFunction = (functionId = undefined, afterUpdate = true) => {
    if (functionId === undefined) functionId = system.data.binary.entryFunction
    if (this.currentFunctions.includes(functionId)) {
      this.currentFunctionsIndex = this.currentFunctions.indexOf(functionId)
      // if(this.currentFunctionsIndex == 0) this.currentFunctions = [this.currentFunctions[0]]
    }
    else {
      this.currentFunctions.push(functionId)
      this.currentFunctionsIndex = this.currentFunctions.length - 1
    }
    if (afterUpdate) this.afterUpdate('currentGraph')
  }
  this.resetCurrentFunction = (afterUpdate = true) => {
    this.currentFunctions = [ system.data.binary.entryFunction ]
    this.currentFunctionsIndex = 0
    if (afterUpdate) this.afterUpdate('currentGraph')
  }
  /*
  */
  this.updatePathsFilter = (filterId, min, max, afterUpdate = true) => {
    this.pathsFilters[filterId] = [min, max]
    // TODO: substitute graph redraw with graph update
    if (afterUpdate) this.afterUpdate('currentGraph')
    if (afterUpdate) this.afterUpdate('currentNode')
  }
  this.resetPathsFilter = (filterId, afterUpdate = true) => {
    this.pathsFilters[filterId] = null
    // TODO: substitute graph redraw with graph update
    if (afterUpdate) this.afterUpdate('currentGraph')
    if (afterUpdate) this.afterUpdate('currentNode')
  }
  /*
  */
  this.addSymbTreeFilter = (filter, afterUpdate = true) => {
    this.symbTreeFilters.push(filter)
    if (afterUpdate) this.afterUpdate('symbTreeFilter')
  }
  this.removeSymbTreeFilter = (filterIndex, afterUpdate = true) => {
    /*if(Array.isArray(filterIndex)){
      this.symbTreeFilters = this.symbTreeFilters.filter((d, i) => { 
        return !filterIndex.includes(i)
      })
    }
    else*/
    this.symbTreeFilters.splice(filterIndex, 1)
    if (afterUpdate) this.afterUpdate('symbTreeFilter')
  }
  this.resetSymbTreeFilters = (afterUpdate = true) => {
    this.symbTreeFilters = []
    if (afterUpdate) this.afterUpdate('symbTreeFilter')
  }
  /*
  */
  this.addSelectedForkingBlock = (blockId, afterUpdate = true) => {
    this.selectedForkingBlocks.push(blockId)
    if (afterUpdate) this.afterUpdate('selectedForkingBlocks')
  }
  this.removeSelectedForkingBlock = (blockId, afterUpdate = true) => {
    this.selectedForkingBlocks.splice(this.selectedForkingBlocks.indexOf(blockId), 1)
    if (afterUpdate) this.afterUpdate('selectedForkingBlocks')
  }
  this.resetSelectedForkingBlocks = (afterUpdate = true) => {
    this.selectedForkingBlocks = []
    if (afterUpdate) this.afterUpdate('selectedForkingBlocks')
  }
  /*
  */
  this.addSelectedForkingSymbol = (symbolId, afterUpdate = true) => {
    this.selectedForkingSymbols.push(symbolId)
    if (afterUpdate) this.afterUpdate('selectedForkingSymbols')
  }
  this.removeSelectedForkingSymbol = (symbolId, afterUpdate = true) => {
    this.selectedForkingSymbols.splice(this.selectedForkingSymbols.indexOf(symbolId), 1)
    if (afterUpdate) this.afterUpdate('selectedForkingSymbols')
  }
  this.resetSelectedForkingSymbols = (afterUpdate = true) => {
    this.selectedForkingSymbols = []
    if (afterUpdate) this.afterUpdate('selectedForkingSymbols')
  }
  /*
  */
  this.setGraphLayer = (name, visible, afterUpdate = true) => {
    this.graphLayers[name] = visible;
    if (afterUpdate) this.afterUpdate('graphLayers')
  }
  /*
  */
  this.highlightNodes = (nodesId, highlight = true) => {
    system.tree.highlightNodes(nodesId, highlight)
  }
  /*
  */
  this.afterUpdate = (updateFunction) => {
    switch (updateFunction) {
      case 'currentGraph':
        if (this.currentNode === null) {
          system.cfg.drawGraph(this.currentFunctions.map(functionId => {
            const func = system.data.getFunctionById(functionId)
            return func.getCfg(functionId)
          }), this.currentFunctionsIndex)
        }
        else system.cfg.drawGraph(this.currentFunctions.map(functionId => system.data.getGraph(functionId, this.currentNode, this.pathsFilters)), this.currentFunctionsIndex)
        //system.cfg.drawGraph(this.currentFunctions.map(functionId => system.data.getGraph(functionId, this.currentNodes[this.currentNodes.length - 1])), this.currentFunctionsIndex)
        break
      case 'currentNode':
        const currentTree = system.data.getTree((this.currentNode === null) ? system.data.symbTree.rootNode : this.currentNode, this.pathsFilters, treeMaxDepth)
        const totalTree = system.data.getTree(system.data.symbTree.rootNode, this.pathsFilters)
        system.tree.drawTree(currentTree, this.currentNode)
        system.tree.drawTreeOverview(totalTree, this.currentNode)
        system.tree.drawTreeLegend()
        if (this.currentNode !== null) {
          system.stats.update()
        }
        else {
          system.stats.reset()
        }
        break
      case 'graphLayers':
        system.cfg.updateGraph()
        break
      case 'selectedForkingBlocks':
        system.tree.updateTreeLegend()
        break
      case 'symbTreeFilter':
        system.api.pruneTree()
        system.filters.update()
        break
      case 'selectedForkingSymbols':
        system.tree.updateTreeLegend()
        break
      default:
        break
    }
  }
  return this
}).call({})