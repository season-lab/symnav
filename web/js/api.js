if (window.system == undefined) window.system = {}
system.api = (function() {
  /*
  */
  this.pruneTree = async (commit = false) => {
    this.waitTree(commit)
    const tree = await eel.prune_tree(system.state.symbTreeFilters, commit)()
    this.newTree(tree)
  }
  /*
  */
 this.continueExploration = async (time = 0, memory = 0) => {
   this.waitTree(true)
   const computationConfig = {
     time: time,
     memory: memory
   }
   const tree = await eel.continue_exploration(system.state.symbTreeFilters, computationConfig)()
   this.newTree(tree)
 }
  /*
  */
  this.waitTree = (commit) => {
    if (commit) console.log('Waiting for a new fancy tree!')
    else console.log('Waiting for a sub-tree!')
    system.layout.lockUI()
  }
  /*
  */
  this.newTree = (tree) => {
    return new Promise((resolve, reject) => {
      try {
        const { symbolic_tree, coverage_loss, symbols, leaves } = tree
        system.state.resetCurrentNode()
        system.data.resetSymbolicTree()
          .then(() => system.data.resetCoverageLoss())
          .then(() => system.data.resetSymbols())
          .then(() => system.data.resetLeaves())
          .then(() => system.data.loadSymbolicTree(symbolic_tree))
          .then(() => system.data.loadCoverageLoss(coverage_loss))
          .then(() => system.data.loadSymbols(symbols))
          .then(() => system.data.loadLeaves(leaves))
          .then(() => { 
            system.state.init(); 
            system.stats.init();
            system.filters.update();
            system.layout.unlockUI() 
          })
          .then(() => resolve(true))
      }
      catch (error) {
        reject(error)
      }
    })
    
  }
  /* SymbTreeFilters
  */
  this.filterBlock = (blockId, mode, count = null) => {
    console.log(count)
    let countMode = null
    if (count === null) {
      countMode = mode === 'white' ? 1 : 0
    }
    system.state.addSymbTreeFilter({
      type: 'filter_block',
      block_id: blockId,
      mode: mode,
      count: countMode === null ? count : countMode,
      elementStr: "Block <br>[" + system.data.getBlockAddressById(blockId) + "]"
    })
    this.pruneTree()
  }
  this.filterEdge = (srcId, trgId, mode, count = null) => {
    let countMode = null
    if (count === null) {
      countMode = mode === 'white' ? 1 : 0
    }
    system.state.addSymbTreeFilter({
      type: 'filter_edge', 
      src_id: srcId,
      dst_id: trgId,
      mode: mode,
      count: countMode === null ? count : countMode,
      elementStr: "Edge <br>[" + system.data.getBlockAddressById(srcId) + ", " + system.data.getBlockAddressById(trgId) + "]"
    })
    this.pruneTree()
  }
  this.limitFork = (blockId, numFork, inverted = false, forkChoice = null) => {
    if (forkChoice !== null) {
      system.state.addSymbTreeFilter({
        type: 'limit_fork', 
        block_id: blockId,
        num_fork: numFork,
        inverted: inverted,
        fork_choice: forkChoice,
        elementStr: "Block <br>[" + system.data.getBlockAddressById(blockId) + "]"
      })
    }
    else {
      system.state.addSymbTreeFilter({
        type: 'limit_fork', 
        block_id: blockId,
        num_fork: numFork,
        inverted: inverted,
        elementStr: "Block <br>[" + system.data.getBlockAddressById(blockId) + "]"
      })
    }
    this.pruneTree()
  }
  this.limitSymbol = (symbolId, min, max) => {
    system.state.addSymbTreeFilter({
      type: 'limit_symbol', 
      symbol_id: symbolId,
      min: min,
      max: max,
      elementStr: "--- da finire ---"
    })
    this.pruneTree()
  }
  return this
}).call({})
