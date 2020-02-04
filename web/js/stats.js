if (window.system == undefined) window.system = {}
system.stats = (function() {
  const that = this
  this.paths = {
    whole: 0,
    current: 0
  }
  this.nodes = {
    whole: 0,
    current: 0
  }
  this.blocks = {
    whole: 0,
    current: 0
  }
  this.symbols = {
    whole: 0,
    current: 0
  }
  this.init = () => {
    const rootNode = system.data.getNodeById(system.data.symbTree.rootNode)
    const paths = rootNode.getSubPathsNodes().length
    this.paths.whole = paths
    this.paths.current = paths
    const nodes = rootNode.getSubTreeNodes().length
    this.nodes.whole = nodes
    this.nodes.current = nodes
    const blocks = rootNode.getSubTreeBlocks().length
    this.blocks.whole = blocks
    this.blocks.current = blocks
    const symbols = system.data.getForkingSymbols(rootNode.id).length
    this.symbols.whole = symbols
    this.symbols.current = symbols
    this.draw()
  }
  this.update = () => {
    const currentNode = system.data.getNodeById(system.state.currentNode)
    this.paths.current = currentNode.getSubPathsNodes(system.state.pathsFilters).length
    this.nodes.current = currentNode.getSubTreeNodes(system.state.pathsFilters).length
    this.blocks.current = currentNode.getSubTreeBlocks(system.state.pathsFilters).length
    this.symbols.current = system.data.getForkingSymbols(currentNode.id, system.state.pathsFilters).length
    this.draw()
  }
  this.reset = () => {
    this.paths.current = this.paths.whole
    this.nodes.current = this.nodes.whole
    this.blocks.current = this.blocks.whole
    this.symbols.current = this.symbols.whole
    this.draw()
  }
  this.draw = () => {
    const div = d3.select('#tree-stats')
    div.selectAll('*').remove()
    const entries = [
      {
        key: 'nodes',
        label: 'Nodes'
      },
      {
        key: 'blocks',
        label: 'Blocks'
      },
      {
        key: 'paths',
        label: 'Paths'
      },
      {
        key: 'symbols',
        label: 'Symbols'
      }
    ]
    entries.forEach(e => {
      const container = div.append('div').attr('class', 'stats-entry-container')
      container.append('div').text(e.label).attr('class', 'stats-entry-label')
      const numbers = container.append('div').attr('class', 'stats-entry-numbers')
      numbers.append('span').text(this[e.key].current).attr('class', 'stats-entry-current')
      numbers.append('span').text(`/ ${this[e.key].whole}`).attr('class', 'stats-entry-whole')
    })
  }
  return(this)
}).call({})