if(window.system == undefined) window.system = {}
system.paths = (new class {
  constructor() {
    this.parcoordsContainer = d3.select('#paths-container')
    this.parcoords = ParCoords()('#paths-container')
  }

  prepareData() {
    this.parcoords
      .data(system.data.leaves)
      .dimensions({
        numBlocks: { title: 'Blocks', type: 'number' },
        numBlocksUnique: { title: 'Unique Blocks', type: 'number' },
        maxRepBlock: { title: 'Rep. Block', type: 'number' },
        numConstraints: { title: 'Constraints', type: 'number' },
        mappedPages: { title: 'Pages', type: 'number' },
        symbolicPages: { title: 'Symb. Pages', type: 'number' },
        generatedSymbols: { title: 'Gen. Symbols', type: 'number' },
        numMallocFree: { title: 'Malloc Free', type: 'number' }
      })
      .margin({
        top: 60,
        left: 20,
        right: 20,
        bottom: 12
      })
      .on('brushend', (brushed, args) => {
        if (args.selection.scaled.length === 0) system.state.resetPathsFilter(args.axis)
        else system.state.updatePathsFilter(args.axis, args.selection.scaled[1], args.selection.scaled[0])
      })
      
  }
  drawParCoords() {
    this.prepareData()
    this.parcoords
      .render()
      .shadows()
      .reorderable()
      .interactive()
      .brushMode('1D-axes')
    this.parcoordsContainer.selectAll('.label').attr('transform', function() { return `${d3.select(this).attr('transform')} translate(0, -20) rotate(-45)` })
    if (Object.values(system.state.pathsFilters).filter(v => v !== null).length > 0) {
      const extentsKeys = Object.keys(system.state.pathsFilters).filter(k => system.state.pathsFilters[k] !== null)
      const extents = pick(system.state.pathsFilters, extentsKeys)
      this.parcoords.brushExtents(extents)
    }
  }
  hideParCoords() {
    this.parcoordsContainer.selectAll('*').style('visibility', 'hidden')
  }
  updateParCoords() {
    this.parcoordsContainer.selectAll('*').remove()
    this.parcoords = ParCoords()('#paths-container')
    this.drawParCoords()
    //this.parcoords.width(this.parcoordsContainer.node().getBoundingClientRect().width).resize().render()
  }

}())