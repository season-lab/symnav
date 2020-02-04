if (window.system == undefined) window.system = {};
system.cfg = (new class {

  constructor() {
    var that = this;

    this.svg = d3.select("#cfg").select("svg");
    this.width = this.svg.node().getBoundingClientRect().width;
    this.height = this.svg.node().getBoundingClientRect().height;
    this.title = d3.select("#cfg-title");

    this.container = this.svg.append("g");
    this.historyDiv = d3.select("#cfg-history");

    this.zoom = d3.zoom()
      //.scaleExtent([0.1, 25])
      //.translateExtent([[-10 * that.width, -10 * that.height], [10 * that.width, 10 * that.height]])
      .on("zoom", function () {
        that.container.attr("transform", d3.event.transform);
      });
    that.svg.call(this.zoom);


    this.currentGraph = undefined;
    this.historyGraphs = undefined;
    this.currentGraphIndex = undefined;

    this.nodesIndexById= {};
    this.edgesIndexById = {};
    this.dagreGraph = undefined;
    this.dagreRender = undefined;

    this.graphOptions = function() {
      return {
        rankdir: 'TB', // 'TB'
        align: 'UL', // undefined
        nodesep: 40, // 50
        edgesep: 30, // 10
        ranksep: 20, // 50,
        ranker: 'tight-tree' // 'network-simplex', 'tight-tree', longest-path'
      }
    }

    this.nodeSizes = function(v){
      return {
        label: 16,
        code: 22,
        padding: 10, //fixed by dagree
        collapsedWidth: (v.type == "block") ? 150 : 50,
        collapsedHeight: (v.type == "block") ? 70 : 50,
        expandedWidth: 400,
        expandedHeight: 400,
        forksBar: 15,
        symbolsBar: 15,
        border: 5,
      }
    }

    d3.select("#cfg-expand-all").on("click", function(){
      that.currentGraph.vertices.forEach(function(v){
        v.svg.expand(false);
      })
      that.dagreRender(that.container, that.dagreGraph);
      that._centerCurrentGraph()
    }).each(function(){ tippy(this, {content: "Expand All", arrow: true, placement: 'right'})});

    d3.select("#cfg-collapse-all").on("click", function(){
      that.currentGraph.vertices.forEach(function(v){
        v.svg.collapse(false);
      })
      that.dagreRender(that.container, that.dagreGraph);
      that._centerCurrentGraph()
    }).each(function(){ tippy(this, {content: "Collapse All", arrow: true, placement: 'right'})});

    this.verticesScales = {
      forksBarHeight: d3.scaleLinear().range([5, that.nodeSizes({type:"block"}).collapsedHeight - 2*that.nodeSizes({type:"block"}).border ]),
      forksColor: system.colors.cfgForksColor().forceOut(system.colors.cfgForksColorFixed),
      symbolsBarHeight: d3.scaleLinear().range([5, that.nodeSizes({type:"block"}).collapsedHeight - 2*that.nodeSizes({type:"block"}).border]),
      symbolsColor: system.colors.cfgSymbolsColor().forceOut(system.colors.cfgSymbolsColorFixed),
    }
    this.edgeScales = {
      tickness: d3.scaleLinear().range([3, 16]),
      color: system.colors.cfgEdgeColor(),
      markerSize: d3.scaleLog().domain([5, 20]).range([6, 2]),
    }

    /*
    */
    d3.select("#cfg-checkboxes").selectAll("input")
      .each(function(){
        var name = d3.select(this).property("name");
        d3.select(this).property("checked", system.state.graphLayers[name]);
      })
      .on("change", function(){
        var name = d3.select(this).property("name");
        var selected = d3.select(this).property("checked");
        system.state.setGraphLayer(name, selected)
      })
  }

  setScales(){
    var that = this;
    this.verticesScales.forksColor.domain([0, d3.max(that.currentGraph.vertices, function(v){
      return that.getVertexForksValue(v);
    })]);
    this.verticesScales.forksBarHeight.domain([0, d3.max(that.currentGraph.vertices, function(v){
      return that.getVertexForksValue(v);
    })]);
    this.verticesScales.symbolsColor.domain([0, d3.max(that.currentGraph.vertices, function(v){
      return that.getVertexSymbolsValue(v);
    })]);
    this.verticesScales.symbolsBarHeight.domain([0, d3.max(that.currentGraph.vertices, function(v){
      return that.getVertexSymbolsValue(v);
    })]);
    this.edgeScales.tickness.domain(d3.extent(that.currentGraph.edges, function(e){
      if(e.type != "blockBlock") return 0;
      return that.getEdgeTicknessValue(e);
    }));
    this.edgeScales.color.domain([0, 1]);
  }
  
  getEdgeColorValue(e){
    var valTot = 0.0;
    if(system.state.graphLayers.node) valTot += e.nodePath * Math.max(this.currentGraph.numSubPaths, 1);
    if(system.state.graphLayers.path) valTot += e.backPath * Math.max(this.currentGraph.numSubPaths, 1);
    if(system.state.graphLayers.subtree) valTot += e.subPaths;
    
    var valUniq = 0.0;
    if(system.state.graphLayers.node) valUniq += e.nodePathUnique * Math.max(this.currentGraph.numSubPaths, 1);
    if(system.state.graphLayers.path) valUniq += e.backPathUnique * Math.max(this.currentGraph.numSubPaths, 1);
    if(system.state.graphLayers.subtree) valUniq += e.subPathsUnique;

    return (valTot == 0) ? 0 : valUniq / valTot
  }

  getEdgeTicknessValue(e){
    var val = 0;
    if(system.state.graphLayers.node) val += e.nodePath * Math.max(this.currentGraph.numSubPaths, 1);
    if(system.state.graphLayers.path) val += e.backPath * Math.max(this.currentGraph.numSubPaths, 1);
    if(system.state.graphLayers.subtree) val += e.subPaths;
    return val;
  }

  getVertexPathsValue(v){
    if(v.nodePath == undefined) return 0;
    var val = 0;
    if(system.state.graphLayers.node) val += v.nodePath.count;
    if(system.state.graphLayers.path) val += v.backPath.count;
    if(system.state.graphLayers.subtree) val += v.subPaths.count;
    return val;
  }

  getFunctionPathsValue(v){
    // TODO: 
    var val = {
      in: 0,
      out: 0
    };
    if(v.nodePath == undefined) return val;
    if(v.type == "callee"){
      if(system.state.graphLayers.node) val.in += v.nodePath.in;
      if(system.state.graphLayers.path) val.in += v.backPath.in;
      if(system.state.graphLayers.subtree) val.in += v.subPaths.in;

      if(system.state.graphLayers.node) val.out += v.nodePath.out;
      if(system.state.graphLayers.path) val.out += v.backPath.out;
      if(system.state.graphLayers.subtree) val.out += v.subPaths.out;
    }

    if(v.type == "caller" || v.type == "callre"){
      var callerId = v.id.split("-")[0] + "-caller-"// + v.id.split("-")[2];
      var callreId = v.id.split("-")[0] + "-callre-"// + v.id.split("-")[2];

      var caller = this.currentGraph.vertices.filter(d => { return d.id.includes( callerId)});
      var callre = this.currentGraph.vertices.filter(d => { return d.id.includes(callreId)});

      if(caller.length == 0 || callre == 0){
        val.in = 0;
        val.out = -1;
        return val;
      }
      
      caller = caller[0];
      callre = callre[0];

      if(system.state.graphLayers.node) val.in += callre.nodePath.in;
      if(system.state.graphLayers.path) val.in += callre.backPath.in;
      if(system.state.graphLayers.subtree) val.in += callre.subPaths.in;

      if(system.state.graphLayers.node) val.out += caller.nodePath.out;
      if(system.state.graphLayers.path) val.out += caller.backPath.out;
      if(system.state.graphLayers.subtree) val.out += caller.subPaths.out;
    }
    return val;
  }

  getVertexNodePathsValue(v){
    if(v.nodePath == undefined) return 0;
    var val = 0;
    if(system.state.graphLayers.node) val += v.nodePath.count;
    return val;
  }

  getVertexForksValue(v){
    var val = 0;
    if(v.nodePath == undefined || v.nodePath.forkNodes == undefined) return 0;
    if(system.state.graphLayers.node) val += v.nodePath.forkNodes.length;
    if(system.state.graphLayers.path) val += v.backPath.forkNodes.length;
    if(system.state.graphLayers.subtree) val += v.subPaths.forkNodes.length;
    return val;
  }

  getVertexSymbolsValue(v){
    var val = 0;
    if(v.nodePath == undefined || v.nodePath.generatedSymbols == undefined) return 0;
    if(system.state.graphLayers.node) val += v.nodePath.generatedSymbols.length;
    if(system.state.graphLayers.path) val += v.backPath.generatedSymbols.length;
    if(system.state.graphLayers.subtree) val += v.subPaths.generatedSymbols.length;
    return val;
  }

  getEdgeColor(e){
    if(this.getEdgeColorValue(e) == 0) return null
    return this.edgeScales.color(this.getEdgeColorValue(e))
  }

  getEdgeTickness(e){
    if(this.getEdgeTicknessValue(e) == 0) return 1
    if(this.edgeScales.tickness.domain()[0] == this.edgeScales.tickness.domain()[1]) return this.edgeScales.tickness.range()[0]
    return this.edgeScales.tickness(this.getEdgeTicknessValue(e))
  }

  getEdgeArrowSize(e){
    return this.edgeScales.markerSize(this.getEdgeTickness(e)) 
  }

  getVertexForksColor(v){
    if(this.getVertexForksValue(v) == 0) return null
    return this.verticesScales.forksColor(this.getVertexForksValue(v))
  }

  getVertexForksBarHeight(v){
    if(this.getVertexForksValue(v) == 0) return null
    return this.verticesScales.forksBarHeight(this.getVertexForksValue(v))
  }

  getVertexSymbolsColor(v){
    if(this.getVertexSymbolsValue(v) == 0) return null
    return this.verticesScales.symbolsColor(this.getVertexSymbolsValue(v))
  }

  getVertexSymbolsBarHeight(v){
    if(this.getVertexSymbolsValue(v) == 0) return null
    return this.verticesScales.symbolsBarHeight(this.getVertexSymbolsValue(v))
  }

  drawGraph(graphs, currentIndex){
    var that = this;
    this.historyGraphs = graphs;
    this.currentGraph = graphs[currentIndex];
    this.currentGraphIndex = currentIndex;
    this.setScales();
    /*
    *
    */
    this._drawHistoryGraphs();
    this._drawCurrentGraph();
    this.drawLegend();
    
    this.title.selectAll("*").remove();
    this.title.append("span").attr("class", "function-name").text(system.data.getFunctionById(this.currentGraph.functionId).name);
    /*if(this.currentGraph.nodeId != undefined){
      this.title.append("span").text("-");
      this.title.append("span").attr("class", "block-name").text(this.currentGraph.nodeId);
    }*/
  }


  _drawCurrentGraph(){
    var that = this;
    this.nodesIndexById = {};
    this.edgesIndexById = {};
    that.currentGraph.edges.forEach(function (e, i) {
      that.edgesIndexById[e.id] = i;
    })
    that.currentGraph.vertices.forEach(function (v, i) {
      that.nodesIndexById[v.id] = i;
    })
    
    if(that.g != undefined) that.g.remove()

    that.container.selectAll("*").remove();
    that.dagreGraph = new dagreD3.graphlib.Graph()
      .setGraph(this.graphOptions())
      .setDefaultEdgeLabel(function () { return {}; });

    that.currentGraph.vertices.forEach(function (v, i) {
      v.svg = {};
      v.obj = (v.type !== "block") ? system.data.getFunctionById(v.functionId) : system.data.getBlockById(v.id);
      (function(){
         
          this.g = undefined;
          this.background = undefined;
          this.gCollapsed = undefined;
          this.gExpanded = undefined;
        
          var isExpanded = false;
          var inTransition = false;
    
          var size = that.nodeSizes(v);
          if(v.type == "block") size.expandedHeight = size.collapsedHeight + (v.obj.code.length + 1) * size.code;

          this.nodeOptions = function() {
            return {
              label: (v.type == "block") ? v.obj.address : "",
              class: v.type, 
              width: v.svg.getSize().width, 
              height: v.svg.getSize().height,
              shape: (v.type == "block") ? "rect" : "circle",
            }
          }
      
          this.getSize = function() {
            return {
              width: (!isExpanded ? size.collapsedWidth : size.expandedWidth) - 2*size.padding,
              height: (!isExpanded ? size.collapsedHeight : size.expandedHeight)  - 2*size.padding
            }
          }

          this.getInnerSize = function() {
            return {
              collapsed: {
                width: size.collapsedWidth - 2*size.border,
                height: size.collapsedHeight - 2*size.border
              },
              expanded: {
                width: size.expandedWidth - 2*size.border,
                height: size.expandedHeight - 2*size.border
              }
            }
          }

          this.getTransform = function() {
            return {
              collapsed: {
                x: (-size.collapsedWidth/2) + size.border,
                y: (-size.collapsedHeight/2) + size.border
              },
              expanded: {
                x: (-size.expandedWidth/2) + size.border,
                y: (-size.expandedHeight/2) + size.border
              }
            }
          }

          this.expand = function(render=true) {
            if(v.type != "block") return;
            isExpanded = true;
            inTransition = true;
            v.svg.g.classed("expanded", true);
            v.svg.g.classed("collapsed", false);
            system.cfg.dagreGraph.setNode(v.id, v.svg.nodeOptions());
            if(render) system.cfg.dagreRender(system.cfg.container, system.cfg.dagreGraph);
          }
        
          this.collapse = function(render=true) {
            if(v.type != "block") return;
            isExpanded = false;
            inTransition = true;
            v.svg.g.classed("expanded", false);
            v.svg.g.classed("collapsed", true);
            system.cfg.dagreGraph.setNode(v.id, v.svg.nodeOptions());
            if(render) system.cfg.dagreRender(system.cfg.container, system.cfg.dagreGraph);
          }
        
          this.beforeTransition = function() {
            v.svg.g.classed("collapsed", !isExpanded);
            v.svg.g.classed("expanded", isExpanded);
            if(!inTransition) return;
            v.svg.gCollapsed.style("display", "none");
            v.svg.gExpanded.style("display", "none");
          }
    
          this.afterTransition = function() {
            v.svg.g.classed("collapsed", !isExpanded);
            v.svg.g.classed("expanded", isExpanded);
            if(v.type == "block"){
              v.svg.g
                .classed("VertexPathsValue", that.getVertexPathsValue(v) > 0)
                .classed("NodePathsValue", that.getVertexNodePathsValue(v) > 0)
            }
            if(!inTransition) return;
            v.svg.gCollapsed.style("display", isExpanded ? "none" : null);
            v.svg.gExpanded.style("display",  isExpanded ? null : "none");
            inTransition = false;
            this.update()
          }

          this.init = function(element) {
            v.svg.g = d3.select(element).attr("type", v.type).style("opacity", 1);
            v.svg.shape = v.svg.g.select(".shape")//.style("display", "none");

            
            v.svg.g
              //.on("mouseover", d => console.log(system.cfg.currentGraph.vertices.filter(v => v.id === d)[0]))
              .on("click", function () {
                if(v.type !== "block"){
                  system.state.setCurrentFunction(v.functionId)
                  return;
                }
                
                if(isExpanded && d3.select(d3.event.srcElement).classed("label-background") || !isExpanded){
                  if(isExpanded) v.svg.collapse();
                  else v.svg.expand();
                }
              })
              /*
              .on("mouseover", () => {
                if(v.type !== "block") return;
                system.state.highlightNodes(v.obj.nodes, true)
              })
              .on("mouseout", () => {
                if(v.type !== "block") return;
                system.state.highlightNodes(null, false)
              })
              */
              .each(function(){
                if (v.__proto__.constructor.name == "Vertex"){
                  
                  if(v.type == "block"){
                    const containerEl = document.createElement('div')
                    const container = d3.select(containerEl)
                      .attrs({
                        class: 'cfgBlockTipContainer',
                        id: `cfgBlockTipContainer-${v.id}`
                      })
                    
                    container.append('div').attr('class', 'cfg-tip-label').text(v.obj.address)

                    const singlePaths = [
                      {
                        type: 'backPath',
                        label: 'Path'
                      },
                      {
                        type: 'nodePath',
                        label: 'Node'
                      }
                    ]
                    const statsTable = container.append('table').attr('class', 'cfg-tip-stats')
                    singlePaths.forEach(path => {
                      let row = statsTable.append('tr')
                      row.append('td').text(path.label)
                      row.append('td').append('span').append('i')
                        .attr('class', `fas ${v[path.type].countUnique > 0 ? 'fa-check' : 'fa-times'}`)
                        row.append('td').text(() => v[path.type].count > 0 ? v[path.type].count : '')
                    })
                    const statsSubtree = statsTable.append('tr')
                    statsSubtree.append('td').text('Subtree')
                    const statsSubtreeCount = statsSubtree.append('td')
                    if (v.subPaths.countUnique > 0) statsSubtreeCount.text(v.subPaths.countUnique)
                    else statsSubtreeCount.append('span').append('i').attr('class', 'fas fa-times')
                    statsSubtree.append('td').text(v.subPaths.count)
                    
                    const filtersContainer = container.append('div').attr('class', 'cfg-tip-filters-cont')
                    filtersContainer.append('div').text('Filters').styles({
                      'font-size': '16px',
                      
                    })

                    const filters = [
                      {
                        type: 'white',
                        label: 'Include',
                        filter: system.data.getBlockWhiteFilterByBlockId(v.id),
                        call: (count) => system.api.filterBlock(v.id, 'white', count)
                      },
                      {
                        type: 'black',
                        label: 'Exclude',
                        filter: system.data.getBlockBlackFilterByBlockId(v.id),
                        call: (count) => system.api.filterBlock(v.id, 'black', count)
                      },
                      {
                        type: 'limit',
                        label: 'Limit',
                        filter: null,
                        call: (numFork, inverted, forkChoice) => system.api.limitFork(v.id, numFork, inverted, forkChoice)
                      }
                    ]
                    filters.forEach(f => {
                      let filterContainer = filtersContainer.append('div').attr('class', 'cfg-tip-fil-cont')
                      let filterHead = filterContainer.append('div').attr('class', 'cfg-tip-fil-head')
                      let filterDetails = filterContainer.append('div').style('display', 'none').attr('class', 'cfg-tip-fil-details')
                      filterHead
                        .append('div')
                          .attr('class', 'cfg-tip-fil-trig')
                          .on('click', () => filterDetails.style('display', filterDetails.style('display') === 'none' ? 'block' : 'none'))
                        .append('i')
                          .attr('class', 'fas fa-angle-down')
                      filterHead
                        .append('div').text(f.label)
                          .attr('class', 'cfg-tip-fil-label')
                      if (['white', 'black'].indexOf(f.type) >= 0) {
                        filterHead
                          .append('div')
                            .attr('class', 'cfg-tip-fil-cov')
                            .text(() => f.filter !== undefined ? `${f.filter.coverageLoss} %` : '')
                        filterHead
                          .append('div')
                            .attr('class', 'cfg-tip-fil-red')
                            .text(() => f.filter !== undefined ? `${f.filter.treeReduction} %` : '')
                        filterHead
                          .append('div')
                            .attr('class', 'cfg-tip-fil-apply')
                            .on('click', () => f.call(d3.select(`#${v.id}-${f.type}-count`).property('value')))
                          .append('i')
                            .attr('class', 'fas fa-filter')
                        filterDetails.append('label').attrs({
                          for: `${v.id}-${f.type}-count`
                        }).text('Count: ')
                        filterDetails.append('input').attrs({
                          type: 'number',
                          min: 0,
                          value: f.type === 'white' ? 1 : 0,
                          id: `${v.id}-${f.type}-count`
                        })
                        .styles({
                          'max-width': '30px',
                          'margin': '0.1rem 0.6rem 0.1rem 0.3rem'
                        })
                      }
                      else if (f.type === 'limit') {
                        filterHead.append('div').attr('class', 'cfg-tip-fil-cov')
                        filterHead.append('div').attr('class', 'cfg-tip-fil-red')
                        filterHead
                          .append('div')
                            .attr('class', 'cfg-tip-fil-apply')
                            .on('click', () => {
                              let numFork = d3.select(`#${v.id}-${f.type}-numFork`).property('value')
                              let inverted = d3.select(`#${v.id}-${f.type}-inverted`).property('checked')
                              let forkChoice = d3.select(`#${v.id}-${f.type}-branch`).property('value')
                              if (forkChoice === 'empty') forkChoice = null 
                              f.call(numFork, inverted, forkChoice)
                            })
                          .append('i')
                            .attr('class', 'fas fa-filter')
                        
                        const filterCount = filterDetails.append('div')
                        .styles({
                          'display': 'flex',
                          'flex-direction': 'row',
                          'align-items': 'center'
                        })
                        filterCount.append('label').attrs({
                          for: `${v.id}-${f.type}-numFork`
                        }).text('Count: ')
                        filterCount.append('input').attrs({
                          type: 'number',
                          min: 0,
                          value: f.type === 'white' ? 1 : 0,
                          id: `${v.id}-${f.type}-numFork`
                        }).styles({
                          'max-width': '30px',
                          'margin': '0.1rem 0.6rem 0.1rem 0.3rem'
                        })
                        filterCount.append('span').text('Inverted: ')
                        const invLabel = filterCount.append('label').attrs({
                          class: 'switch',
                          for: `${v.id}-${f.type}-inverted`
                        })
                        invLabel.append('input').attrs({
                          type: 'checkbox',
                          id: `${v.id}-${f.type}-inverted`
                        })
                        invLabel.append('span').attr('class', 'slider')

                        const filterBranch = filterDetails.append('div')
                        filterBranch.append('label').attrs({
                          for: `${v.id}-${f.type}-branch`
                        }).text('Branch: ')
                        const branchSelect = filterBranch.append('select')
                          .attr('id', `${v.id}-${f.type}-branch`)
                        branchSelect.append('option')
                          .attr('value', 'empty')
                          .text('')
                        v.obj.successors.forEach(suc => {
                          branchSelect.append('option')
                            .attr('value', suc)
                            .text(system.data.getBlockById(suc).address)
                        })
                      }
                    })

                    let refs = [
                      {
                        layer: 'path',
                        prefix: 'backPath',
                        label: 'Path'
                      },
                      {
                        layer: 'node',
                        prefix: 'nodePath',
                        label: 'Node'
                      },
                      {
                        layer: 'subtree',
                        prefix: 'subPaths',
                        label: 'Subtree'
                      }
                    ]

                    let forks = 0
                    if (system.state.graphLayers.path) forks += v.backPath.forkNodes.length
                    if (system.state.graphLayers.node) forks += v.nodePath.forkNodes.length
                    if (system.state.graphLayers.subtree) forks += v.subPaths.forkNodes.length
                    if (forks) {
                      container.append('div')
                        .attr('class', 'cfg-tip-symbols-head-label')
                        .text('Forking Symbols')
                      let forksHeadContainer = container.append('div')
                        .attr('class', 'cfg-tip-symbols-head-cont')
                      let forksTable = forksHeadContainer.append('table')
                      refs.forEach(ref => {
                        if (system.state.graphLayers[ref.layer] && v[ref.prefix].forkNodes.length > 0) {
                          let forksContainer = container.append('div')
                            .attr('class', 'cfg-tip-symbols-cont')
                          forksTable = forksContainer.append('table')
                          forksTable
                            .append('thead')
                            .append('tr')
                            .append('th')
                              .text(ref.label)
                              .attr('colspan', 3)
                          let forksBody = forksTable.append('tbody')
                          let forkSymbols = Object.keys(v[ref.prefix].forkSymbolsBySymbolId)
                            .map(symbolId => ({ 
                              symbolId: symbolId,
                              nodes: v[ref.prefix].forkSymbolsBySymbolId[symbolId] 
                            }))
                            .sort((a, b) => b.nodes.length - a.nodes.length)
                          forkSymbols.forEach(s => {
                            let forkRow = forksBody.append('tr')
                            forkRow.append('td').attr('class', 'cfg-tip-symbols-id').text(s.symbolId)
                            forkRow.append('td').attr('class', 'cfg-tip-symbols-nodes').text(s.nodes.length)
                            let genSymbol = forkRow.append('td').attr('class', 'cfg-tip-symbols-gen')
                            let symbol = system.data.getSymbolById(s.symbolId)
                            if (symbol.creationNode) {
                              genSymbol
                                  .on('click', () => {
                                    let creationBlock = system.data.getBlockById(system.data.getSymbolById(s.symbolId).creationBlock)
                                    let creationFunctionId = creationBlock.functionId
                                    system.state.setCurrentNode(system.data.getSymbolById(s.symbolId).creationNode)
                                    system.state.setCurrentFunction(creationFunctionId)
                                  })
                                  .on('mouseover', () => {
                                    system.state.highlightNodes([system.data.getSymbolById(s.symbolId).creationNode], true)
                                  })
                                  .on('mouseout', () => {
                                    system.state.highlightNodes(null, false)
                                  })
                                .append('i').attr('class', 'fas fa-level-up-alt')
                            }
                          })
                        }
                      })
                    }

                    let genSymbols = 0
                    if (system.state.graphLayers.path) genSymbols += v.backPath.generatedSymbols.length
                    if (system.state.graphLayers.node) genSymbols += v.nodePath.generatedSymbols.length
                    if (system.state.graphLayers.subtree) genSymbols += v.subPaths.generatedSymbols.length
                    if (genSymbols) {
                      container.append('div')
                        .attr('class', 'cfg-tip-symbols-head-label')
                        .text('Generated Symbols')
                      let genHeadContainer = container.append('div')
                        .attr('class', 'cfg-tip-symbols-head-cont')
                      let genTable = genHeadContainer.append('table')
                      refs.forEach(ref => {
                        if (system.state.graphLayers[ref.layer] && v[ref.prefix].generatedSymbols.length > 0) {
                          let genContainer = container.append('div')
                            .attr('class', 'cfg-tip-symbols-cont')
                          genTable = genContainer.append('table')
                          genTable
                            .append('thead')
                            .append('tr')
                            .append('th')
                              .text(ref.label)
                              .attr('colspan', 3)
                          let genBody = genTable.append('tbody')
                          // TODO: clean duplicated symbols
                          const genSymbols = [ ...new Set(v[ref.prefix].generatedSymbols)]
                          genSymbols.forEach(s => {
                            let genRow = genBody.append('tr')
                            genRow.append('td').attr('class', 'cfg-tip-symbols-id').text(s)
                            //genRow.append('td').attr('class', 'cfg-tip-symbols-nodes').text(s.nodes.length)
                            let genSymbol = genRow.append('td').attr('class', 'cfg-tip-symbols-gen')
                            let symbol = system.data.getSymbolById(s)
                            if (symbol.creationNode) {
                              genSymbol
                                  .on('click', () => {
                                    let creationBlock = system.data.getBlockById(system.data.getSymbolById(s).creationBlock)
                                    let creationFunctionId = creationBlock.functionId
                                    system.state.setCurrentNode(system.data.getSymbolById(s).creationNode)
                                    system.state.setCurrentFunction(creationFunctionId)
                                  })
                                  .on('mouseover', () => {
                                    system.state.highlightNodes([system.data.getSymbolById(s).creationNode], true)
                                  })
                                  .on('mouseout', () => {
                                    system.state.highlightNodes(null, false)
                                  })
                                .append('i').attr('class', 'fas fa-level-up-alt')
                            }
                          })
                        }
                      })
                    }
                    
                    tippy(this, {
                      content: '',
                      placement: 'left',
                      boundary: 'viewport',
                      arrow: true,
                      interactive: true,
                      multiple: true,
                      flipOnUpdate: true,
                      onShow: (instance) => instance.setContent(container.node()),
                      onHide: () => { that.tooltipRight = undefined},
                      delay: [500, 200]
                    })
                  }
                  else {
                    //function
                    const containerEl = document.createElement('div')
                    const container = d3.select(containerEl)
                      .attrs({
                        class: 'cfgBlockTipContainer',
                        id: `cfgBlockTipContainer-${v.id}`
                      })
                    
                    container.append('div').attr('class', 'cfg-tip-label').text(v.functionId)

                    const singlePaths = [
                      {
                        type: 'backPath',
                        label: 'Path'
                      },
                      {
                        type: 'nodePath',
                        label: 'Node'
                      }
                    ]
                    if(v.type == "caller"){
                      const statsTable = container.append('table').attr('class', 'cfg-tip-stats')
                      singlePaths.forEach(path => {
                        let row = statsTable.append('tr')
                        row.append('td').text(path.label)
                        row.append('td').append('span').append('i')
                          .attr('class', `fas ${v[path.type].outUnique > 0 ? 'fa-check' : 'fa-times'}`)
                          row.append('td').text(() => v[path.type].out > 0 ? v[path.type].out : '')
                      })
                      const statsSubtree = statsTable.append('tr')
                      statsSubtree.append('td').text('Subtree')
                      const statsSubtreeCount = statsSubtree.append('td')
                      if (v.subPaths.outUnique > 0) statsSubtreeCount.text(v.subPaths.outUnique)
                      else statsSubtreeCount.append('span').append('i').attr('class', 'fas fa-times')
                      statsSubtree.append('td').text(v.subPaths.out)
                    }
                    if(v.type == "callre"){
                      const statsTable = container.append('table').attr('class', 'cfg-tip-stats')
                      singlePaths.forEach(path => {
                        let row = statsTable.append('tr')
                        row.append('td').text(path.label)
                        row.append('td').append('span').append('i')
                          .attr('class', `fas ${v[path.type].inUnique > 0 ? 'fa-check' : 'fa-times'}`)
                          row.append('td').text(() => v[path.type].in > 0 ? v[path.type].in : '')
                      })
                      const statsSubtree = statsTable.append('tr')
                      statsSubtree.append('td').text('Subtree')
                      const statsSubtreeCount = statsSubtree.append('td')
                      if (v.subPaths.inUnique > 0) statsSubtreeCount.text(v.subPaths.inUnique)
                      else statsSubtreeCount.append('span').append('i').attr('class', 'fas fa-times')
                      statsSubtree.append('td').text(v.subPaths.in)
                    }
                    if(v.type == "callee"){
                      const statsTable = container.append('table').attr('class', 'cfg-tip-stats')
                      singlePaths.forEach(path => {
                        let row = statsTable.append('tr')
                        row.append('td').text(path.label)
                        row.append('td').append('span')
                          .append('i').attr('class', `fas ${v[path.type].inUnique > 0 ? 'fa-check' : 'fa-times'}`)
                        row.append('td').text(() => v[path.type].in > 0 ? v[path.type].in : '')
                        row.append('td').text(" / ")
                        row.append('td').append('span')
                          .append('i').attr('class', `fas ${v[path.type].outUnique > 0 ? 'fa-check' : 'fa-times'}`)
                        row.append('td').text(() => v[path.type].out > 0 ? v[path.type].out : '')
                      })
                      const statsSubtree = statsTable.append('tr')
                      statsSubtree.append('td').text('Subtree')
                      
                      const statsSubtreeCount = statsSubtree.append('td')
                      if (v.subPaths.inUnique > 0) statsSubtreeCount.text(v.subPaths.inUnique)
                      else statsSubtreeCount.append('span').append('i').attr('class', 'fas fa-times')
                      statsSubtree.append('td').text(v.subPaths.in)

                      statsSubtree.append('td').text(' / ')

                      const statsSubtreeCountOut = statsSubtree.append('td')
                      if (v.subPaths.outUnique > 0) statsSubtreeCountOut.text(v.subPaths.outUnique)
                      else statsSubtreeCountOut.append('span').append('i').attr('class', 'fas fa-times')
                      statsSubtree.append('td').text(v.subPaths.out)

                    }


                    tippy(this, {
                      content: '',
                      placement: 'right',
                      boundary: 'viewport',
                      arrow: true,
                      interactive: true,
                      multiple: true,
                      flipOnUpdate: true,
                      onShow: (instance) => instance.setContent(container.node()),
                      delay: [500, 200]
                    })
                    /*
                    let contentRight = ""
                    contentRight += "subPaths <small>in: <b>" + v.subPaths.in + "</b> out: <b>" + v.subPaths.out + "</b></small><br>"
                    contentRight += "subPathsUnique <small>in: <b>" + v.subPaths.inUnique + "</b> out: <b>" + v.subPaths.outUnique + "</b></small><br>"

                    that.tooltipRight = tippy(this, {
                      content: contentRight,
                      placement: "right",
                      arrow: true,
                      interactive: true,
                      multiple: true,
                      onHide: () => { that.tooltipRight = undefined}
                    })

                    let contentLeft = ""
                    contentLeft += "<b>" + v.functionId + "</b><br>"
                    contentLeft += "backPath <small>in: <b>" + v.backPath.in + "</b> out: <b>" + v.backPath.out + "</b></small><br>"
                    contentLeft += "backPathUnique <small>in: <b>" + v.backPath.inUnique + "</b> out: <b>" + v.backPath.outUnique + "</b></small><br>"
                    contentLeft += "nodePath <small>in: <b>" + v.nodePath.in + "</b> out: <b>" + v.nodePath.out + "</b></small><br>"
                    contentLeft += "nodePathUnique <small>in: <b>" + v.nodePath.inUnique + "</b> out: <b>" + v.nodePath.outUnique + "</b></small><br>"
                    
                    tippy(this, {
                      content: contentLeft,
                      placement: "left",
                      arrow: true,
                      interactive: true,
                      multiple: true
                    })
                    */
                  }
                }       
              });

            v.svg.g.classed("collapsed", true);
            if(v.type != "block") v.svg.g.classed("no-out", that.getFunctionPathsValue(v).in != that.getFunctionPathsValue(v).out);
            

            v.svg.gCollapsed = v.svg.g.append("g")
              .attr("class", "collapsed-content")
              //.attr("transform", "translate(" + ((-size.collapsedWidth/2)) + " " + ((-size.collapsedHeight/2)) + ")");
              .attr("transform", "translate(" + v.svg.getTransform().collapsed.x + " " + v.svg.getTransform().collapsed.y  + ")");
      
            v.svg.gExpanded = v.svg.g.append("g").attr("class", "expanded-content")
              //.attr("transform", "translate(" + (-size.expandedWidth/2) + " " + (-size.expandedHeight/2) + ")")
              .attr("transform", "translate(" + v.svg.getTransform().expanded.x + " " + v.svg.getTransform().expanded.y  + ")")
              .style("display", "none");
            
            v.svg.createNodeElements();
            
          }

          this.createNodeElements = function() {
            
            if(v.svg.shape.node().nodeName == "rect"){
              v.svg.gCollapsed.append("rect")
                .attr("class", "background")
                .attr("width", v.svg.getInnerSize().collapsed.width)
                .attr("height", v.svg.getInnerSize().collapsed.height)
                .on("mouseover", () => {
                  if(v.type !== "block") return;
                  system.state.highlightNodes(v.obj.nodes, true)
                })
                .on("mouseout", () => {
                  if(v.type !== "block") return;
                  system.state.highlightNodes(null, false)
                })

              v.svg.gExpanded.append("rect")
                .attr("class", "background")
                .attr("width", v.svg.getInnerSize().expanded.width)
                .attr("height", v.svg.getInnerSize().expanded.height);
            }
            if(v.svg.shape.node().nodeName == "circle"){
              v.svg.gCollapsed.append("circle")
                .attr("class", "background")
                .attr("cx", v.svg.getInnerSize().collapsed.width/2)
                .attr("cy", v.svg.getInnerSize().collapsed.height/2)
                .attr("r", v.svg.getInnerSize().collapsed.height/2);
            }
            
            if(v.type == "block"){
              v.svg.g
                .classed("VertexPathsValue", that.getVertexPathsValue(v) > 0)
                .classed("NodePathsValue", that.getVertexNodePathsValue(v) > 0)
            }

            this.createLabel();
            this.createForksBar();
            this.createSymbolsBar();
            this.createIcon();
            this.createCode();
            this.update(false);
          }

          this.createLabel = function() {
            //compressed
            var t = v.svg.gCollapsed.append("text")
              .attr("class", "label")
              .style("visibility", "hidden")
              .text((v.type == "block") ? v.obj.address : "")
              .style("pointer-events", "none")
              .style("font-size", size.label)
        
            var w = size.label * v.obj.address.length * 0.7;
            var h = size.label * 0.1;

            t.attr("x", (size.collapsedWidth  - w) / 2)
              .attr("y", (size.collapsedHeight + h) / 2)
              .attr("width", w)
              .style("visibility", "visible");
        
            v.svg.gExpanded.append("rect")
              .attr("class", "label-background")
              .attr("width", v.svg.getInnerSize().expanded.width)
              .attr("height", v.svg.getInnerSize().collapsed.height)
              .on("mouseover", () => {
                if(v.type !== "block") return;
                system.state.highlightNodes(v.obj.nodes, true)
              })
              .on("mouseout", () => {
                if(v.type !== "block") return;
                system.state.highlightNodes(null, false)
              })
        
            v.svg.gExpanded.append("text")
              .attr("class", "label")
              .style("pointer-events", "none")
              .style("font-size", size.label)
              .text(v.obj.address)
              .attr("x", (size.expandedWidth  - w) / 2)
              .attr("y", (size.collapsedHeight + h) / 2)
          }

          this.createForksBar = function() {
            if(that.currentGraph.nodeId == undefined) return;
            if(that.getVertexForksColor(v) == null || that.getVertexForksBarHeight(v) == null) return;
            
            v.svg.forksBar = v.svg.gCollapsed
              .append("rect")
              .attr("class", "forks-bar")
              .attr("fill", that.getVertexForksColor(v))
              .attr("width", size.forksBar)
              .attr("height", 0)
              .attr("y", v.svg.getInnerSize().collapsed.height)
              .on("click", function(){ d3.event.stopPropagation() })
              
            v.svg.forksBar .transition()
              .attr("height", that.getVertexForksBarHeight(v))
              .attr("y", v.svg.getInnerSize().collapsed.height - that.getVertexForksBarHeight(v))
             .attr("height", v.svg.getInnerSize().collapsed.height)
              .attr("y", 0)

            v.svg.forksBarExpanded = v.svg.gExpanded
              .append("rect")
              .attr("class", "forks-bar")
              .attr("fill", that.getVertexForksColor(v))
              .attr("width", size.forksBar)
              .attr("height", 0)
              .attr("y", v.svg.getInnerSize().collapsed.height)
              .on("click", function(){ d3.event.stopPropagation() })
              
            v.svg.forksBarExpanded .transition()
              .attr("height", that.getVertexForksBarHeight(v))
              .attr("y", v.svg.getInnerSize().collapsed.height - that.getVertexForksBarHeight(v))
              
            

          }

          this.createSymbolsBar = function() {
            if(that.currentGraph.nodeId == undefined) return;
            if(that.getVertexSymbolsColor(v) == null || that.getVertexSymbolsBarHeight(v) == null) return;
            
            v.svg.symbolsBar = v.svg.gCollapsed
              .append("rect")
              .attr("class", "symbols-bar")
              .attr("transform", "translate(" + (v.svg.getInnerSize().collapsed.width - size.symbolsBar) + " 0)")
              .attr("fill", that.getVertexSymbolsColor(v))
              .attr("width", size.symbolsBar)
              .attr("height", 0)
              .attr("y", v.svg.getInnerSize().collapsed.height)
              .on("click", function(){ d3.event.stopPropagation() })
              
            v.svg.symbolsBar.transition()
              .attr("height", that.getVertexSymbolsBarHeight(v))
              .attr("y", v.svg.getInnerSize().collapsed.height - that.getVertexSymbolsBarHeight(v))
              

            v.svg.symbolsBarExpanded = v.svg.gExpanded
              .append("rect")
              .attr("class", "symbols-bar")
              .attr("transform", "translate(" + (v.svg.getInnerSize().expanded.width - size.symbolsBar) + " 0)")
              .attr("fill", that.getVertexSymbolsColor(v))
              .attr("width", size.symbolsBar)
              .attr("height", 0)
              .attr("y", v.svg.getInnerSize().collapsed.height)
              .on("click", function(){ d3.event.stopPropagation() })
              
            v.svg.symbolsBarExpanded.transition()
              .attr("height", that.getVertexSymbolsBarHeight(v))
              .attr("y", v.svg.getInnerSize().collapsed.height - that.getVertexSymbolsBarHeight(v))
              
          }

          this.createCode = function() {
            if(v.type != "block") return;

            var gCode = v.svg.gExpanded.append("g")
              .attr("class", "code")
              .attr("transform", "translate(" + size.padding + " " + (size.collapsedHeight + size.code) +  ")");
        
            var gCallLinks = v.svg.gExpanded.append("g")
            .attr("class", "call-links")
            .attr("transform", "translate(" + (size.expandedWidth - size.code - 2*size.border) + " " + (size.collapsedHeight + size.code) +  ")");
        
            var lines = gCode.selectAll("text")
              .data(v.obj.code)
              .enter()
              .append("text")
              .attr("y", function(d, i){ return i*size.code})
              .text(function(d){ return d})
            
            
            var arrows = gCallLinks.selectAll("text")
              .data(v.obj.functionRefs)
              .enter()
              .append("text")
              .attr("y", function(d){ return d.codeIndex*size.code})
              .text("\uf04e")
              .on("click", function(d){
                d3.event.stopPropagation()
                if(d.type != "INVALID"){
                  system.state.setCurrentFunction(d.function)
                }
              })
              .attr("type", function(d){ return d.type;})
              .on("mouseover", function(d){
                d3.select(lines._groups[0][d.codeIndex]).classed("mouseover", true)
              })
              .on("mouseout", function(d){
                d3.select(lines._groups[0][d.codeIndex]).classed("mouseover", false)
              })
          }

          this.createIcon = function() {
            if(v.type == "block") return;
            var w = size.collapsedHeight * 0.5;

            var t = v.svg.gCollapsed.append("text")
              .attr("class", "icon")
              .attr("x", (size.collapsedHeight - w) / 2  - w*0.2)
              .attr("y", (size.collapsedHeight ) / 2 + w*0.2)
              .style("font-size", w)
              .text(function(){
                if(v.type == "callee") return "\uf2f1"
                if(v.type == "caller") return "\uf2f6"
                if(v.type == "callre") return "\uf2f5"
              })
          }


          this.update = function(transition = true) {
            var duration = 400;
            if(!transition) duration = 0;
            
            if(v.type != undefined && v.type == "callee") this.g.transition().duration(duration).style("opacity", system.state.graphLayers.callees ? 1 : 0)
            if(v.type != undefined && v.type == "caller") this.g.transition().duration(duration).style("opacity", system.state.graphLayers.callers ? 1 : 0)
            if(v.type != undefined && v.type == "callre") this.g.transition().duration(duration).style("opacity", system.state.graphLayers.callers ? 1 : 0)
            

            if(this.forksBar != undefined) this.forksBar.transition().duration(duration)
              .attr("fill", that.getVertexForksColor(v))
              .attr("height", that.getVertexForksBarHeight(v))
              .attr("y", v.svg.getInnerSize().collapsed.height - that.getVertexForksBarHeight(v))


            if(this.symbolsBar != undefined) this.symbolsBar.transition().duration(duration)
              .attr("fill", that.getVertexSymbolsColor(v))
              .attr("height", that.getVertexSymbolsBarHeight(v))
              .attr("y", v.svg.getInnerSize().collapsed.height - that.getVertexSymbolsBarHeight(v))
              

            if(this.forksBarExpanded != undefined) this.forksBarExpanded.transition().duration(duration)
              .attr("fill", that.getVertexForksColor(v))
               .attr("height", that.getVertexForksBarHeight(v))
              .attr("y", v.svg.getInnerSize().collapsed.height - that.getVertexForksBarHeight(v))
              

            if(this.symbolsBarExpanded != undefined) this.symbolsBarExpanded.transition().duration(duration)
              .attr("fill", that.getVertexSymbolsColor(v))
              .attr("height", that.getVertexSymbolsBarHeight(v))
              .attr("y", v.svg.getInnerSize().collapsed.height - that.getVertexSymbolsBarHeight(v))
              

            if(v.type != "block") v.svg.g.classed("no-out", that.getFunctionPathsValue(v).in != that.getFunctionPathsValue(v).out);
          }

      }).apply(v.svg);
      that.dagreGraph.setNode(v.id, v.svg.nodeOptions());
    });

    that.currentGraph.edges.forEach(function (e, i) {
      e.svg = {};
      (function(){
        this.svgElem = undefined;
        this.line = undefined;

        this.edgeOptions = function() {
          return {
            minlen: function() {
              let rank = 4
              const backEdgeId = `${e.targetId}-${e.sourceId}`
              if (that.edgesIndexById[backEdgeId] !== undefined) rank = 3
              return rank
            }(), // 1
            weight: function() {
              let weight = 1
              if (e.sourceId === e.targetId) {
                weight = 1
              } 
              return weight
            }(),
            curve: d3.curveBasis,
            arrowheadClass: "edge-arrow",
          }
        }

        this.init = function(svgElem){
          this.svgElem = svgElem;
          svgElem.attr("source-id", e.sourceId).attr("target-id", e.targetId).attr("type", e.type).style("opacity", 1);
          this.line = svgElem.select("path");
          this.arrow = svgElem.select("marker").remove()

          this.arrow = d3.select(".edgeArrows").append("defs")
            .append('svg:marker')
            .attr('id', function(d){ return 'marker-' + e.id})
            .attr('markerHeight', 10)
            .attr('markerWidth', 10)
            .attr('markerUnits', 'strokeWidth')
            .attr('orient', 'auto')
            .attr('refX', 0)
            .attr('refY', 0)
            .attr('viewBox', '-5 -5 10 10')
            .append('svg:path')
            .attr('d', 'M 0,0 m -5,-5 L 5,0 L -5,5 Z')
            .attr("stroke-width", "0px")
          this.line.attr('marker-end', 'url(#marker-' + e.id  + ')');
          e.svg.svgElem.each(function() {
            if (e.__proto__.constructor.name == 'Edge') {
              if (e.type == 'blockBlock') {
                const containerEl = document.createElement('div')
                const container = d3.select(containerEl)
                  .attrs({
                    class: 'cfgEdgeTipContainer',
                    id: `cfgEdgeTipContainer-${e.id}`
                  })
                const src = system.data.getBlockById(e.sourceId)
                const dst = system.data.getBlockById(e.targetId)
                container.append('div').attr('class', 'cfg-tip-label').text(`${src.address} - ${dst.address}`)
                const singlePaths = [
                  {
                    type: 'backPath',
                    label: 'Path'
                  },
                  {
                    type: 'nodePath',
                    label: 'Node'
                  }
                ]
                const statsTable = container.append('table').attr('class', 'cfg-tip-stats')
                singlePaths.forEach(path => {
                  let row = statsTable.append('tr')
                  row.append('td').text(path.label)
                  row.append('td').append('span').append('i')
                    .attr('class', `fas ${e[`${path.type}Unique`] > 0 ? 'fa-check' : 'fa-times'}`)
                    row.append('td').text(() => e[path.type] > 0 ? e[path.type] : '')
                })
                const statsSubtree = statsTable.append('tr')
                statsSubtree.append('td').text('Subtree')
                const statsSubtreeCount = statsSubtree.append('td')
                if (e.subPathsUnique > 0) statsSubtreeCount.text(e.subPathsUnique)
                else statsSubtreeCount.append('span').append('i').attr('class', 'fas fa-times')
                statsSubtree.append('td').text(e.subPaths)

                const filtersContainer = container.append('div').attr('class', 'cfg-tip-filters-cont')
                filtersContainer.append('div').text('Filters')

                const filters = [
                  {
                    type: 'white',
                    label: 'Include',
                    filter: system.data.getEdgeWhiteFilterByBlocksId(src.id, dst.id),
                    call: () => system.api.filterEdge(src.id, dst.id, 'white')
                  },
                  {
                    type: 'black',
                    label: 'Exclude',
                    filter: system.data.getEdgeBlackFilterByBlocksId(src.id, dst.id),
                    call: () => system.api.filterEdge(src.id, dst.id, 'black')
                  }
                ]
                filters.forEach(f => {
                  let filterContainer = filtersContainer.append('div').attr('class', 'cfg-tip-fil-cont')
                  let filterHead = filterContainer.append('div').attr('class', 'cfg-tip-fil-head')
                  let filterDetails = filterContainer.append('div').style('display', 'none').attr('class', 'cfg-tip-fil-details')
                  filterHead
                    .append('div')
                      .attr('class', 'cfg-tip-fil-trig')
                      .on('click', () => filterDetails.style('display', filterDetails.style('display') === 'none' ? 'block' : 'none'))
                    .append('i')
                      .attr('class', 'fas fa-angle-down')
                  filterHead
                    .append('div').text(f.label)
                      .attr('class', 'cfg-tip-fil-label')
                  if (['white', 'black'].indexOf(f.type) >= 0) {
                    filterHead
                      .append('div')
                        .attr('class', 'cfg-tip-fil-cov')
                        .text(() => f.filter !== undefined ? `${f.filter.coverageLoss} %` : '')
                    filterHead
                      .append('div')
                        .attr('class', 'cfg-tip-fil-red')
                        .text(() => f.filter !== undefined ? `${f.filter.treeReduction} %` : '')
                    filterHead
                      .append('div')
                        .attr('class', 'cfg-tip-fil-apply')
                        .on('click', f.call)
                      .append('i')
                        .attr('class', 'fas fa-filter')
                    filterDetails.append('label').attrs({
                        for: `${e.id}-${f.type}-count`
                      }).text('Count: ')
                    filterDetails.append('input').attrs({
                      type: 'number',
                      min: 0,
                      value: f.type === 'white' ? 1 : 0,
                      id: `${e.id}-${f.type}-count`
                    })
                    .styles({
                      'max-width': '30px',
                      'margin': '0.1rem 0.6rem 0.1rem 0.3rem'
                    })
                  }
                })
                tippy(this, {
                  content: '',
                  placement: 'right',
                  followCursor: true,
                  arrow: true,
                  interactive: true,
                  multiple: true,
                  flipOnUpdate: true,
                  onShow: (instance) => instance.setContent(container.node()),
                  delay: [500, 200]
                })
              }
            }
          })
          this.update();
        }

        this.update = function(){
          if(e.type && e.type == "blockBlock"){
            this.line.transition()
              .style("stroke-width", that.getEdgeTickness(e) + "px")
              .style("stroke", that.getEdgeColor(e));
              
           this.line.attr('marker-end', null);
           
           d3.select(".edgeArrows").select('#marker-' + e.id).remove()
           
           this.arrow = d3.select(".edgeArrows").append("defs")
            .append('svg:marker')
            .attr('id', function(d){ return 'marker-' + e.id})
            .attr('markerHeight', that.getEdgeArrowSize(e))
            .attr('markerWidth', that.getEdgeArrowSize(e))
            .attr('markerUnits', 'strokeWidth')
            .attr('orient', 'auto')
            .attr('refX', 0)
            .attr('refY', 0)
            .attr('viewBox', '-5 -5 10 10')
            .append('svg:path')
            .attr('d', 'M 0,0 m -5,-5 L 5,0 L -5,5 Z')
            .attr("stroke-width", "0px")
            .attr('fill', that.getEdgeColor(e))
          this.line.attr('marker-end', 'url(#marker-' + e.id  + ')');
          }
          
          if(e.type){
            if(e.type == "blockCallFunction") this.svgElem.transition().style("opacity", system.state.graphLayers.callees ? 1 : 0)
            if(e.type == "functionCallBlock") this.svgElem.transition().style("opacity", system.state.graphLayers.callers ? 1 : 0)
            if(e.type == "blockRetFunction") this.svgElem.transition().style("opacity", system.state.graphLayers.callers ? 1 : 0)
          }

        }
      }).apply(e.svg);
      that.dagreGraph.setEdge(e.sourceId, e.targetId, e.svg.edgeOptions());
    })
   
    
    that.dagreRender = new dagreD3.render();
    that.dagreRender(that.container, that.dagreGraph);

    
    that._centerCurrentGraph();

    that.graphCollapsedDimension = {
      width: that.dagreGraph.graph().width,
      height: that.dagreGraph.graph().height
    }

    d3.entries(that.dagreGraph._nodes).forEach(function (d) {
      var v = that.currentGraph.vertices[that.nodesIndexById[d.key]];
      v.svg.init(d.value.elem);
    });

    d3.entries(that.dagreGraph._edgeLabels).forEach(function (d) {
      var svgElem = d3.select(d.value.elem);
      var sourceId = svgElem.data()[0].v;
      var targetId = svgElem.data()[0].w;
      var id = sourceId + "-" + targetId;
      var e = that.currentGraph.edges[that.edgesIndexById[id]];
      e.svg.init(svgElem)
    });


    that.dagreGraph.graph().transition = function (selection) {
      return selection.transition().duration(300)
      .on("start", function(d){
          if(selection.classed("node") && d!= undefined){
            var v = that.currentGraph.vertices[that.nodesIndexById[d]];
            v.svg.beforeTransition();
          } 
        })
      .on("end", function(d){
          if(selection.classed("node") && d!= undefined){
            var v = that.currentGraph.vertices[that.nodesIndexById[d]];
            v.svg.afterTransition();
          } 
      });
    };

  }

  _centerCurrentGraph(){
    var that = this;
    var viewport = that.svg.select(function(){ return this.parentNode}).node().getBoundingClientRect();

    var initialScale = Math.min(
      viewport.width*0.95 / that.dagreGraph.graph().width,
      viewport.height*0.95 / that.dagreGraph.graph().height,
    );
    
    that.svg.call(that.zoom.transform, 
      d3.zoomIdentity.translate(
        (that.width - that.dagreGraph.graph().width * initialScale) / 2, 
        (that.height - that.dagreGraph.graph().height * initialScale) / 2)
        .scale(initialScale));
  }

  _drawHistoryGraphs(){
    var that = this;

    that.historyDiv.selectAll("*").remove()

    that.historyDiv.selectAll("svg")
      .data(that.historyGraphs)
      .enter()
      .append("svg")
      .classed("current", function(d, i){ return i == that.currentGraphIndex})
      .attr("preserveAspectratio", "XMidYMid")
      .on("click", function(d){
        if(d.blockId == undefined) system.state.setCurrentFunction(d.functionId);
        else system.state.setCurrentBlock(d.blockId);
        
      })
      .each(function(graph){
        var container = d3.select(this);
        
        var dagreGraph = new dagreD3.graphlib.Graph()
          .setGraph(that.graphOptions())
          .setDefaultEdgeLabel(function () { return {}; });

        graph.vertices.forEach(function (v, i) {
          that.nodesIndexById[v.id] = i;
          v.svg = {};
          v.obj = (v.type !== "block") ? system.data.getFunctionById(v.functionId) : system.data.getBlockById(v.id);
          (function(){

            var size = that.nodeSizes(v);

            this.getSize = function(){
              return {
                width: size.collapsedWidth - 2*size.padding,
                height: size.collapsedHeight  - 2*size.padding
              }
            }

            this.nodeOptions = function(){
              return {
                label: v.obj.address, 
                class: v.type, 
                width: v.svg.getSize().width, 
                height: v.svg.getSize().height,
                shape: (v.type == "block") ? "rect" : "circle",
              }
            }

            this.init = function(element){
              v.svg.g = d3.select(element);
              v.svg.shape = v.svg.g.select(".shape");
              v.svg.g.classed("collapsed", true);
            }

          }).call(v.svg);
          dagreGraph.setNode(v.id, v.svg.nodeOptions());
        });

        graph.edges.forEach(function (e) {
          dagreGraph.setEdge(e.sourceId, e.targetId, () => {
            const opts = e.svg.edgeOptions()
            delete opts.arrowheadClass
            return opts
          });
        });

        var dagreRender = new dagreD3.render();
        dagreRender(container, dagreGraph);
        container.attr("viewBox", "0 0 " + dagreGraph.graph().width + " " + dagreGraph.graph().height);
        //tooltip
        tippy(container.node(), {
          content: system.data.getFunctionById(graph.functionId).name,
          placement: "top",
          arrow: true
        });
      })
  }

  updateGraph(){
    this.setScales();
    this.currentGraph.edges.forEach(function(e){
      e.svg.update()
    });
    this.currentGraph.vertices.forEach(function(v){
      v.svg.update()
    });
    this.drawLegend();
  }

  drawLegend(){
    var that = this;
    var width = 200;
    var height = 22;
    var margin = 5;
    
   //paths
   var paths = {
      ticks: d3.range(
        that.edgeScales.tickness.domain()[0], 
        that.edgeScales.tickness.domain()[1], 
        (that.edgeScales.tickness.domain()[1] - that.edgeScales.tickness.domain()[0])/ (Math.min(10, that.edgeScales.tickness.domain()[1] - that.edgeScales.tickness.domain()[0] - 1))),
      svg: undefined
    };
    paths.scaleX = d3.scaleBand().domain(paths.ticks).rangeRound([0, width]).paddingInner(0.2);
    paths.axis = d3.axisBottom(d3.scaleLinear().domain(d3.extent(paths.ticks)).range([0, width]).nice()).tickFormat(d3.format("d"))
    //d3.axisBottom(paths.scaleX).tickFormat(d3.format("d"))
    paths.scaleY = d3.scaleLinear().domain(d3.extent(paths.ticks)).range([0, height/2])
    

    d3.select("#paths-legend").select(".content").selectAll("*").remove();
    paths.svg = d3.select("#paths-legend")
      .select(".content")
      .attr("viewBox", "0 0 " + (width + 2*margin) + " " + (height + 2*margin))
      .append("g")
      .attr("transform", "translate(" + margin + " " + margin + ")")
    
    paths.svg.append("g")
      .attr("class", "axis")
      .attr("transform", "translate( 0 "  + (height/2) + ")")
      .style("font-size", "7")
      .call(paths.axis);
    
    paths.svg.append("g")
      .selectAll("rect")
      .data(paths.ticks)
      .enter()
      .append("rect")
      .attr('width', paths.scaleX.bandwidth())
      .attr('height', d => { return paths.scaleY(d)})
      .attr('y', d => { return (height/2) - paths.scaleY(d) })
      .attr('x', (d) => {return paths.scaleX(d); })
      .attr("fill", (d) => { return this.edgeScales.color(1)})
  

    //loops
    var loops = {
      ticks: d3.range(
        that.edgeScales.color.domain()[0], 
        that.edgeScales.color.domain()[1], 
        (that.edgeScales.color.domain()[1] - that.edgeScales.color.domain()[0])/10),
        //ticks: [0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1],
      svg: undefined
    };
    loops.scaleX = d3.scaleBand().domain(loops.ticks).rangeRound([0, width]).paddingInner(0.2);
    loops.axis = //d3.axisBottom(d3.scaleLinear().domain(d3.extent(loops.ticks)).range([0, width]).nice()).tickFormat(d3.format(".0%"))
    d3.axisBottom(loops.scaleX).tickFormat(d3.format(".0%")).tickSizeOuter(0)

    d3.select("#loops-legend").select(".content").selectAll("*").remove();
    loops.svg = d3.select("#loops-legend")
      .select(".content")
      .attr("viewBox", "0 0 " + (width + 2*margin) + " " + (height + 2*margin))
      .append("g")
      .attr("transform", "translate(" + margin + " " + margin + ")")
    
    loops.svg.append("g")
      .attr("class", "axis")
      //.attr("transform", "translate(" + (-loops.scaleX.bandwidth()/2) + " "  + (height/2) + ")")
      .attr("transform", "translate( 0 "  + (height/2) + ")")
      .style("font-size", "7")
      .call(loops.axis);
    
   loops.svg.append("g")
      .selectAll("rect")
      .data(loops.ticks)
      .enter()
      .append("rect")
      .attr('width', loops.scaleX.bandwidth())
      .attr('height', height/2)
      .attr('y', 0)
      .attr('x', (d) => {return loops.scaleX(d); })
      .attr("fill", (d) => { return this.edgeScales.color( 1 - d)});

    //forks
    var forks = {
      ticks: d3.range(
        that.verticesScales.forksColor.domain()[0], 
        that.verticesScales.forksColor.domain()[1], 
        (that.verticesScales.forksColor.domain()[1] - that.verticesScales.forksColor.domain()[0])/ (Math.min(10, that.verticesScales.forksColor.domain()[1] - that.verticesScales.forksColor.domain()[0] - 1))),
      svg: undefined
    };
    forks.scaleX = d3.scaleBand().domain(forks.ticks).rangeRound([0, width]).paddingInner(0.2);
    forks.axis = d3.axisBottom(d3.scaleLinear().domain(d3.extent(forks.ticks)).range([0, width]).nice()).tickFormat(d3.format("d"))

    d3.select("#forks-legend").select(".content").selectAll("*").remove();
    forks.svg = d3.select("#forks-legend")
      .select(".content")
      .attr("viewBox", "0 0 " + (width + 2*margin) + " " + (height + 2*margin))
      .append("g")
      .attr("transform", "translate(" + margin + " " + margin + ")")
    
      forks.svg.append("g")
      .attr("class", "axis")
      .attr("transform", "translate( 0 "  + (height/2) + ")")
      .style("font-size", "7")
      .call(forks.axis);
    
      forks.svg.append("g")
      .selectAll("rect")
      .data(forks.ticks)
      .enter()
      .append("rect")
      .attr('width', forks.scaleX.bandwidth())
      .attr('height', height/2)
      .attr('y', 0)
      .attr('x', (d) => {return forks.scaleX(d); })
      .attr("fill", (d) => { return that.verticesScales.forksColor(d)});

      
    //symbols
    var symbols = {
      ticks: d3.range(
        that.verticesScales.symbolsColor.domain()[0], 
        that.verticesScales.symbolsColor.domain()[1], 
        (that.verticesScales.symbolsColor.domain()[1] - that.verticesScales.symbolsColor.domain()[0])/10),
      svg: undefined
    };
    symbols.scaleX = d3.scaleBand().domain(symbols.ticks).rangeRound([0, width]).paddingInner(0.2);
    symbols.axis = d3.axisBottom(d3.scaleLinear().domain(d3.extent(symbols.ticks)).range([0, width]).nice()).tickFormat(d3.format("d"))

    d3.select("#symbols-legend").select(".content").selectAll("*").remove();
    symbols.svg = d3.select("#symbols-legend")
      .select(".content")
      .attr("viewBox", "0 0 " + (width + 2*margin) + " " + (height + 2*margin))
      .append("g")
      .attr("transform", "translate(" + margin + " " + margin + ")")
    
    symbols.svg.append("g")
      .attr("class", "axis")
      .attr("transform", "translate( 0 "  + (height/2) + ")")
      .style("font-size", "7")
      .call(symbols.axis);
    
    symbols.svg.append("g")
      .selectAll("rect")
      .data(symbols.ticks)
      .enter()
      .append("rect")
      .attr('width', symbols.scaleX.bandwidth())
      .attr('height', height/2)
      .attr('y', 0)
      .attr('x', (d) => {return symbols.scaleX(d); })
      .attr("fill", (d) => { return that.verticesScales.symbolsColor(d)});
      

  }
}());